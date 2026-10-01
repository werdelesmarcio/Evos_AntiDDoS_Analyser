#include "evos/live_capture.hpp"

#include "evos/packet_decoder.hpp"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace evos {
namespace {

class PacketRing {
public:
    explicit PacketRing(const std::string& interface_name) {
        const auto interface_index = if_nametoindex(interface_name.c_str());
        if (interface_index == 0) {
            throw std::system_error(errno, std::generic_category(), "unknown interface: " + interface_name);
        }

        socket_fd_ = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
        if (socket_fd_ < 0) {
            const auto error_code = errno;
            const auto message = error_code == EPERM || error_code == EACCES
                ? "cannot open packet socket; CAP_NET_RAW is required"
                : "cannot open AF_PACKET socket in this environment";
            throw std::system_error(error_code, std::generic_category(), message);
        }

        try {
            configure_ring();
            bind_interface(interface_index);
        } catch (...) {
            release();
            throw;
        }
    }

    PacketRing(const PacketRing&) = delete;
    PacketRing& operator=(const PacketRing&) = delete;

    ~PacketRing() {
        release();
    }

    int socket_fd() const noexcept {
        return socket_fd_;
    }

    std::size_t block_size() const noexcept {
        return request_.tp_block_size;
    }

    std::uint32_t block_count() const noexcept {
        return request_.tp_block_nr;
    }

    tpacket_block_desc* block(std::uint32_t index) const noexcept {
        auto* bytes = static_cast<std::uint8_t*>(ring_memory_);
        return reinterpret_cast<tpacket_block_desc*>(bytes + index * request_.tp_block_size);
    }

private:
    void configure_ring() {
        int version = TPACKET_V3;
        if (setsockopt(socket_fd_, SOL_PACKET, PACKET_VERSION, &version, sizeof(version)) < 0) {
            throw std::system_error(errno, std::generic_category(), "cannot select TPACKET_V3");
        }

        request_.tp_block_size = 1U << 20;
        request_.tp_block_nr = 4;
        request_.tp_frame_size = 2048;
        request_.tp_frame_nr = (request_.tp_block_size / request_.tp_frame_size) * request_.tp_block_nr;
        request_.tp_retire_blk_tov = 64;
        if (setsockopt(socket_fd_, SOL_PACKET, PACKET_RX_RING, &request_, sizeof(request_)) < 0) {
            throw std::system_error(errno, std::generic_category(), "cannot configure packet ring");
        }

        ring_length_ = static_cast<std::size_t>(request_.tp_block_size) * request_.tp_block_nr;
        ring_memory_ = mmap(nullptr, ring_length_, PROT_READ | PROT_WRITE, MAP_SHARED, socket_fd_, 0);
        if (ring_memory_ == MAP_FAILED) {
            ring_memory_ = nullptr;
            throw std::system_error(errno, std::generic_category(), "cannot map packet ring");
        }
    }

    void bind_interface(unsigned int interface_index) {
        sockaddr_ll address{};
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(ETH_P_ALL);
        address.sll_ifindex = static_cast<int>(interface_index);
        if (bind(socket_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
            throw std::system_error(errno, std::generic_category(), "cannot bind packet socket to interface");
        }
    }

    void release() noexcept {
        if (ring_memory_ != nullptr) {
            munmap(ring_memory_, ring_length_);
            ring_memory_ = nullptr;
        }
        if (socket_fd_ >= 0) {
            tpacket_req3 disabled{};
            setsockopt(socket_fd_, SOL_PACKET, PACKET_RX_RING, &disabled, sizeof(disabled));
            close(socket_fd_);
            socket_fd_ = -1;
        }
    }

    int socket_fd_ = -1;
    void* ring_memory_ = nullptr;
    std::size_t ring_length_ = 0;
    tpacket_req3 request_{};
};

void process_block(
    PacketRing& ring,
    tpacket_block_desc& block,
    Analyzer& analyzer,
    std::uint64_t& last_timestamp,
    bool& has_last_timestamp,
    const EventHandler& on_event,
    const AlertHandler& on_alert) {
    const auto block_size = ring.block_size();
    const auto packet_count = block.hdr.bh1.num_pkts;
    std::size_t packet_offset = block.hdr.bh1.offset_to_first_pkt;
    if (packet_offset > block_size) {
        throw std::runtime_error("invalid packet offset in TPACKET block");
    }

    for (std::uint32_t packet_index = 0; packet_index < packet_count; ++packet_index) {
        if (packet_offset > block_size - sizeof(tpacket3_hdr)) {
            throw std::runtime_error("truncated packet header in TPACKET block");
        }
        auto* header = reinterpret_cast<tpacket3_hdr*>(reinterpret_cast<std::uint8_t*>(&block) + packet_offset);
        const auto available = block_size - packet_offset;
        if (header->tp_mac > available || header->tp_snaplen > available - header->tp_mac) {
            throw std::runtime_error("invalid packet bounds in TPACKET block");
        }

        auto timestamp = static_cast<std::uint64_t>(header->tp_sec);
        // Multi-queue receive can reorder timestamps; keep event windows monotonic.
        if (has_last_timestamp && timestamp < last_timestamp) {
            timestamp = last_timestamp;
        } else {
            last_timestamp = timestamp;
            has_last_timestamp = true;
        }

        const auto* frame = reinterpret_cast<const std::uint8_t*>(header) + header->tp_mac;
        const auto event = decode_ethernet_packet(
            std::span<const std::uint8_t>(frame, header->tp_snaplen), timestamp, header->tp_len);
        if (event.has_value()) {
            on_event(*event);
            for (const auto& alert : analyzer.consume(*event)) {
                on_alert(alert);
            }
        }

        if (packet_index + 1 < packet_count) {
            if (header->tp_next_offset == 0 || header->tp_next_offset > block_size - packet_offset) {
                throw std::runtime_error("invalid next packet offset in TPACKET block");
            }
            packet_offset += header->tp_next_offset;
        }
    }
}

}  // namespace

void capture_live_packets(
    const std::string& interface_name,
    Analyzer& analyzer,
    const volatile std::sig_atomic_t& stop_requested,
    const EventHandler& on_event,
    const AlertHandler& on_alert) {
    PacketRing ring(interface_name);
    std::uint32_t block_index = 0;
    std::uint64_t last_timestamp = 0;
    bool has_last_timestamp = false;

    while (!stop_requested) {
        auto* block = ring.block(block_index);
        if ((block->hdr.bh1.block_status & TP_STATUS_USER) == 0) {
            pollfd descriptor{ring.socket_fd(), POLLIN, 0};
            const auto ready = poll(&descriptor, 1, 100);
            if (ready < 0 && errno != EINTR) {
                throw std::system_error(errno, std::generic_category(), "packet socket poll failed");
            }
            continue;
        }

        std::atomic_thread_fence(std::memory_order_acquire);
        process_block(ring, *block, analyzer, last_timestamp, has_last_timestamp, on_event, on_alert);
        std::atomic_thread_fence(std::memory_order_release);
        block->hdr.bh1.block_status = TP_STATUS_KERNEL;
        block_index = (block_index + 1) % ring.block_count();
    }
}

}  // namespace evos