#include "evos/ipfix_receiver.hpp"

#include "evos/ipfix.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <system_error>

namespace evos {
namespace {

class UdpListener {
public:
    explicit UdpListener(std::uint16_t port) {
        socket_fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (socket_fd_ < 0) {
            throw std::system_error(errno, std::generic_category(), "cannot create IPFIX UDP socket");
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        address.sin_port = htons(port);
        if (bind(socket_fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) < 0) {
            const auto error = errno;
            close(socket_fd_);
            socket_fd_ = -1;
            throw std::system_error(error, std::generic_category(), "cannot bind IPFIX UDP port");
        }
    }

    UdpListener(const UdpListener&) = delete;
    UdpListener& operator=(const UdpListener&) = delete;

    ~UdpListener() {
        if (socket_fd_ >= 0) {
            close(socket_fd_);
        }
    }

    int descriptor() const noexcept { return socket_fd_; }

private:
    int socket_fd_ = -1;
};

std::string exporter_name(const sockaddr_in& address) {
    std::array<char, INET_ADDRSTRLEN> ip{};
    if (inet_ntop(AF_INET, &address.sin_addr, ip.data(), ip.size()) == nullptr) {
        throw std::runtime_error("cannot format IPFIX exporter address");
    }
    return std::string(ip.data()) + ":" + std::to_string(ntohs(address.sin_port));
}

}  // namespace

void receive_ipfix(
    std::uint16_t port,
    Analyzer& analyzer,
    const volatile std::sig_atomic_t& stop_requested,
    const EventHandler& on_event,
    const AlertHandler& on_alert) {
    UdpListener listener(port);
    IpfixDecoder decoder;
    std::array<std::uint8_t, 65535> buffer{};
    std::cerr << "Listening for IPFIX UDP on 0.0.0.0:" << port << '\n';

    while (!stop_requested) {
        pollfd descriptor{.fd = listener.descriptor(), .events = POLLIN, .revents = 0};
        const auto ready = poll(&descriptor, 1, 500);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "error waiting for IPFIX datagram");
        }
        if (ready == 0 || (descriptor.revents & POLLIN) == 0) {
            continue;
        }

        sockaddr_in exporter{};
        socklen_t exporter_length = sizeof(exporter);
        const auto received = recvfrom(
            listener.descriptor(), buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&exporter), &exporter_length);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::generic_category(), "error receiving IPFIX datagram");
        }
        try {
            // Exporter receive time keeps analyzer windows ordered despite flow timestamps.
            const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            const auto events = decoder.decode(
                std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(received)),
                exporter_name(exporter), static_cast<std::uint64_t>(now));
            for (const auto& event : events) {
                on_event(event);
                for (const auto& alert : analyzer.consume(event)) {
                    on_alert(alert);
                }
            }
        } catch (const std::exception& error) {
            std::cerr << "Discarding invalid IPFIX datagram: " << error.what() << '\n';
        }
    }
}

}  // namespace evos