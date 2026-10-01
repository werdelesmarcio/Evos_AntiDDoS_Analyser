#include "evos/pcap_reader.hpp"

#include <array>
#include <stdexcept>

namespace evos {
namespace {

constexpr std::uint32_t maximum_snapshot_length = 16 * 1024 * 1024;

std::uint16_t read_u16(const std::uint8_t* bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<std::uint16_t>(bytes[0]) |
            static_cast<std::uint16_t>(bytes[1] << 8);
    }
    return static_cast<std::uint16_t>(bytes[0] << 8) |
        static_cast<std::uint16_t>(bytes[1]);
}

std::uint32_t read_u32(const std::uint8_t* bytes, bool little_endian) {
    if (little_endian) {
        return static_cast<std::uint32_t>(bytes[0]) |
            (static_cast<std::uint32_t>(bytes[1]) << 8) |
            (static_cast<std::uint32_t>(bytes[2]) << 16) |
            (static_cast<std::uint32_t>(bytes[3]) << 24);
    }
    return (static_cast<std::uint32_t>(bytes[0]) << 24) |
        (static_cast<std::uint32_t>(bytes[1]) << 16) |
        (static_cast<std::uint32_t>(bytes[2]) << 8) |
        static_cast<std::uint32_t>(bytes[3]);
}

}  // namespace

PcapReader::PcapReader(std::istream& input) : input_(input) {
    std::array<std::uint8_t, 24> header{};
    input_.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (input_.gcount() != static_cast<std::streamsize>(header.size())) {
        throw std::runtime_error("truncated PCAP global header");
    }

    // The magic number defines both byte order and timestamp precision.
    if (header[0] == 0xd4 && header[1] == 0xc3 && header[2] == 0xb2 && header[3] == 0xa1) {
        little_endian_ = true;
    } else if (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0xc3 && header[3] == 0xd4) {
        little_endian_ = false;
    } else if (header[0] == 0x4d && header[1] == 0x3c && header[2] == 0xb2 && header[3] == 0xa1) {
        little_endian_ = true;
        nanosecond_timestamps_ = true;
    } else if (header[0] == 0xa1 && header[1] == 0xb2 && header[2] == 0x3c && header[3] == 0x4d) {
        little_endian_ = false;
        nanosecond_timestamps_ = true;
    } else {
        throw std::runtime_error("unsupported PCAP format or byte order");
    }

    if (read_u16(header.data() + 4, little_endian_) != 2 ||
        read_u16(header.data() + 6, little_endian_) != 4) {
        throw std::runtime_error("unsupported PCAP version; expected 2.4");
    }
    snapshot_length_ = read_u32(header.data() + 16, little_endian_);
    if (snapshot_length_ == 0 || snapshot_length_ > maximum_snapshot_length) {
        throw std::runtime_error("invalid PCAP snapshot length");
    }
    if (read_u32(header.data() + 20, little_endian_) != 1) {
        throw std::runtime_error("unsupported PCAP link type; expected Ethernet");
    }
}

bool PcapReader::next(CapturedPacket& packet) {
    std::array<std::uint8_t, 16> record_header{};
    input_.read(reinterpret_cast<char*>(record_header.data()), static_cast<std::streamsize>(record_header.size()));
    const auto header_bytes = input_.gcount();
    if (header_bytes == 0 && input_.eof()) {
        return false;
    }
    if (header_bytes != static_cast<std::streamsize>(record_header.size())) {
        throw std::runtime_error("truncated PCAP packet header");
    }

    const auto timestamp_seconds = read_u32(record_header.data(), little_endian_);
    const auto timestamp_fraction = read_u32(record_header.data() + 4, little_endian_);
    const auto captured_length = read_u32(record_header.data() + 8, little_endian_);
    const auto wire_length = read_u32(record_header.data() + 12, little_endian_);
    const auto fraction_limit = nanosecond_timestamps_ ? 1000000000U : 1000000U;
    if (timestamp_fraction >= fraction_limit || captured_length > snapshot_length_ ||
        captured_length > wire_length || captured_length > maximum_snapshot_length) {
        throw std::runtime_error("invalid PCAP packet record");
    }

    packet.bytes.resize(captured_length);
    input_.read(reinterpret_cast<char*>(packet.bytes.data()), static_cast<std::streamsize>(packet.bytes.size()));
    if (input_.gcount() != static_cast<std::streamsize>(packet.bytes.size())) {
        throw std::runtime_error("truncated PCAP packet data");
    }
    packet.timestamp_unix_seconds = timestamp_seconds;
    packet.wire_length = wire_length;
    return true;
}

}  // namespace evos