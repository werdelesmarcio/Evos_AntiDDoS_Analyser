#include "evos/packet_decoder.hpp"
#include "evos/pcap_reader.hpp"

#include <cassert>
#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void append_u16(std::string& output, std::uint16_t value, bool little_endian) {
    const auto first = static_cast<char>(little_endian ? value & 0xff : value >> 8);
    const auto second = static_cast<char>(little_endian ? value >> 8 : value & 0xff);
    output += first;
    output += second;
}

void append_u32(std::string& output, std::uint32_t value, bool little_endian) {
    for (int index = 0; index < 4; ++index) {
        const auto shift = static_cast<unsigned int>(little_endian ? index * 8 : (3 - index) * 8);
        output += static_cast<char>((value >> shift) & 0xff);
    }
}

std::string make_pcap(
    const std::vector<std::uint8_t>& frame,
    bool little_endian,
    bool nanosecond_timestamps,
    std::uint32_t link_type = 1) {
    std::string output;
    if (little_endian && nanosecond_timestamps) {
        output.append("\x4d\x3c\xb2\xa1", 4);
    } else if (little_endian) {
        output.append("\xd4\xc3\xb2\xa1", 4);
    } else if (nanosecond_timestamps) {
        output.append("\xa1\xb2\x3c\x4d", 4);
    } else {
        output.append("\xa1\xb2\xc3\xd4", 4);
    }
    append_u16(output, 2, little_endian);
    append_u16(output, 4, little_endian);
    append_u32(output, 0, little_endian);
    append_u32(output, 0, little_endian);
    append_u32(output, 65535, little_endian);
    append_u32(output, link_type, little_endian);
    append_u32(output, 1200, little_endian);
    append_u32(output, 42, little_endian);
    append_u32(output, static_cast<std::uint32_t>(frame.size()), little_endian);
    append_u32(output, static_cast<std::uint32_t>(frame.size() + 4), little_endian);
    output.append(reinterpret_cast<const char*>(frame.data()), frame.size());
    return output;
}

std::vector<std::uint8_t> ipv4_frame() {
    std::vector<std::uint8_t> frame(14 + 20, 0);
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[16] = 0x00;
    frame[17] = 0x14;
    frame[23] = 17;
    frame[26] = 192;
    frame[27] = 0;
    frame[28] = 2;
    frame[29] = 1;
    frame[30] = 198;
    frame[31] = 51;
    frame[32] = 100;
    frame[33] = 20;
    return frame;
}

std::vector<std::uint8_t> vlan_ipv6_frame() {
    std::vector<std::uint8_t> frame(12, 0);
    frame.insert(frame.end(), {0x88, 0xa8, 0x00, 0x01, 0x81, 0x00, 0x00, 0x02, 0x86, 0xdd});
    frame.resize(frame.size() + 40, 0);
    const std::size_t ipv6 = 22;
    frame[ipv6] = 0x60;
    frame[ipv6 + 6] = 6;
    frame[ipv6 + 8] = 0x20;
    frame[ipv6 + 9] = 0x01;
    frame[ipv6 + 10] = 0x0d;
    frame[ipv6 + 11] = 0xb8;
    frame[ipv6 + 23] = 1;
    frame[ipv6 + 24] = 0x20;
    frame[ipv6 + 25] = 0x01;
    frame[ipv6 + 26] = 0x0d;
    frame[ipv6 + 27] = 0xb8;
    frame[ipv6 + 39] = 2;
    return frame;
}

void test_reads_little_endian_pcap_and_decodes_ipv4() {
    std::stringstream input(make_pcap(ipv4_frame(), true, false), std::ios::in | std::ios::binary);
    evos::PcapReader reader(input);
    evos::CapturedPacket packet{};
    assert(reader.next(packet));
    assert(packet.timestamp_unix_seconds == 1200);
    assert(packet.wire_length == 38);

    const auto event = evos::decode_ethernet_packet(packet.bytes, packet.timestamp_unix_seconds, packet.wire_length);
    assert(event.has_value());
    assert(event->source_ip == "192.0.2.1");
    assert(event->destination_ip == "198.51.100.20");
    assert(event->protocol == "UDP");
    assert(event->packets == 1);
    assert(event->bytes == 38);
    assert(!reader.next(packet));
}

void test_reads_big_endian_nanosecond_pcap_and_vlan_ipv6() {
    std::stringstream input(make_pcap(vlan_ipv6_frame(), false, true), std::ios::in | std::ios::binary);
    evos::PcapReader reader(input);
    evos::CapturedPacket packet{};
    assert(reader.next(packet));

    const auto event = evos::decode_ethernet_packet(packet.bytes, packet.timestamp_unix_seconds, packet.wire_length);
    assert(event.has_value());
    assert(event->source_ip == "2001:db8::1");
    assert(event->destination_ip == "2001:db8::2");
    assert(event->protocol == "TCP");
}

void test_skips_non_ip_frames() {
    auto frame = ipv4_frame();
    frame[12] = 0x08;
    frame[13] = 0x06;
    assert(!evos::decode_ethernet_packet(frame, 1200, static_cast<std::uint32_t>(frame.size())).has_value());
}

void test_rejects_unsupported_link_type() {
    std::stringstream input(make_pcap(ipv4_frame(), true, false, 101), std::ios::in | std::ios::binary);
    bool rejected = false;
    try {
        evos::PcapReader reader(input);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

}  // namespace

int main() {
    test_reads_little_endian_pcap_and_decodes_ipv4();
    test_reads_big_endian_nanosecond_pcap_and_vlan_ipv6();
    test_skips_non_ip_frames();
    test_rejects_unsupported_link_type();
}