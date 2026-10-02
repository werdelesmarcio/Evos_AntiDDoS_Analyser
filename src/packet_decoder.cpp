#include "evos/packet_decoder.hpp"

#include <arpa/inet.h>

#include <array>
#include <string>

namespace evos {
namespace {

// Le um campo Ethernet de 16 bits em ordem de rede.
std::uint16_t read_u16(const std::uint8_t* bytes) {
    return static_cast<std::uint16_t>(bytes[0] << 8) |
        static_cast<std::uint16_t>(bytes[1]);
}

// Converte o numero de protocolo IP para um nome curto.
std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 58: return "ICMPv6";
    default: return "IP-" + std::to_string(protocol);
    }
}

// Formata enderecos e cria um evento para o pacote IP validado.
std::optional<TrafficEvent> make_event(
    std::span<const std::uint8_t> frame,
    std::size_t address_offset,
    int address_family,
    std::uint8_t protocol,
    std::uint64_t timestamp,
    std::uint32_t wire_length) {
    const std::size_t address_length = address_family == AF_INET ? 4 : 16;
    std::array<char, INET6_ADDRSTRLEN> source{};
    std::array<char, INET6_ADDRSTRLEN> destination{};
    if (inet_ntop(address_family, frame.data() + address_offset, source.data(), source.size()) == nullptr ||
        inet_ntop(address_family, frame.data() + address_offset + address_length,
            destination.data(), destination.size()) == nullptr) {
        return std::nullopt;
    }
    return TrafficEvent{
        .timestamp_unix_seconds = timestamp,
        .source_ip = source.data(),
        .destination_ip = destination.data(),
        .protocol = protocol_name(protocol),
        .packets = 1,
        .bytes = wire_length,
    };
}

}  // namespace

// Decodifica cabecalhos Ethernet e IP; quadros truncados ou nao suportados sao ignorados.
std::optional<TrafficEvent> decode_ethernet_packet(
    std::span<const std::uint8_t> frame,
    std::uint64_t timestamp_unix_seconds,
    std::uint32_t wire_length) {
    constexpr std::size_t ethernet_header_length = 14;
    if (frame.size() < ethernet_header_length) {
        return std::nullopt;
    }

    auto ether_type = read_u16(frame.data() + 12);
    std::size_t network_offset = ethernet_header_length;
    // Skip common VLAN tags while checking each tag is fully captured.
    for (unsigned int tag_count = 0; tag_count < 2 && (ether_type == 0x8100 || ether_type == 0x88a8); ++tag_count) {
        if (frame.size() < network_offset + 4) {
            return std::nullopt;
        }
        ether_type = read_u16(frame.data() + network_offset + 2);
        network_offset += 4;
    }

    if (ether_type == 0x0800) {
        if (frame.size() < network_offset + 20 || (frame[network_offset] >> 4) != 4) {
            return std::nullopt;
        }
        const auto header_length = static_cast<std::size_t>(frame[network_offset] & 0x0f) * 4;
        const auto total_length = read_u16(frame.data() + network_offset + 2);
        if (header_length < 20 || frame.size() < network_offset + header_length || total_length < header_length) {
            return std::nullopt;
        }
        return make_event(frame, network_offset + 12, AF_INET, frame[network_offset + 9],
            timestamp_unix_seconds, wire_length);
    }

    if (ether_type == 0x86dd) {
        if (frame.size() < network_offset + 40 || (frame[network_offset] >> 4) != 6) {
            return std::nullopt;
        }
        return make_event(frame, network_offset + 8, AF_INET6, frame[network_offset + 6],
            timestamp_unix_seconds, wire_length);
    }
    return std::nullopt;
}

}  // namespace evos