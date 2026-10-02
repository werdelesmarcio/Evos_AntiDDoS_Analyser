#include "evos/ipfix.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>

namespace evos {
namespace {

constexpr std::uint16_t variable_length = 65535;
constexpr std::uint16_t minimum_template_id = 256;

// Le um inteiro de 16 bits em ordem de rede com verificacao de limites.
std::uint16_t read_u16(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 2) {
        throw std::invalid_argument("truncated IPFIX 16-bit value");
    }
    return static_cast<std::uint16_t>((bytes[offset] << 8) | bytes[offset + 1]);
}

// Le um inteiro de 32 bits em ordem de rede com verificacao de limites.
std::uint32_t read_u32(std::span<const std::uint8_t> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < 4) {
        throw std::invalid_argument("truncated IPFIX 32-bit value");
    }
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
        (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
        (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
        static_cast<std::uint32_t>(bytes[offset + 3]);
}

// Converte contadores IPFIX de largura variavel para uint64.
std::uint64_t read_unsigned(std::span<const std::uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > sizeof(std::uint64_t)) {
        throw std::invalid_argument("unsupported IPFIX counter width");
    }
    std::uint64_t value = 0;
    for (const auto byte : bytes) {
        value = (value << 8) | byte;
    }
    return value;
}

// Detecta bytes zero usados como preenchimento no final de um Set.
bool all_zero(std::span<const std::uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](std::uint8_t byte) { return byte == 0; });
}

// Formata um endereco binario IPv4 ou IPv6 em texto.
std::string format_address(std::span<const std::uint8_t> bytes, int family) {
    const auto expected_size = family == AF_INET ? 4U : 16U;
    if (bytes.size() != expected_size) {
        return {};
    }
    std::array<char, INET6_ADDRSTRLEN> output{};
    if (inet_ntop(family, bytes.data(), output.data(), output.size()) == nullptr) {
        throw std::runtime_error("could not format IPFIX address");
    }
    return output.data();
}

// Traduz protocolos comuns e preserva o numero para os demais.
std::string protocol_name(std::span<const std::uint8_t> bytes) {
    const auto number = read_unsigned(bytes);
    switch (number) {
    case 1: return "ICMP";
    case 6: return "TCP";
    case 17: return "UDP";
    case 58: return "ICMPv6";
    default: return "IPPROTO_" + std::to_string(number);
    }
}

struct RecordField {
    std::uint16_t id;
    std::span<const std::uint8_t> value;
    bool enterprise;
};

// Extrai um campo fixo ou prefixado por comprimento variavel do registro.
bool next_field_value(
    std::span<const std::uint8_t> data,
    std::size_t& offset,
    std::uint16_t template_length,
    std::span<const std::uint8_t>& value) {
    std::size_t length = template_length;
    if (template_length == variable_length) {
        if (offset >= data.size()) {
            return false;
        }
        length = data[offset++];
        if (length == 255) {
            length = read_u16(data, offset);
            offset += 2;
        }
    }
    if (offset > data.size() || length > data.size() - offset) {
        throw std::invalid_argument("truncated IPFIX data record");
    }
    value = data.subspan(offset, length);
    offset += length;
    return true;
}

}  // namespace

// Atualiza templates e converte Data Sets conhecidos em eventos de trafego.
std::vector<TrafficEvent> IpfixDecoder::decode(
    std::span<const std::uint8_t> message,
    const std::string& exporter,
    std::uint64_t received_at_unix_seconds) {
    if (message.size() < 16 || read_u16(message, 0) != 10) {
        throw std::invalid_argument("invalid IPFIX message header or unsupported version");
    }
    const auto message_length = read_u16(message, 2);
    if (message_length < 16 || message_length != message.size()) {
        throw std::invalid_argument("invalid IPFIX message length");
    }
    const auto observation_domain = read_u32(message, 12);
    std::vector<TrafficEvent> events;

    std::size_t set_offset = 16;
    while (set_offset < message.size()) {
        if (message.size() - set_offset < 4) {
            if (all_zero(message.subspan(set_offset))) {
                break;
            }
            throw std::invalid_argument("truncated IPFIX set header");
        }
        const auto set_id = read_u16(message, set_offset);
        const auto set_length = read_u16(message, set_offset + 2);
        if (set_length < 4 || set_length > message.size() - set_offset) {
            throw std::invalid_argument("invalid IPFIX set length");
        }
        const auto set = message.subspan(set_offset + 4, set_length - 4);
        std::size_t offset = 0;

        if (set_id == 2 || set_id == 3) {
            while (offset < set.size()) {
                if (set.size() - offset < 4) {
                    if (all_zero(set.subspan(offset))) {
                        break;
                    }
                    throw std::invalid_argument("truncated IPFIX template");
                }
                const auto template_id = read_u16(set, offset);
                const auto field_count = read_u16(set, offset + 2);
                offset += 4;
                if (template_id < minimum_template_id) {
                    throw std::invalid_argument("invalid IPFIX template ID");
                }
                // IPFIX templates are scoped to an exporter and Observation Domain.
                const TemplateKey key{exporter, observation_domain, template_id};
                if (field_count == 0) {
                    templates_.erase(key);
                    continue;
                }
                if (set_id == 3) {
                    if (set.size() - offset < 2) {
                        throw std::invalid_argument("truncated IPFIX options template");
                    }
                    const auto scope_count = read_u16(set, offset);
                    offset += 2;
                    if (scope_count > field_count) {
                        throw std::invalid_argument("invalid IPFIX options scope count");
                    }
                }
                std::vector<Field> fields;
                fields.reserve(field_count);
                for (std::uint16_t field_index = 0; field_index < field_count; ++field_index) {
                    if (set.size() - offset < 4) {
                        throw std::invalid_argument("truncated IPFIX template field");
                    }
                    const auto raw_id = read_u16(set, offset);
                    const auto length = read_u16(set, offset + 2);
                    offset += 4;
                    const bool enterprise = (raw_id & 0x8000U) != 0;
                    if (enterprise) {
                        if (set.size() - offset < 4) {
                            throw std::invalid_argument("truncated IPFIX enterprise field");
                        }
                        offset += 4;
                    }
                    if (length == 0) {
                        throw std::invalid_argument("invalid zero-length IPFIX template field");
                    }
                    fields.push_back({static_cast<std::uint16_t>(raw_id & 0x7fffU), length, enterprise});
                }
                templates_[key] = std::move(fields);
            }
        } else if (set_id >= minimum_template_id) {
            const auto template_it = templates_.find({exporter, observation_domain, set_id});
            if (template_it != templates_.end()) {
                const auto& fields = template_it->second;
                const bool variable = std::any_of(fields.begin(), fields.end(), [](const Field& field) {
                    return field.length == variable_length;
                });
                std::size_t fixed_record_length = 0;
                if (!variable) {
                    for (const auto& field : fields) {
                        fixed_record_length += field.length;
                    }
                    if (fixed_record_length == 0) {
                        throw std::invalid_argument("empty IPFIX data template");
                    }
                }
                while (offset < set.size()) {
                    const auto remaining = set.subspan(offset);
                    if (variable && remaining.size() <= 3 && all_zero(remaining)) {
                        break;
                    }
                    if (!variable && remaining.size() < fixed_record_length) {
                        if (all_zero(remaining)) {
                            break;
                        }
                        throw std::invalid_argument("truncated IPFIX data record");
                    }
                    std::vector<RecordField> values;
                    values.reserve(fields.size());
                    for (const auto& field : fields) {
                        std::span<const std::uint8_t> value;
                        if (!next_field_value(set, offset, field.length, value)) {
                            throw std::invalid_argument("truncated IPFIX variable-length field");
                        }
                        values.push_back({field.id, value, field.enterprise});
                    }

                    std::string source_ip;
                    std::string destination_ip;
                    std::string protocol = "IP";
                    std::uint64_t packets = 1;
                    std::uint64_t bytes = 0;
                    for (const auto& value : values) {
                        if (value.enterprise) {
                            continue;
                        }
                        switch (value.id) {
                        case 8: source_ip = format_address(value.value, AF_INET); break;
                        case 12: destination_ip = format_address(value.value, AF_INET); break;
                        case 27: source_ip = format_address(value.value, AF_INET6); break;
                        case 28: destination_ip = format_address(value.value, AF_INET6); break;
                        case 4: protocol = protocol_name(value.value); break;
                        case 2:
                        case 86: packets = read_unsigned(value.value); break;
                        case 1:
                        case 85: bytes = read_unsigned(value.value); break;
                        default: break;
                        }
                    }
                    if (!source_ip.empty() && !destination_ip.empty()) {
                        events.push_back({
                            .timestamp_unix_seconds = received_at_unix_seconds,
                            .source_ip = std::move(source_ip),
                            .destination_ip = std::move(destination_ip),
                            .protocol = std::move(protocol),
                            .packets = packets,
                            .bytes = bytes,
                        });
                    }
                }
            }
        }
        set_offset += set_length;
    }
    return events;
}

}  // namespace evos