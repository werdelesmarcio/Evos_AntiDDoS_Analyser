#pragma once

#include "evos/analyzer.hpp"

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <tuple>
#include <vector>

namespace evos {

// Decodifica mensagens IPFIX e conserva templates por exportador e dominio.
class IpfixDecoder {
public:
    // Aprende templates ou converte Data Sets em eventos normalizados.
    std::vector<TrafficEvent> decode(
        std::span<const std::uint8_t> message,
        const std::string& exporter,
        std::uint64_t received_at_unix_seconds);

private:
    struct Field {
        std::uint16_t id;
        std::uint16_t length;
        bool enterprise;
    };

    using TemplateKey = std::tuple<std::string, std::uint32_t, std::uint16_t>;
    std::map<TemplateKey, std::vector<Field>> templates_;
};

}  // namespace evos