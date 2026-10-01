#pragma once

#include "evos/analyzer.hpp"

#include <cstdint>
#include <optional>
#include <span>

namespace evos {

std::optional<TrafficEvent> decode_ethernet_packet(
    std::span<const std::uint8_t> frame,
    std::uint64_t timestamp_unix_seconds,
    std::uint32_t wire_length);

}  // namespace evos