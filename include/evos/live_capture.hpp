#pragma once

#include "evos/analyzer.hpp"

#include <csignal>
#include <functional>
#include <string>

namespace evos {

using EventHandler = std::function<void(const TrafficEvent&)>;
using AlertHandler = std::function<void(const Alert&)>;

void capture_live_packets(
    const std::string& interface_name,
    Analyzer& analyzer,
    const volatile std::sig_atomic_t& stop_requested,
    const EventHandler& on_event,
    const AlertHandler& on_alert);

}  // namespace evos