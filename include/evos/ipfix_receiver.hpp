#pragma once

#include "evos/live_capture.hpp"

#include <csignal>
#include <cstdint>

namespace evos {

// Escuta IPFIX/UDP e envia eventos e alertas aos callbacks fornecidos.
void receive_ipfix(
    std::uint16_t port,
    Analyzer& analyzer,
    const volatile std::sig_atomic_t& stop_requested,
    const EventHandler& on_event,
    const AlertHandler& on_alert);

}  // namespace evos