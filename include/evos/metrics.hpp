#pragma once

#include "evos/analyzer.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace evos {

class Metrics {
public:
    void observe_event(const TrafficEvent& event) noexcept;
    void observe_alert(const Alert& alert) noexcept;
    void set_capture_active(bool active) noexcept;
    std::string render_prometheus() const;

private:
    std::atomic<std::uint64_t> packets_total_{0};
    std::atomic<std::uint64_t> bytes_total_{0};
    std::atomic<std::uint64_t> source_alerts_total_{0};
    std::atomic<std::uint64_t> destination_alerts_total_{0};
    std::atomic<bool> capture_active_{false};
};

class MetricsServer {
public:
    MetricsServer(const std::string& address, const Metrics& metrics);
    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;
    ~MetricsServer();

    std::uint16_t port() const noexcept;

private:
    void serve();
    void serve_client(int client_fd) const noexcept;

    const Metrics& metrics_;
    int listen_fd_ = -1;
    std::uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

}  // namespace evos