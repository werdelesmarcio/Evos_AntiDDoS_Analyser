#include "evos/metrics.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace {

std::string request_metrics(std::uint16_t port, const std::string& path) {
    const auto client_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (client_fd < 0) {
        throw std::runtime_error("could not create metrics test socket");
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    if (connect(client_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        close(client_fd);
        throw std::runtime_error("could not connect to metrics test server");
    }

    const auto request = "GET " + path + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if (send(client_fd, request.data(), request.size(), 0) < 0) {
        close(client_fd);
        throw std::runtime_error("could not send metrics test request");
    }

    std::string response;
    char buffer[512];
    for (;;) {
        const auto received = recv(client_fd, buffer, sizeof(buffer), 0);
        if (received == 0) {
            break;
        }
        if (received < 0) {
            close(client_fd);
            throw std::runtime_error("could not read metrics test response");
        }
        response.append(buffer, static_cast<std::size_t>(received));
    }
    close(client_fd);
    return response;
}

void test_prometheus_endpoint() {
    evos::Metrics metrics;
    metrics.observe_event({100, "192.0.2.1", "198.51.100.1", "TCP", 3, 300});
    metrics.observe_alert({100, 10, evos::AlertScope::Source, "192.0.2.1", "198.51.100.1", 3, 300,
        {"packet_threshold"}});
    metrics.observe_alert({100, 10, evos::AlertScope::Destination, {}, "198.51.100.1", 3, 300,
        {"destination_packet_threshold"}});
    metrics.set_capture_active(true);

    evos::MetricsServer server("127.0.0.1:0", metrics);
    const auto response = request_metrics(server.port(), "/metrics");
    assert(response.find("HTTP/1.1 200 OK") != std::string::npos);
    assert(response.find("evos_packets_total 3\n") != std::string::npos);
    assert(response.find("evos_bytes_total 300\n") != std::string::npos);
    assert(response.find("evos_alerts_total{scope=\"source\"} 1\n") != std::string::npos);
    assert(response.find("evos_alerts_total{scope=\"destination\"} 1\n") != std::string::npos);
    assert(response.find("evos_capture_active 1\n") != std::string::npos);

    const auto missing = request_metrics(server.port(), "/not-found");
    assert(missing.find("HTTP/1.1 404 Not Found") != std::string::npos);
}

}  // namespace

int main() {
    test_prometheus_endpoint();
}