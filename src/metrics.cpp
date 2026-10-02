#include "evos/metrics.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <cerrno>
#include <string_view>
#include <stdexcept>
#include <system_error>

namespace evos {
namespace {

// Monta uma resposta HTTP completa com tamanho e tipo de conteudo.
std::string http_response(int status, const char* reason, const char* content_type, const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n" +
        "Content-Type: " + content_type + "\r\n" +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" + body;
}

// Envia a resposta inteira, repetindo operacoes interrompidas ou parciais.
void send_response(int client_fd, const std::string& response) noexcept {
    std::size_t sent = 0;
    while (sent < response.size()) {
        const auto result = send(client_fd, response.data() + sent, response.size() - sent, MSG_NOSIGNAL);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return;
        }
        sent += static_cast<std::size_t>(result);
    }
}

}  // namespace

void Metrics::observe_event(const TrafficEvent& event) noexcept {
    packets_total_.fetch_add(event.packets, std::memory_order_relaxed);
    bytes_total_.fetch_add(event.bytes, std::memory_order_relaxed);
}

void Metrics::observe_alert(const Alert& alert) noexcept {
    auto& counter = alert.scope == AlertScope::Source ? source_alerts_total_ : destination_alerts_total_;
    counter.fetch_add(1, std::memory_order_relaxed);
}

void Metrics::set_capture_active(bool active) noexcept {
    capture_active_.store(active, std::memory_order_relaxed);
}

std::string Metrics::render_prometheus() const {
    std::string output;
    output += "# HELP evos_packets_total Packets observed by the analyzer.\n";
    output += "# TYPE evos_packets_total counter\n";
    output += "evos_packets_total " + std::to_string(packets_total_.load(std::memory_order_relaxed)) + "\n";
    output += "# HELP evos_bytes_total Wire bytes observed by the analyzer.\n";
    output += "# TYPE evos_bytes_total counter\n";
    output += "evos_bytes_total " + std::to_string(bytes_total_.load(std::memory_order_relaxed)) + "\n";
    output += "# HELP evos_alerts_total Alerts emitted by scope.\n";
    output += "# TYPE evos_alerts_total counter\n";
    output += "evos_alerts_total{scope=\"source\"} " +
        std::to_string(source_alerts_total_.load(std::memory_order_relaxed)) + "\n";
    output += "evos_alerts_total{scope=\"destination\"} " +
        std::to_string(destination_alerts_total_.load(std::memory_order_relaxed)) + "\n";
    output += "# HELP evos_capture_active Whether live packet capture is active.\n";
    output += "# TYPE evos_capture_active gauge\n";
    output += std::string("evos_capture_active ") +
        (capture_active_.load(std::memory_order_relaxed) ? "1\n" : "0\n");
    return output;
}

MetricsServer::MetricsServer(const std::string& address, const Metrics& metrics) : metrics_(metrics) {
    const auto separator = address.rfind(':');
    if (separator == std::string::npos || separator == 0 || separator + 1 == address.size()) {
        throw std::invalid_argument("metrics address must use IPv4 host:port format");
    }

    auto host = address.substr(0, separator);
    if (host == "localhost") {
        host = "127.0.0.1";
    }
    unsigned int requested_port = 0;
    const auto port_text = std::string_view(address).substr(separator + 1);
    const auto [end, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), requested_port);
    if (error != std::errc{} || end != port_text.data() + port_text.size() || requested_port > 65535) {
        throw std::invalid_argument("metrics port must be between 0 and 65535");
    }

    sockaddr_in listen_address{};
    listen_address.sin_family = AF_INET;
    listen_address.sin_port = htons(static_cast<std::uint16_t>(requested_port));
    if (inet_pton(AF_INET, host.c_str(), &listen_address.sin_addr) != 1) {
        throw std::invalid_argument("metrics host must be an IPv4 address or localhost");
    }

    listen_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listen_fd_ < 0) {
        throw std::system_error(errno, std::generic_category(), "cannot create metrics socket");
    }
    int reuse_address = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse_address, sizeof(reuse_address)) < 0 ||
        bind(listen_fd_, reinterpret_cast<sockaddr*>(&listen_address), sizeof(listen_address)) < 0 ||
        listen(listen_fd_, 8) < 0) {
        const auto error_code = errno;
        close(listen_fd_);
        listen_fd_ = -1;
        throw std::system_error(error_code, std::generic_category(), "cannot start metrics endpoint");
    }

    socklen_t address_length = sizeof(listen_address);
    if (getsockname(listen_fd_, reinterpret_cast<sockaddr*>(&listen_address), &address_length) < 0) {
        const auto error_code = errno;
        close(listen_fd_);
        listen_fd_ = -1;
        throw std::system_error(error_code, std::generic_category(), "cannot inspect metrics endpoint");
    }
    port_ = ntohs(listen_address.sin_port);
    worker_ = std::thread(&MetricsServer::serve, this);
}

MetricsServer::~MetricsServer() {
    stopping_.store(true, std::memory_order_relaxed);
    if (worker_.joinable()) {
        worker_.join();
    }
    if (listen_fd_ >= 0) {
        close(listen_fd_);
    }
}

std::uint16_t MetricsServer::port() const noexcept {
    return port_;
}

void MetricsServer::serve() {
    while (!stopping_.load(std::memory_order_relaxed)) {
        pollfd descriptor{listen_fd_, POLLIN, 0};
        const auto ready = poll(&descriptor, 1, 100);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (ready == 0 || (descriptor.revents & POLLIN) == 0) {
            continue;
        }

        const auto client_fd = accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (client_fd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            return;
        }
        serve_client(client_fd);
        close(client_fd);
    }
}

void MetricsServer::serve_client(int client_fd) const noexcept {
    std::array<char, 2048> request{};
    std::size_t received = 0;
    bool complete = false;
    while (received < request.size() && !complete) {
        pollfd descriptor{client_fd, POLLIN, 0};
        const auto ready = poll(&descriptor, 1, 500);
        if (ready <= 0 || (descriptor.revents & POLLIN) == 0) {
            return;
        }
        const auto result = recv(client_fd, request.data() + received, request.size() - received, 0);
        if (result < 0 && errno == EINTR) {
            continue;
        }
        if (result <= 0) {
            return;
        }
        received += static_cast<std::size_t>(result);
        complete = std::string_view(request.data(), received).find("\r\n\r\n") != std::string_view::npos;
    }

    const std::string_view request_text(request.data(), received);
    if (request_text.starts_with("GET /metrics ")) {
        send_response(client_fd, http_response(200, "OK", "text/plain; version=0.0.4; charset=utf-8",
            metrics_.render_prometheus()));
    } else {
        send_response(client_fd, http_response(404, "Not Found", "text/plain; charset=utf-8", "not found\n"));
    }
}

}  // namespace evos