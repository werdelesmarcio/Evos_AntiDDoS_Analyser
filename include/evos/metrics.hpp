#pragma once

#include "evos/analyzer.hpp"

#include <atomic>
#include <cstdint>
#include <string>
#include <thread>

namespace evos {

// Mantem contadores atomicos e os expoe no formato Prometheus.
class Metrics {
public:
    // Soma os contadores do evento processado.
    void observe_event(const TrafficEvent& event) noexcept;
    // Incrementa o contador correspondente ao escopo do alerta.
    void observe_alert(const Alert& alert) noexcept;
    // Atualiza o estado do coletor de trafego.
    void set_capture_active(bool active) noexcept;
    // Renderiza todas as metricas como texto Prometheus.
    std::string render_prometheus() const;

private:
    std::atomic<std::uint64_t> packets_total_{0};
    std::atomic<std::uint64_t> bytes_total_{0};
    std::atomic<std::uint64_t> source_alerts_total_{0};
    std::atomic<std::uint64_t> destination_alerts_total_{0};
    std::atomic<bool> capture_active_{false};
};

// Servidor HTTP pequeno que atende /metrics e 404 para outras rotas.
class MetricsServer {
public:
    // Inicia o endpoint no endereco IPv4 informado; porta zero escolhe uma livre.
    MetricsServer(const std::string& address, const Metrics& metrics);
    MetricsServer(const MetricsServer&) = delete;
    MetricsServer& operator=(const MetricsServer&) = delete;
    ~MetricsServer();

    // Retorna a porta efetiva, inclusive quando a porta solicitada foi zero.
    std::uint16_t port() const noexcept;

private:
    // Aceita conexoes ate o servidor ser encerrado.
    void serve();
    // Responde uma requisicao HTTP com metricas ou 404.
    void serve_client(int client_fd) const noexcept;

    const Metrics& metrics_;
    int listen_fd_ = -1;
    std::uint16_t port_ = 0;
    std::atomic<bool> stopping_{false};
    std::thread worker_;
};

}  // namespace evos