#include "evos/analyzer.hpp"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

// Cria um evento direcionado ao mesmo destino para facilitar os cenarios.
evos::TrafficEvent event(std::uint64_t timestamp, std::string source, std::uint64_t packets, std::uint64_t bytes) {
    return {timestamp, std::move(source), "203.0.113.10", "TCP", packets, bytes};
}

// Confere a conversao CSV e a rejeicao de contadores negativos.
void test_csv_parser() {
    const auto parsed = evos::parse_csv_event("1001,198.51.100.1,203.0.113.10,TCP,12,1400");
    assert(parsed.timestamp_unix_seconds == 1001);
    assert(parsed.source_ip == "198.51.100.1");
    assert(parsed.packets == 12);
    assert(parsed.bytes == 1400);

    bool rejected = false;
    try {
        (void)evos::parse_csv_event("1001,198.51.100.1,203.0.113.10,TCP,-1,1400");
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);
}

// Verifica agregacao entre eventos e alerta ao exceder pacotes por fluxo.
void test_aggregation_and_packet_threshold() {
    evos::Analyzer analyzer({10, 10, 1000, 1000, 100000, 5, 3.0});
    assert(analyzer.consume(event(1001, "198.51.100.1", 6, 400)).empty());
    assert(analyzer.consume(event(1009, "198.51.100.1", 5, 400)).empty());
    assert(analyzer.consume(event(1009, "198.51.100.2", 1, 10)).empty());

    const auto alerts = analyzer.consume(event(1010, "198.51.100.2", 1, 10));
    assert(alerts.size() == 1);
    assert(alerts.front().source_ip == "198.51.100.1");
    assert(alerts.front().scope == evos::AlertScope::Source);
    assert(alerts.front().destination_ip == "203.0.113.10");
    assert(alerts.front().window_start_unix_seconds == 1000);
    assert(alerts.front().packets == 11);
    assert(alerts.front().bytes == 800);
    assert(alerts.front().reasons == std::vector<std::string>{"packet_threshold"});
    assert(analyzer.finish().empty());
}

// Confere limite de bytes e escape de caracteres especiais no JSON.
void test_byte_threshold_and_json_escaping() {
    evos::Analyzer analyzer({10, 100, 500, 1000, 100000, 5, 3.0});
    assert(analyzer.consume(event(2000, "198.51.100.\"1", 1, 501)).empty());
    const auto alerts = analyzer.finish();
    assert(alerts.size() == 1);
    assert(alerts.front().reasons == std::vector<std::string>{"byte_threshold"});
    assert(evos::alert_to_json(alerts.front()).find("198.51.100.\\\"1") != std::string::npos);
    assert(analyzer.finish().empty());
}

// Garante que eventos atrasados nao alterem janelas ja processadas.
void test_rejects_out_of_order_events() {
    evos::Analyzer analyzer({10, 100, 1000, 1000, 100000, 5, 3.0});
    (void)analyzer.consume(event(1010, "198.51.100.1", 1, 100));
    bool rejected = false;
    try {
        (void)analyzer.consume(event(1009, "198.51.100.1", 1, 100));
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);
}

// Detecta excesso agregado por destino mesmo com varias origens.
void test_detects_distributed_destination_flood() {
    evos::Analyzer analyzer({10, 10, 1000, 10, 1000, 5, 3.0});
    assert(analyzer.consume(event(3001, "198.51.100.1", 6, 400)).empty());
    assert(analyzer.consume(event(3002, "198.51.100.2", 6, 400)).empty());

    const auto alerts = analyzer.consume({3010, "198.51.100.3", "203.0.113.20", "UDP", 1, 10});
    assert(alerts.size() == 1);
    assert(alerts.front().scope == evos::AlertScope::Destination);
    assert(alerts.front().source_ip.empty());
    assert(alerts.front().destination_ip == "203.0.113.10");
    assert(alerts.front().packets == 12);
    assert(alerts.front().reasons == std::vector<std::string>{"destination_packet_threshold"});
    assert(evos::alert_to_json(alerts.front()).find("\"source_ip\":null") != std::string::npos);
}

// Detecta picos contra o baseline sem incorporar a janela suspeita.
void test_detects_spike_against_prior_baseline_without_learning_attack() {
    evos::Analyzer analyzer({10, 100000, 10000000, 100000, 10000000, 3, 2.0});
    assert(analyzer.consume(event(0, "198.51.100.1", 100, 1000)).empty());
    assert(analyzer.consume(event(10, "198.51.100.1", 110, 1100)).empty());
    assert(analyzer.consume(event(20, "198.51.100.1", 90, 900)).empty());
    assert(analyzer.consume(event(30, "198.51.100.1", 105, 1050)).empty());
    assert(analyzer.consume(event(40, "198.51.100.1", 1000, 10000)).empty());

    const auto spike_alerts = analyzer.consume(event(50, "198.51.100.1", 100, 1000));
    assert(spike_alerts.size() == 1);
    assert(spike_alerts.front().scope == evos::AlertScope::Destination);
    assert(spike_alerts.front().window_start_unix_seconds == 40);
    assert(spike_alerts.front().reasons ==
        (std::vector<std::string>{"destination_packet_anomaly", "destination_byte_anomaly"}));

    assert(analyzer.consume(event(60, "198.51.100.1", 100, 1000)).empty());
    assert(analyzer.finish().empty());
}

}  // namespace

int main() {
    test_csv_parser();
    test_aggregation_and_packet_threshold();
    test_byte_threshold_and_json_escaping();
    test_rejects_out_of_order_events();
    test_detects_distributed_destination_flood();
    test_detects_spike_against_prior_baseline_without_learning_attack();
}