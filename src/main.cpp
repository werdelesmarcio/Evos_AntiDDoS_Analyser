#include "evos/analyzer.hpp"
#include "evos/ipfix_receiver.hpp"
#include "evos/live_capture.hpp"
#include "evos/metrics.hpp"
#include "evos/packet_decoder.hpp"
#include "evos/pcap_reader.hpp"

#include <charconv>
#include <csignal>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

volatile std::sig_atomic_t stop_requested = 0;

// Sinaliza aos loops de captura que devem encerrar com seguranca.
void request_stop(int) {
    stop_requested = 1;
}

// Lista os modos de entrada, limites e opcoes aceitos pelo executavel.
void print_usage(std::ostream& output) {
    output << "Uso: evos-analyzer (--input <arquivo.csv|-> | --pcap <arquivo.pcap|-> | --interface <nome> | --ipfix-port <porta>) [opcoes]\n"
           << "\n"
           << "CSV: timestamp_unix_seconds,source_ip,destination_ip,protocol,packets,bytes\n"
           << "Os eventos devem estar ordenados pelo timestamp. Uma linha de cabecalho e aceita.\n"
           << "PCAP: formato classico, link Ethernet; decodifica IPv4, IPv6 e VLAN.\n"
           << "Captura ao vivo: AF_PACKET/TPACKET_V3 passivo; requer CAP_NET_RAW e encerra com Ctrl+C.\n"
           << "IPFIX: NetFlow v10 por UDP; aguarda templates e fluxos, usando o timestamp de recebimento.\n"
           << "\n"
           << "Opcoes:\n"
           << "  --input <caminho>       Arquivo CSV ou '-' para stdin\n"
           << "  --pcap <caminho>        Captura PCAP offline ou '-' para stdin\n"
           << "  --interface <nome>      Captura ao vivo na interface de rede\n"
           << "  --ipfix-port <porta>    Escuta IPFIX/UDP em todas as interfaces (padrao: 2055)\n"
           << "  --metrics-address <ip:porta>  Exportador Prometheus (ex: 127.0.0.1:9108)\n"
           << "  --window-seconds <n>    Duracao da janela (padrao: 10)\n"
           << "  --max-packets <n>       Limite por origem/destino/janela (padrao: 10000)\n"
           << "  --max-bytes <n>         Limite por origem/destino/janela (padrao: 10000000)\n"
           << "  --max-destination-packets <n>  Limite agregado por destino (padrao: 50000)\n"
           << "  --max-destination-bytes <n>    Limite agregado por destino (padrao: 50000000)\n"
           << "  --baseline-windows <n>  Janelas anteriores para aquecer baseline (padrao: 5)\n"
           << "  --baseline-sigma <n>    Desvios padrao acima da media (padrao: 3)\n"
           << "O baseline e calculado por destino; janelas alertadas nao entram no aprendizado.\n"
           << "  --help                  Exibe esta ajuda\n";
}

// Converte uma opcao inteira positiva e associa erros ao nome da opcao.
std::uint64_t parse_option_value(std::string_view value, const std::string& option) {
    std::uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || parsed == 0) {
        throw std::invalid_argument(option + " deve ser um inteiro maior que zero");
    }
    return parsed;
}

// Converte o multiplicador do baseline e rejeita valores nao finitos ou nulos.
double parse_sigma(std::string_view value) {
    double parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || !std::isfinite(parsed) || parsed <= 0) {
        throw std::invalid_argument("--baseline-sigma deve ser um numero maior que zero");
    }
    return parsed;
}

struct Options {
    std::string input_path;
    std::string pcap_path;
    std::string interface_name;
    std::uint16_t ipfix_port = 2055;
    bool receive_ipfix = false;
    std::string metrics_address;
    evos::Thresholds thresholds;
};

// Interpreta argumentos e exige exatamente um modo de entrada.
Options parse_options(int argc, char* argv[]) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string argument(argv[index]);
        if (argument == "--help") {
            print_usage(std::cout);
            std::exit(0);
        }
        if (index + 1 >= argc) {
            throw std::invalid_argument("missing value for " + argument);
        }
        const std::string value(argv[++index]);
        if (argument == "--input") {
            options.input_path = value;
        } else if (argument == "--pcap") {
            options.pcap_path = value;
        } else if (argument == "--interface") {
            options.interface_name = value;
        } else if (argument == "--ipfix-port") {
            const auto port = parse_option_value(value, argument);
            if (port > 65535) {
                throw std::invalid_argument("--ipfix-port deve estar entre 1 e 65535");
            }
            options.ipfix_port = static_cast<std::uint16_t>(port);
            options.receive_ipfix = true;
        } else if (argument == "--metrics-address") {
            options.metrics_address = value;
        } else if (argument == "--window-seconds") {
            options.thresholds.window_seconds = parse_option_value(value, argument);
        } else if (argument == "--max-packets") {
            options.thresholds.max_packets = parse_option_value(value, argument);
        } else if (argument == "--max-bytes") {
            options.thresholds.max_bytes = parse_option_value(value, argument);
        } else if (argument == "--max-destination-packets") {
            options.thresholds.max_destination_packets = parse_option_value(value, argument);
        } else if (argument == "--max-destination-bytes") {
            options.thresholds.max_destination_bytes = parse_option_value(value, argument);
        } else if (argument == "--baseline-windows") {
            options.thresholds.baseline_min_windows = parse_option_value(value, argument);
        } else if (argument == "--baseline-sigma") {
            options.thresholds.baseline_sigma = parse_sigma(value);
        } else {
            throw std::invalid_argument("unknown option: " + argument);
        }
    }
    const auto input_modes = static_cast<unsigned int>(!options.input_path.empty()) +
        static_cast<unsigned int>(!options.pcap_path.empty()) +
        static_cast<unsigned int>(!options.interface_name.empty()) +
        static_cast<unsigned int>(options.receive_ipfix);
    if (input_modes != 1) {
        throw std::invalid_argument("provide exactly one input mode: --input, --pcap, --interface, or --ipfix-port");
    }
    return options;
}

// Registra metricas e imprime cada alerta em JSON Lines.
void write_alerts(const std::vector<evos::Alert>& alerts, evos::Metrics& metrics) {
    for (const auto& alert : alerts) {
        metrics.observe_alert(alert);
        std::cout << evos::alert_to_json(alert) << '\n';
    }
}

}  // namespace

// Inicializa os servicos e encaminha cada fonte de dados ao analisador.
int main(int argc, char* argv[]) {
    try {
        const auto options = parse_options(argc, argv);
        const bool reading_pcap = !options.pcap_path.empty();
        const bool capturing_live = !options.interface_name.empty();
        const bool receiving_ipfix = options.receive_ipfix;
        const auto& input_path = reading_pcap ? options.pcap_path : options.input_path;
        std::ifstream file;
        std::istream* input = &std::cin;
        if (!capturing_live && !receiving_ipfix && input_path != "-") {
            file.open(input_path, reading_pcap ? std::ios::binary : std::ios::in);
            if (!file) {
                throw std::runtime_error("could not open input file: " + input_path);
            }
            input = &file;
        }

        evos::Analyzer analyzer(options.thresholds);
        evos::Metrics metrics;
        std::unique_ptr<evos::MetricsServer> metrics_server;
        if (!options.metrics_address.empty()) {
            metrics_server = std::make_unique<evos::MetricsServer>(options.metrics_address, metrics);
        }
        if (capturing_live) {
            std::signal(SIGINT, request_stop);
            std::signal(SIGTERM, request_stop);
            // AF_PACKET observes packets without changing the traffic path.
            metrics.set_capture_active(true);
            try {
                evos::capture_live_packets(options.interface_name, analyzer, stop_requested,
                    [&metrics](const evos::TrafficEvent& event) {
                        metrics.observe_event(event);
                    },
                [&metrics](const evos::Alert& alert) {
                    metrics.observe_alert(alert);
                    std::cout << evos::alert_to_json(alert) << '\n';
                });
            } catch (...) {
                metrics.set_capture_active(false);
                throw;
            }
            metrics.set_capture_active(false);
        } else if (receiving_ipfix) {
            std::signal(SIGINT, request_stop);
            std::signal(SIGTERM, request_stop);
            metrics.set_capture_active(true);
            try {
                evos::receive_ipfix(options.ipfix_port, analyzer, stop_requested,
                    [&metrics](const evos::TrafficEvent& event) {
                        metrics.observe_event(event);
                    },
                    [&metrics](const evos::Alert& alert) {
                        metrics.observe_alert(alert);
                        std::cout << evos::alert_to_json(alert) << '\n';
                    });
            } catch (...) {
                metrics.set_capture_active(false);
                throw;
            }
            metrics.set_capture_active(false);
        } else if (reading_pcap) {
            evos::PcapReader reader(*input);
            evos::CapturedPacket packet{};
            while (reader.next(packet)) {
                // Convert decoded frames to the same event stream used by CSV input.
                const auto event = evos::decode_ethernet_packet(
                    packet.bytes, packet.timestamp_unix_seconds, packet.wire_length);
                if (event.has_value()) {
                    metrics.observe_event(*event);
                    write_alerts(analyzer.consume(*event), metrics);
                }
            }
        } else {
            std::string line;
            std::size_t line_number = 0;
            bool first_record = true;
            while (std::getline(*input, line)) {
                ++line_number;
                if (line.empty()) {
                    continue;
                }
                if (first_record) {
                    first_record = false;
                    if (line == "timestamp_unix_seconds,source_ip,destination_ip,protocol,packets,bytes") {
                        continue;
                    }
                }
                try {
                    const auto event = evos::parse_csv_event(line);
                    metrics.observe_event(event);
                    write_alerts(analyzer.consume(event), metrics);
                } catch (const std::exception& error) {
                    throw std::runtime_error("line " + std::to_string(line_number) + ": " + error.what());
                }
            }
        }
        if (!capturing_live && input->bad()) {
            throw std::runtime_error("error while reading input");
        }
        write_alerts(analyzer.finish(), metrics);
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        print_usage(std::cerr);
        return 2;
    }
    return 0;
}