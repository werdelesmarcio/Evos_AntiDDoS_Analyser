#include "evos/analyzer.hpp"

#include <charconv>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

void print_usage(std::ostream& output) {
    output << "Uso: evos-analyzer --input <arquivo.csv|-> [opcoes]\n"
           << "\n"
           << "CSV: timestamp_unix_seconds,source_ip,destination_ip,protocol,packets,bytes\n"
           << "Os eventos devem estar ordenados pelo timestamp. Uma linha de cabecalho e aceita.\n"
           << "\n"
           << "Opcoes:\n"
           << "  --input <caminho>       Arquivo CSV ou '-' para stdin\n"
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

std::uint64_t parse_option_value(std::string_view value, const std::string& option) {
    std::uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (error != std::errc{} || end != value.data() + value.size() || parsed == 0) {
        throw std::invalid_argument(option + " deve ser um inteiro maior que zero");
    }
    return parsed;
}

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
    evos::Thresholds thresholds;
};

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
    if (options.input_path.empty()) {
        throw std::invalid_argument("--input is required");
    }
    return options;
}

void write_alerts(const std::vector<evos::Alert>& alerts) {
    for (const auto& alert : alerts) {
        std::cout << evos::alert_to_json(alert) << '\n';
    }
}

}  // namespace

int main(int argc, char* argv[]) {
    try {
        const auto options = parse_options(argc, argv);
        std::ifstream file;
        std::istream* input = &std::cin;
        if (options.input_path != "-") {
            file.open(options.input_path);
            if (!file) {
                throw std::runtime_error("could not open input file: " + options.input_path);
            }
            input = &file;
        }

        evos::Analyzer analyzer(options.thresholds);
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
                write_alerts(analyzer.consume(evos::parse_csv_event(line)));
            } catch (const std::exception& error) {
                throw std::runtime_error("line " + std::to_string(line_number) + ": " + error.what());
            }
        }
        if (input->bad()) {
            throw std::runtime_error("error while reading input");
        }
        write_alerts(analyzer.finish());
    } catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        print_usage(std::cerr);
        return 2;
    }
    return 0;
}