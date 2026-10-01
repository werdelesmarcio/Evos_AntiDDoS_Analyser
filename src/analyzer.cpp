#include "evos/analyzer.hpp"

#include <charconv>
#include <cmath>
#include <limits>
#include <set>
#include <stdexcept>
#include <string_view>
#include <utility>

namespace evos {
namespace {

std::uint64_t parse_unsigned(std::string_view value, const char* field_name) {
    std::uint64_t result = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), result);
    if (error != std::errc{} || end != value.data() + value.size()) {
        throw std::invalid_argument(std::string("invalid ") + field_name + ": " + std::string(value));
    }
    return result;
}

void add_checked(std::uint64_t& total, std::uint64_t value, const char* field_name) {
    if (value > std::numeric_limits<std::uint64_t>::max() - total) {
        throw std::overflow_error(std::string(field_name) + " total overflow");
    }
    total += value;
}

std::string escape_json(const std::string& value) {
    constexpr char hex[] = "0123456789abcdef";
    std::string escaped;
    escaped.reserve(value.size());
    for (const unsigned char character : value) {
        switch (character) {
        case '"': escaped += "\\\""; break;
        case '\\': escaped += "\\\\"; break;
        case '\b': escaped += "\\b"; break;
        case '\f': escaped += "\\f"; break;
        case '\n': escaped += "\\n"; break;
        case '\r': escaped += "\\r"; break;
        case '\t': escaped += "\\t"; break;
        default:
            if (character < 0x20) {
                escaped += "\\u00";
                escaped += hex[character >> 4];
                escaped += hex[character & 0x0f];
            } else {
                escaped += static_cast<char>(character);
            }
        }
    }
    return escaped;
}

}  // namespace

Analyzer::Analyzer(Thresholds thresholds) : thresholds_(thresholds) {
    if (thresholds_.window_seconds == 0 || thresholds_.max_packets == 0 || thresholds_.max_bytes == 0) {
        throw std::invalid_argument("window and thresholds must be greater than zero");
    }
    if (thresholds_.max_destination_packets == 0 || thresholds_.max_destination_bytes == 0 ||
        thresholds_.baseline_min_windows == 0 || !std::isfinite(thresholds_.baseline_sigma) ||
        thresholds_.baseline_sigma <= 0) {
        throw std::invalid_argument("destination and baseline thresholds must be greater than zero");
    }
}

std::vector<Alert> Analyzer::consume(const TrafficEvent& event) {
    if (finished_) {
        throw std::logic_error("cannot consume events after finish");
    }
    if (event.source_ip.empty() || event.destination_ip.empty() || event.protocol.empty()) {
        throw std::invalid_argument("source_ip, destination_ip, and protocol must not be empty");
    }
    if (has_last_timestamp_ && event.timestamp_unix_seconds < last_timestamp_) {
        throw std::invalid_argument("events must be ordered by timestamp");
    }

    const auto window_start = event.timestamp_unix_seconds -
        (event.timestamp_unix_seconds % thresholds_.window_seconds);
    std::vector<Alert> alerts;
    if (has_current_window_ && window_start != current_window_start_) {
        const auto windows_between = (window_start - current_window_start_) / thresholds_.window_seconds;
        alerts = close_window();
        if (windows_between > 1) {
            add_empty_baseline_windows(windows_between - 1);
        }
        totals_by_flow_.clear();
        totals_by_destination_.clear();
    }

    current_window_start_ = window_start;
    has_current_window_ = true;
    last_timestamp_ = event.timestamp_unix_seconds;
    has_last_timestamp_ = true;

    auto& flow_totals = totals_by_flow_[{event.source_ip, event.destination_ip}];
    add_checked(flow_totals.packets, event.packets, "flow packet");
    add_checked(flow_totals.bytes, event.bytes, "flow byte");
    auto& destination_totals = totals_by_destination_[event.destination_ip];
    add_checked(destination_totals.packets, event.packets, "destination packet");
    add_checked(destination_totals.bytes, event.bytes, "destination byte");
    return alerts;
}

std::vector<Alert> Analyzer::finish() {
    if (finished_) {
        return {};
    }
    finished_ = true;
    if (!has_current_window_) {
        return {};
    }
    return close_window();
}

std::vector<Alert> Analyzer::close_window() {
    std::vector<Alert> alerts;
    std::set<std::string> source_alerted_destinations;
    for (const auto& [flow, totals] : totals_by_flow_) {
        Alert alert{
            .window_start_unix_seconds = current_window_start_,
            .window_seconds = thresholds_.window_seconds,
            .scope = AlertScope::Source,
            .source_ip = flow.first,
            .destination_ip = flow.second,
            .packets = totals.packets,
            .bytes = totals.bytes,
            .reasons = {},
        };
        if (totals.packets > thresholds_.max_packets) {
            alert.reasons.emplace_back("packet_threshold");
        }
        if (totals.bytes > thresholds_.max_bytes) {
            alert.reasons.emplace_back("byte_threshold");
        }
        if (!alert.reasons.empty()) {
            source_alerted_destinations.insert(flow.second);
            alerts.emplace_back(std::move(alert));
        }
    }
    for (const auto& [destination_ip, totals] : totals_by_destination_) {
        auto& baseline = baseline_by_destination_[destination_ip];
        Alert alert{
            .window_start_unix_seconds = current_window_start_,
            .window_seconds = thresholds_.window_seconds,
            .scope = AlertScope::Destination,
            .source_ip = {},
            .destination_ip = destination_ip,
            .packets = totals.packets,
            .bytes = totals.bytes,
            .reasons = {},
        };
        if (totals.packets > thresholds_.max_destination_packets) {
            alert.reasons.emplace_back("destination_packet_threshold");
        }
        if (totals.bytes > thresholds_.max_destination_bytes) {
            alert.reasons.emplace_back("destination_byte_threshold");
        }
        if (baseline.windows >= thresholds_.baseline_min_windows) {
            const auto packets_deviation = std::sqrt(baseline.packets_m2 / baseline.windows);
            const auto bytes_deviation = std::sqrt(baseline.bytes_m2 / baseline.windows);
            if (static_cast<long double>(totals.packets) >
                baseline.mean_packets + thresholds_.baseline_sigma * packets_deviation) {
                alert.reasons.emplace_back("destination_packet_anomaly");
            }
            if (static_cast<long double>(totals.bytes) >
                baseline.mean_bytes + thresholds_.baseline_sigma * bytes_deviation) {
                alert.reasons.emplace_back("destination_byte_anomaly");
            }
        }
        if (!alert.reasons.empty()) {
            alerts.emplace_back(std::move(alert));
        } else if (!source_alerted_destinations.contains(destination_ip)) {
            add_baseline_sample(baseline, totals.packets, totals.bytes);
        }
    }
    for (auto& [destination_ip, baseline] : baseline_by_destination_) {
        if (!totals_by_destination_.contains(destination_ip)) {
            add_baseline_sample(baseline, 0, 0);
        }
    }
    return alerts;
}

void Analyzer::add_baseline_sample(BaselineStats& stats, std::uint64_t packets, std::uint64_t bytes) {
    if (stats.windows == std::numeric_limits<std::uint64_t>::max()) {
        throw std::overflow_error("baseline window count overflow");
    }
    ++stats.windows;
    const auto sample_count = static_cast<long double>(stats.windows);

    const auto packet_delta = static_cast<long double>(packets) - stats.mean_packets;
    stats.mean_packets += packet_delta / sample_count;
    stats.packets_m2 += packet_delta * (static_cast<long double>(packets) - stats.mean_packets);

    const auto byte_delta = static_cast<long double>(bytes) - stats.mean_bytes;
    stats.mean_bytes += byte_delta / sample_count;
    stats.bytes_m2 += byte_delta * (static_cast<long double>(bytes) - stats.mean_bytes);
}

void Analyzer::add_empty_baseline_windows(std::uint64_t count) {
    for (auto& [destination_ip, stats] : baseline_by_destination_) {
        (void)destination_ip;
        if (count > std::numeric_limits<std::uint64_t>::max() - stats.windows) {
            throw std::overflow_error("baseline window count overflow");
        }
        if (stats.windows == 0) {
            stats.windows = count;
            continue;
        }
        const auto old_count = static_cast<long double>(stats.windows);
        const auto empty_count = static_cast<long double>(count);
        const auto new_count = old_count + empty_count;
        stats.packets_m2 += stats.mean_packets * stats.mean_packets * old_count * empty_count / new_count;
        stats.bytes_m2 += stats.mean_bytes * stats.mean_bytes * old_count * empty_count / new_count;
        stats.mean_packets *= old_count / new_count;
        stats.mean_bytes *= old_count / new_count;
        stats.windows += count;
    }
}

TrafficEvent parse_csv_event(const std::string& line) {
    std::string_view remaining(line);
    std::string_view fields[6];
    for (std::size_t index = 0; index < 5; ++index) {
        const auto separator = remaining.find(',');
        if (separator == std::string_view::npos) {
            throw std::invalid_argument("expected six comma-separated fields");
        }
        fields[index] = remaining.substr(0, separator);
        remaining.remove_prefix(separator + 1);
    }
    if (remaining.find(',') != std::string_view::npos) {
        throw std::invalid_argument("expected six comma-separated fields");
    }
    fields[5] = remaining;

    const auto timestamp = parse_unsigned(fields[0], "timestamp");
    const auto packets = parse_unsigned(fields[4], "packets");
    const auto bytes = parse_unsigned(fields[5], "bytes");
    if (fields[1].empty() || fields[2].empty() || fields[3].empty()) {
        throw std::invalid_argument("source_ip, destination_ip, and protocol must not be empty");
    }

    return TrafficEvent{
        .timestamp_unix_seconds = timestamp,
        .source_ip = std::string(fields[1]),
        .destination_ip = std::string(fields[2]),
        .protocol = std::string(fields[3]),
        .packets = packets,
        .bytes = bytes,
    };
}

std::string alert_to_json(const Alert& alert) {
    const char* scope = alert.scope == AlertScope::Source ? "source" : "destination";
    std::string json = "{\"window_start_unix_seconds\":" + std::to_string(alert.window_start_unix_seconds) +
        ",\"window_seconds\":" + std::to_string(alert.window_seconds) +
        ",\"scope\":\"" + scope + "\",\"source_ip\":";
    if (alert.scope == AlertScope::Source) {
        json += "\"" + escape_json(alert.source_ip) + "\"";
    } else {
        json += "null";
    }
    json += ",\"destination_ip\":\"" + escape_json(alert.destination_ip) +
        "\",\"packets\":" + std::to_string(alert.packets) +
        ",\"bytes\":" + std::to_string(alert.bytes) + ",\"reasons\":[";
    for (std::size_t index = 0; index < alert.reasons.size(); ++index) {
        if (index > 0) {
            json += ',';
        }
        json += '"' + escape_json(alert.reasons[index]) + '"';
    }
    json += "]}";
    return json;
}

}  // namespace evos