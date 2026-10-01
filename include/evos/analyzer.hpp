#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace evos {

struct TrafficEvent {
    std::uint64_t timestamp_unix_seconds;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    std::uint64_t packets;
    std::uint64_t bytes;
};

struct Thresholds {
    std::uint64_t window_seconds = 10;
    std::uint64_t max_packets = 10000;
    std::uint64_t max_bytes = 10000000;
    std::uint64_t max_destination_packets = 50000;
    std::uint64_t max_destination_bytes = 50000000;
    std::uint64_t baseline_min_windows = 5;
    double baseline_sigma = 3.0;
};

enum class AlertScope {
    Source,
    Destination,
};

struct Alert {
    std::uint64_t window_start_unix_seconds;
    std::uint64_t window_seconds;
    AlertScope scope;
    std::string source_ip;
    std::string destination_ip;
    std::uint64_t packets;
    std::uint64_t bytes;
    std::vector<std::string> reasons;
};

class Analyzer {
public:
    explicit Analyzer(Thresholds thresholds);

    std::vector<Alert> consume(const TrafficEvent& event);
    std::vector<Alert> finish();

private:
    struct Totals {
        std::uint64_t packets = 0;
        std::uint64_t bytes = 0;
    };

    struct BaselineStats {
        std::uint64_t windows = 0;
        long double mean_packets = 0;
        long double packets_m2 = 0;
        long double mean_bytes = 0;
        long double bytes_m2 = 0;
    };

    std::vector<Alert> close_window();
    void add_baseline_sample(BaselineStats& stats, std::uint64_t packets, std::uint64_t bytes);
    void add_empty_baseline_windows(std::uint64_t count);

    Thresholds thresholds_;
    std::uint64_t current_window_start_ = 0;
    std::uint64_t last_timestamp_ = 0;
    bool has_current_window_ = false;
    bool has_last_timestamp_ = false;
    bool finished_ = false;
    std::map<std::pair<std::string, std::string>, Totals> totals_by_flow_;
    std::map<std::string, Totals> totals_by_destination_;
    std::map<std::string, BaselineStats> baseline_by_destination_;
};

TrafficEvent parse_csv_event(const std::string& line);
std::string alert_to_json(const Alert& alert);

}  // namespace evos