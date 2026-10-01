#pragma once

#include <cstdint>
#include <istream>
#include <vector>

namespace evos {

struct CapturedPacket {
    std::uint64_t timestamp_unix_seconds;
    std::uint32_t wire_length;
    std::vector<std::uint8_t> bytes;
};

class PcapReader {
public:
    explicit PcapReader(std::istream& input);

    bool next(CapturedPacket& packet);

private:
    std::istream& input_;
    bool little_endian_ = false;
    bool nanosecond_timestamps_ = false;
    std::uint32_t snapshot_length_ = 0;
};

}  // namespace evos