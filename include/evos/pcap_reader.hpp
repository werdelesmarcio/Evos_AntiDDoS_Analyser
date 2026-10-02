#pragma once

#include <cstdint>
#include <istream>
#include <vector>

namespace evos {

// Quadro capturado e seus metadados de tempo e tamanho original.
struct CapturedPacket {
    std::uint64_t timestamp_unix_seconds;
    std::uint32_t wire_length;
    std::vector<std::uint8_t> bytes;
};

// Leitor de PCAP classico com suporte a ordem de bytes e precisao temporal.
class PcapReader {
public:
    // Valida o cabecalho global antes de permitir a leitura dos registros.
    explicit PcapReader(std::istream& input);

    // Le o proximo registro; retorna false ao chegar ao fim do arquivo.
    bool next(CapturedPacket& packet);

private:
    std::istream& input_;
    bool little_endian_ = false;
    bool nanosecond_timestamps_ = false;
    std::uint32_t snapshot_length_ = 0;
};

}  // namespace evos