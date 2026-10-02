#include "evos/ipfix.hpp"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <utility>
#include <vector>

namespace {

void append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void append_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 24));
    bytes.push_back(static_cast<std::uint8_t>(value >> 16));
    bytes.push_back(static_cast<std::uint8_t>(value >> 8));
    bytes.push_back(static_cast<std::uint8_t>(value));
}

void finish_message(std::vector<std::uint8_t>& message) {
    const auto length = static_cast<std::uint16_t>(message.size());
    message[2] = static_cast<std::uint8_t>(length >> 8);
    message[3] = static_cast<std::uint8_t>(length);
}

std::vector<std::uint8_t> make_header() {
    std::vector<std::uint8_t> message;
    append_u16(message, 10);
    append_u16(message, 0);
    append_u32(message, 1700000000);
    append_u32(message, 1);
    append_u32(message, 42);
    return message;
}

std::vector<std::uint8_t> make_template_message() {
    auto message = make_header();
    append_u16(message, 2);
    append_u16(message, 28);
    append_u16(message, 256);
    append_u16(message, 5);
    for (const auto [id, length] : std::vector<std::pair<std::uint16_t, std::uint16_t>>{
             {8, 4}, {12, 4}, {4, 1}, {2, 4}, {1, 4}}) {
        append_u16(message, id);
        append_u16(message, length);
    }
    finish_message(message);
    return message;
}

std::vector<std::uint8_t> make_data_message() {
    auto message = make_header();
    append_u16(message, 256);
    append_u16(message, 21);
    message.insert(message.end(), {192, 0, 2, 10, 198, 51, 100, 20, 17});
    append_u32(message, 150);
    append_u32(message, 12000);
    finish_message(message);
    return message;
}

// Aprende um template e usa-o para interpretar o proximo Data Set do exportador.
void test_decodes_data_after_template_from_same_exporter() {
    evos::IpfixDecoder decoder;
    const auto template_message = make_template_message();
    const auto data_message = make_data_message();

    assert(decoder.decode(template_message, "192.0.2.254:2055", 1700000000).empty());
    const auto events = decoder.decode(data_message, "192.0.2.254:2055", 1700000001);
    assert(events.size() == 1);
    assert(events[0].timestamp_unix_seconds == 1700000001);
    assert(events[0].source_ip == "192.0.2.10");
    assert(events[0].destination_ip == "198.51.100.20");
    assert(events[0].protocol == "UDP");
    assert(events[0].packets == 150);
    assert(events[0].bytes == 12000);
}

// Impede que um exportador reutilize templates de outro.
void test_templates_are_isolated_by_exporter() {
    evos::IpfixDecoder decoder;
    const auto template_message = make_template_message();
    const auto data_message = make_data_message();
    decoder.decode(template_message, "192.0.2.254:2055", 1700000000);
    assert(decoder.decode(data_message, "192.0.2.253:2055", 1700000001).empty());
}

// Rejeita mensagens cujo tamanho declarado nao corresponde ao datagrama.
void test_rejects_invalid_message_length() {
    evos::IpfixDecoder decoder;
    auto message = make_template_message();
    message[3]--;
    bool rejected = false;
    try {
        decoder.decode(message, "192.0.2.254:2055", 1700000000);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);
}

}  // namespace

int main() {
    test_decodes_data_after_template_from_same_exporter();
    test_templates_are_isolated_by_exporter();
    test_rejects_invalid_message_length();
}