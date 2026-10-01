CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Iinclude

BUILD_DIR := build
ANALYZER_SOURCES := src/analyzer.cpp
PACKET_SOURCES := src/pcap_reader.cpp src/packet_decoder.cpp src/live_capture.cpp
METRICS_SOURCES := src/metrics.cpp

.PHONY: all test clean

all: $(BUILD_DIR)/evos-analyzer

$(BUILD_DIR)/evos-analyzer: src/main.cpp $(ANALYZER_SOURCES) $(PACKET_SOURCES) $(METRICS_SOURCES) include/evos/analyzer.hpp include/evos/pcap_reader.hpp include/evos/packet_decoder.hpp include/evos/live_capture.hpp include/evos/metrics.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/main.cpp $(ANALYZER_SOURCES) $(PACKET_SOURCES) $(METRICS_SOURCES) -o $@

$(BUILD_DIR)/analyzer-test: tests/analyzer_test.cpp $(ANALYZER_SOURCES) include/evos/analyzer.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/analyzer_test.cpp $(ANALYZER_SOURCES) -o $@

$(BUILD_DIR)/packet-input-test: tests/packet_input_test.cpp $(PACKET_SOURCES) include/evos/pcap_reader.hpp include/evos/packet_decoder.hpp include/evos/analyzer.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/packet_input_test.cpp $(ANALYZER_SOURCES) $(PACKET_SOURCES) -o $@

$(BUILD_DIR)/metrics-test: tests/metrics_test.cpp $(METRICS_SOURCES) include/evos/metrics.hpp include/evos/analyzer.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/metrics_test.cpp $(METRICS_SOURCES) -pthread -o $@

test: $(BUILD_DIR)/analyzer-test $(BUILD_DIR)/packet-input-test $(BUILD_DIR)/metrics-test
	./$(BUILD_DIR)/analyzer-test
	./$(BUILD_DIR)/packet-input-test
	./$(BUILD_DIR)/metrics-test

clean:
	rm -rf $(BUILD_DIR)