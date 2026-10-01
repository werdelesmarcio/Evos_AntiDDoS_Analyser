CXX ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Iinclude

BUILD_DIR := build
ANALYZER_SOURCES := src/analyzer.cpp

.PHONY: all test clean

all: $(BUILD_DIR)/evos-analyzer

$(BUILD_DIR)/evos-analyzer: src/main.cpp $(ANALYZER_SOURCES) include/evos/analyzer.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) src/main.cpp $(ANALYZER_SOURCES) -o $@

$(BUILD_DIR)/analyzer-test: tests/analyzer_test.cpp $(ANALYZER_SOURCES) include/evos/analyzer.hpp
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) tests/analyzer_test.cpp $(ANALYZER_SOURCES) -o $@

test: $(BUILD_DIR)/analyzer-test
	./$(BUILD_DIR)/analyzer-test

clean:
	rm -rf $(BUILD_DIR)