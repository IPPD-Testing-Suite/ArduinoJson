# CAUTION: this file is invoked by https://github.com/google/oss-fuzz

CXXFLAGS += -I../../src -DARDUINOJSON_DEBUG=1 -std=c++11

all: \
	$(OUT)/json_fuzzer \
	$(OUT)/json_fuzzer_seed_corpus.zip \
	$(OUT)/json_fuzzer.options \
	$(OUT)/msgpack_fuzzer \
	$(OUT)/msgpack_fuzzer_seed_corpus.zip \
	$(OUT)/msgpack_fuzzer.options \
	$(OUT)/numeric_overflow_fuzzer \
	$(OUT)/numeric_overflow_fuzzer_seed_corpus.zip \
	$(OUT)/numeric_overflow_fuzzer.options \
	$(OUT)/unicode_escape_fuzzer \
	$(OUT)/unicode_escape_fuzzer_seed_corpus.zip \
	$(OUT)/unicode_escape_fuzzer.options \
	$(OUT)/float_exponent_fuzzer \
	$(OUT)/float_exponent_fuzzer_seed_corpus.zip \
	$(OUT)/float_exponent_fuzzer.options \
	$(OUT)/deep_nesting_fuzzer \
	$(OUT)/deep_nesting_fuzzer_seed_corpus.zip \
	$(OUT)/deep_nesting_fuzzer.options \
	$(OUT)/string_save_fuzzer \
	$(OUT)/string_save_fuzzer_seed_corpus.zip \
	$(OUT)/string_save_fuzzer.options

$(OUT)/%_fuzzer: %_fuzzer.cpp $(shell find ../../src -type f)
	$(CXX) $(CXXFLAGS) $< -o$@ $(LIB_FUZZING_ENGINE)

$(OUT)/%_fuzzer_seed_corpus.zip: %_seed_corpus/*
	zip -j $@ $?

$(OUT)/%_fuzzer.options:
	@echo "[libfuzzer]" > $@
	@echo "max_len = 256" >> $@
	@echo "timeout = 10" >> $@
