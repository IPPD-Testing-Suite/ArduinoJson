// ArduinoJson fuzzer harness — Bug 2: Stack OOB Write in Utf8::encodeCodepoint
//
// Seeded vulnerability: buf[5] was shrunk to buf[4] in Utf8.hpp.
// 4-byte UTF-8 sequences (codepoints >= U+10000) write a 5th byte to buf[4],
// which is now out of bounds.
//
// These codepoints come from UTF-16 surrogate pairs: a high surrogate
// (0xD800–0xDBFF) followed by a low surrogate (0xDC00–0xDFFF) in \uXXXX
// escape sequences inside a JSON string.
//
// Trigger: "\uD83D\uDE00"  (U+1F600, requires surrogate pair)
//
// Sanitizer detection: ASan stack-buffer-overflow

#include <ArduinoJson.h>
#include <string>

static char nibbleToHex(uint8_t n) {
  return n < 10 ? char('0' + n) : char('A' + n - 10);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Interpret each pair of bytes as a big-endian 16-bit codeunit and
  // encode it as a \uXXXX escape inside a JSON string.
  // When two consecutive codeunits form a valid surrogate pair, the parser
  // calls Utf8::encodeCodepoint with a value >= 0x10000, triggering the bug.
  std::string json = "\"";
  for (size_t i = 0; i + 1 < size; i += 2) {
    uint16_t codeunit =
        static_cast<uint16_t>((uint16_t(data[i]) << 8) | uint16_t(data[i + 1]));
    json += "\\u";
    json += nibbleToHex((codeunit >> 12) & 0xF);
    json += nibbleToHex((codeunit >>  8) & 0xF);
    json += nibbleToHex((codeunit >>  4) & 0xF);
    json += nibbleToHex((codeunit >>  0) & 0xF);
  }
  json += "\"";

  JsonDocument doc;
  deserializeJson(doc, json.c_str(), json.size());
  return 0;
}
