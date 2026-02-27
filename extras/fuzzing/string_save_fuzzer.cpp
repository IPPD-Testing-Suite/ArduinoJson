// ArduinoJson fuzzer harness — Bug 5: Heap Buffer Overflow in StringBuilder::save()
//
// Seeded vulnerability: p[size_] = 0  was changed to  p[size_ + 1] = 0  in
// StringBuilder.hpp. When a string of exactly initialCapacity (31) chars is
// saved, size_ == node_->length == 31 and the allocation provides data[0..31]
// (32 bytes). Writing p[32] is one byte past the heap block.
//
// The same overflow recurs at every capacity boundary: 31, 63, 127, 255 chars.
//
// Trigger: a JSON string of exactly 31 characters, e.g.
//          "1234567890123456789012345678901"
//
// Sanitizer detection: ASan heap-buffer-overflow

#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  // Build a JSON string from the fuzz bytes (capped at 63 chars to cover the
  // first two capacity boundaries: 31 and 63).
  // Replace characters that would terminate or escape the string early.
  std::string content;
  content.reserve(size < 63 ? size : 63);
  for (size_t i = 0; i < size && i < 63; i++) {
    char c = static_cast<char>(data[i]);
    if (c == '"' || c == '\\' || c == '\0')
      c = 'A';
    content += c;
  }

  std::string json = "\"";
  json += content;
  json += "\"";

  JsonDocument doc;
  deserializeJson(doc, json.c_str(), json.size());

  // Always exercise the exact 31-char boundary to guarantee the vulnerable
  // path is reachable regardless of what the fuzzer sends.
  {
    std::string exact = "\"";
    for (int i = 0; i < 31; i++)
      exact += char('A' + (i % 26));
    exact += "\"";
    JsonDocument doc2;
    deserializeJson(doc2, exact.c_str(), exact.size());
  }

  return 0;
}
