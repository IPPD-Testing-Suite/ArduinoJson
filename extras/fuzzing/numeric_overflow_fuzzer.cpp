// ArduinoJson fuzzer harness — Bug 1: Stack Buffer Overflow in parseNumericValue
//
// Seeded vulnerability: buffer_[64] was shrunk to buffer_[16] in
// JsonDeserializer.hpp while the loop guard remains n < 63.
// Any numeric token longer than 16 characters overflows the stack buffer.
//
// Trigger: any input with 17+ consecutive bytes that pass canBeInNumber()
// (digits, '.', 'e', 'E', '+', '-').
//
// Sanitizer detection: ASan stack-buffer-overflow

#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  // Only keep bytes that canBeInNumber() accepts so the parser stays inside
  // parseNumericValue rather than branching to a string/object/array path.
  static const char valid[] = "0123456789+-eE.";
  std::string numeric;
  numeric.reserve(size);
  for (size_t i = 0; i < size; i++) {
    char c = static_cast<char>(data[i]);
    for (const char* v = valid; *v; v++) {
      if (c == *v) {
        numeric += c;
        break;
      }
    }
  }

  if (numeric.empty())
    return 0;

  JsonDocument doc;
  deserializeJson(doc, numeric.c_str(), numeric.size());
  return 0;
}
