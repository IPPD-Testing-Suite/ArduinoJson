// ArduinoJson fuzzer harness — Bug 3: Signed Integer Overflow in Exponent Parsing
//
// Seeded vulnerability: the exponent overflow guard was removed from
// parseNumber.hpp. The local variable `exponent` (type int) is accumulated
// unchecked; with 10+ decimal digits it exceeds INT_MAX, which is signed
// integer overflow — undefined behavior caught by UBSan.
//
// Trigger: 1e9999999999  (10-digit exponent)
//
// Sanitizer detection: UBSan signed-integer-overflow

#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  // Build "1e" followed by digit-only bytes from the fuzz input.
  // The exponent accumulation loop runs once per digit; 10 digits overflow int.
  std::string number = "1e";
  for (size_t i = 0; i < size; i++) {
    char c = static_cast<char>(data[i]);
    if (c >= '0' && c <= '9')
      number += c;
  }

  // Need at least one exponent digit for the loop to execute.
  if (number.size() <= 2)
    return 0;

  JsonDocument doc;
  deserializeJson(doc, number.c_str(), number.size());
  return 0;
}
