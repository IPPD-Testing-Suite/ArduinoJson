#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

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
