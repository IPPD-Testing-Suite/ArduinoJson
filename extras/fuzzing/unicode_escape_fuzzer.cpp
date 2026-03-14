#include <ArduinoJson.h>
#include <string>

static char nibbleToHex(uint8_t n) {
  return n < 10 ? char('0' + n) : char('A' + n - 10);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::string json = "\"";
  for (size_t i = 0; i + 1 < size; i += 2) {
    uint16_t codeunit =
        (uint16_t(data[i]) << 8) | uint16_t(data[i + 1]);
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
