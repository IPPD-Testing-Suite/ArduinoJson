#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  std::string number = "1e";
  for (size_t i = 0; i < size; i++) {
    char c = static_cast<char>(data[i]);
    if (c >= '0' && c <= '9')
      number += c;
  }

  if (number.size() <= 2)
    return 0;

  JsonDocument doc;
  deserializeJson(doc, number.c_str(), number.size());
  return 0;
}
