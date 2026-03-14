#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  size_t depth = 0;
  for (size_t i = 0; i < size; i++) {
    if (data[i] == '[')
      depth++;
  }

  if (depth == 0)
    depth = size;

  if (depth > 2000)
    depth = 2000;

  std::string json(depth, '[');
  json += "0";
  json += std::string(depth, ']');

  JsonDocument doc;
  deserializeJson(doc, json.c_str(), json.size());
  return 0;
}
