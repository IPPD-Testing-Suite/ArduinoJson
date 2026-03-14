#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
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
