// ArduinoJson fuzzer harness — Bug 4: Stack Overflow via Unbounded Recursion in parseArray
//
// Seeded vulnerability: the nestingLimit.reached() check was removed from
// parseArray() in JsonDeserializer.hpp. parseObject() retains its guard,
// so only pure array nesting ([[[...]]]) recurses without bound.
//
// Each level of nesting adds a parseVariant + parseArray stack frame.
// At ~200+ levels the C call stack is exhausted.
//
// Trigger: 200 '[' characters followed by '0' followed by 200 ']' characters.
//
// Sanitizer detection: ASan stack-overflow or OS SIGSEGV on stack guard page

#include <ArduinoJson.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0)
    return 0;

  // Count '[' bytes in the fuzz input to derive nesting depth.
  // This lets the fuzzer naturally discover the depth threshold by mutating
  // the number of '[' bytes it sends.
  size_t depth = 0;
  for (size_t i = 0; i < size; i++) {
    if (data[i] == '[')
      depth++;
  }

  // Fall back to raw size as depth when no '[' bytes are present.
  if (depth == 0)
    depth = size;

  // Cap to avoid building extremely large strings (past the stack overflow
  // threshold, more depth just wastes time).
  if (depth > 2000)
    depth = 2000;

  // Construct depth levels of pure array nesting with a scalar inner value.
  std::string json(depth, '[');
  json += "0";
  json += std::string(depth, ']');

  JsonDocument doc;
  deserializeJson(doc, json.c_str(), json.size());
  return 0;
}
