# ArduinoJson Seeded Vulnerability Report

**Library:** ArduinoJson 7.x
**Branch:** 7.x
**Purpose:** Fuzzer evaluation — intentionally introduced vulnerabilities for sanitizer-guided fuzzing research.
**Date:** 2026-02-27

> **Note:** These bugs are NOT present in the upstream ArduinoJson codebase. They were introduced deliberately to evaluate custom fuzzer effectiveness.

---

## Summary Table

| # | CWE | Type | File (modified line) | Sanitizer | Trigger Input |
|---|-----|------|----------------------|-----------|---------------|
| 1 | CWE-121 | Stack buffer overflow | `JsonDeserializer.hpp:694` | ASan `stack-buffer-overflow` | `12345678901234567` |
| 2 | CWE-787 | Stack OOB write | `Utf8.hpp:20` | ASan `stack-buffer-overflow` | `"\uD83D\uDE00"` |
| 3 | CWE-190 | Signed integer overflow | `parseNumber.hpp:201-206` | UBSan `signed-integer-overflow` | `1e9999999999` |
| 4 | CWE-674 | Stack overflow (recursion) | `JsonDeserializer.hpp:155-156` | ASan stack-overflow | 200× `[` + `0` + 200× `]` |
| 5 | CWE-122 | Heap buffer overflow | `StringBuilder.hpp:39` | ASan `heap-buffer-overflow` | `"1234567890123456789012345678901"` |

---

## Bug 1 — Stack Buffer Overflow in `parseNumericValue`

**File:** `src/ArduinoJson/Json/JsonDeserializer.hpp`, line 694
**Harness:** `extras/fuzzing/numeric_overflow_fuzzer.cpp`
**Sanitizer:** ASan `stack-buffer-overflow`

### Change

```diff
- char buffer_[64];  // using a member instead of a local variable ...
+ char buffer_[16];  // using a member instead of a local variable ...
```

### Description

`JsonDeserializer` uses `buffer_` to accumulate characters of the current numeric token before passing the null-terminated string to `parseNumber()`. The accumulation loop at line 516 is:

```cpp
while (canBeInNumber(c) && n < 63) {
  move();
  buffer_[n++] = c;
  c = current();
}
buffer_[n] = 0;
```

The loop guard `n < 63` is **unchanged**. With `buffer_[16]`, the 17th character writes to `buffer_[16]` — one past the end of the 16-element stack array. ASan catches this immediately.

`canBeInNumber()` accepts: digits (`0–9`), `+`, `-`, `.`, `e`, `E` (and `A–Z`, `a–z` when NaN/Infinity support is compiled in).

### Trigger Input

```
12345678901234567
```
(17 digit characters — no JSON wrapper needed)

### Reproduction

```bash
echo -n '12345678901234567' | ./numeric_overflow_fuzzer
```

---

## Bug 2 — Stack OOB Write in `Utf8::encodeCodepoint`

**File:** `src/ArduinoJson/Json/Utf8.hpp`, line 20
**Harness:** `extras/fuzzing/unicode_escape_fuzzer.cpp`
**Sanitizer:** ASan `stack-buffer-overflow`

### Change

```diff
- char buf[5];
+ char buf[4];
```

### Description

`encodeCodepoint` converts a Unicode codepoint to its UTF-8 byte sequence, writing the bytes in **reverse** into a local stack buffer before flushing them to the string builder. The maximum number of bytes written into `buf` is 5:

| Position | Content |
|----------|---------|
| `buf[0]` | Null sentinel (loop terminator) |
| `buf[1]` | Last continuation byte |
| `buf[2]` | Second continuation byte (3- and 4-byte sequences) |
| `buf[3]` | First continuation byte (4-byte sequences only) |
| `buf[4]` | Lead byte (4-byte sequences only) ← **now OOB** |

A 4-byte UTF-8 sequence is required for codepoints ≥ U+10000. These are produced by JSON surrogate pairs: a high surrogate (`\uD800`–`\uDBFF`) followed by a low surrogate (`\uDC00`–`\uDFFF`). For example, `\uD83D\uDE00` encodes U+1F600 (😀), codepoint value `0x1F600`.

With `buf[4]`, valid indices are `0`–`3`. The lead byte write to `buf[4]` is a 1-byte stack overflow.

### Trigger Input

```json
"\uD83D\uDE00"
```

### Reproduction

```bash
printf '"\uD83D\uDE00"' | ./unicode_escape_fuzzer
# Or via the harness directly using raw bytes:
printf '\xD8\x3D\xDE\x00' | ./unicode_escape_fuzzer
```

---

## Bug 3 — Signed Integer Overflow in Exponent Parsing

**File:** `src/ArduinoJson/Numbers/parseNumber.hpp`, lines 201–206 (deleted)
**Harness:** `extras/fuzzing/float_exponent_fuzzer.cpp`
**Sanitizer:** UBSan `signed-integer-overflow`

### Change

```diff
  while (isdigit(*s)) {
    exponent = exponent * 10 + (*s - '0');
-   if (exponent + exponent_offset > traits::exponent_max) {
-     if (negative_exponent)
-       return Number(is_negative ? -0.0f : 0.0f);
-     else
-       return Number(is_negative ? -traits::inf() : traits::inf());
-   }
    s++;
  }
```

### Description

`exponent` is declared as `int` (line 188). Without the early-exit guard, parsing an exponent with 10 or more digits causes signed integer overflow:

- After 9 digits of `9`: `exponent = 999999999`
- Digit 10: `999999999 * 10 = 9999999990`, which exceeds `INT_MAX` (2,147,483,647)

Signed integer overflow is **undefined behavior** in C++. UBSan instruments every signed arithmetic operation with a runtime check and aborts on overflow. Optimizers may also miscompile the loop assuming it cannot overflow, causing unpredictable behavior without UBSan.

### Trigger Input

```
1e9999999999
```
(10-digit exponent — overflows on the 10th digit's multiplication)

### Reproduction

```bash
echo -n '1e9999999999' | ./float_exponent_fuzzer
```

---

## Bug 4 — Unbounded Recursion via Missing Nesting Check in `parseArray`

**File:** `src/ArduinoJson/Json/JsonDeserializer.hpp`, lines 155–156 (deleted from `parseArray`)
**Harness:** `extras/fuzzing/deep_nesting_fuzzer.cpp`
**Sanitizer:** ASan stack-overflow / OS SIGSEGV on stack guard page

### Change

```diff
  template <typename TFilter>
  DeserializationError::Code parseArray(
      VariantData* array, TFilter filter,
      DeserializationOption::NestingLimit nestingLimit) {
    DeserializationError::Code err;

    array->toArray();

-   if (nestingLimit.reached())
-     return DeserializationError::TooDeep;

    // Skip opening bracket
    ARDUINOJSON_ASSERT(current() == '[');
```

### Description

The recursive descent parser calls `parseArray` → `parseVariant` → `parseArray` for each level of nested arrays. Without the depth guard in `parseArray`, pure array nesting recurses without bound. `parseObject` retains its guard, so only `[[[...]]]`-style inputs are affected.

At approximately 200+ levels of nesting, the C call stack is exhausted. Each recursive frame adds `parseVariant` + `parseArray` stack usage. The default system stack (typically 8 MB on Linux) is overflowed before any other defense fires.

Note: in debug builds, `NestingLimit::decrement()` will `ARDUINOJSON_ASSERT(value_ > 0)` when the limit underflows. In fuzzer builds (compiled with `-DNDEBUG`), this assert is a no-op and the uint8_t limit wraps around to 255, continuing indefinitely.

### Trigger Input

200 `[` characters + `0` + 200 `]` characters:
```
[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
```

### Reproduction

```bash
python3 -c "print('[' * 200 + '0' + ']' * 200, end='')" | ./deep_nesting_fuzzer
# Or increase stack limit if needed:
ulimit -s unlimited
python3 -c "print('[' * 200 + '0' + ']' * 200, end='')" | ./deep_nesting_fuzzer
```

---

## Bug 5 — Heap Buffer Overflow in `StringBuilder::save()`

**File:** `src/ArduinoJson/Memory/StringBuilder.hpp`, line 39
**Harness:** `extras/fuzzing/string_save_fuzzer.cpp`
**Sanitizer:** ASan `heap-buffer-overflow`

### Change

```diff
- p[size_] = 0;
+ p[size_ + 1] = 0;
```

### Description

`StringBuilder` allocates a `StringNode` via `createString(initialCapacity)` where `initialCapacity = 31`. `StringNode::sizeForLength(n)` provides exactly `n + 1` bytes of usable string data: `data[0]` through `data[n]` (inclusive). The `data[n]` slot is reserved for the null terminator.

The original `save()` correctly null-terminates at `p[size_]`. The modified version writes to `p[size_ + 1]` instead.

**When the overflow triggers:** a string of exactly 31 characters is parsed.

| State after 31 `append()` calls | Value |
|----------------------------------|-------|
| `size_` | 31 |
| `node_->length` | 31 (no resize occurred — resize triggers on the 32nd char) |
| Valid `data[]` indices | 0–31 (32 bytes: `sizeForLength(31) = 31 + 1 + offsetof`) |
| `p[size_]` = `p[31]` | Valid (null terminator slot) |
| `p[size_ + 1]` = `p[32]` | **One past end of heap allocation** |

The same overflow recurs at every capacity boundary: strings of exactly 31, 63, 127, 255, ... characters all hit this path.

### Trigger Input

```json
"1234567890123456789012345678901"
```
(JSON string of exactly 31 characters)

### Reproduction

```bash
printf '"1234567890123456789012345678901"' | ./string_save_fuzzer
```

---

## Build Instructions

All harnesses use the libFuzzer interface and must be compiled with Clang:

```bash
cd /path/to/ArduinoJson

# Compile a specific harness (replace NAME with the target):
clang++ -std=c++11 \
  -I src \
  -fsanitize=address,undefined \
  -fno-sanitize-recover=all \
  -fsanitize=fuzzer \
  -g -O1 \
  extras/fuzzing/NAME_fuzzer.cpp \
  -o NAME_fuzzer

# Run with the existing seed corpus:
./NAME_fuzzer extras/fuzzing/json_seed_corpus/ -max_total_time=60

# Or reproduce directly with a known trigger:
echo -n 'TRIGGER_INPUT' | ./NAME_fuzzer
```

Available harnesses:

| Harness | Targets |
|---------|---------|
| `numeric_overflow_fuzzer` | Bug 1 |
| `unicode_escape_fuzzer` | Bug 2 |
| `float_exponent_fuzzer` | Bug 3 |
| `deep_nesting_fuzzer` | Bug 4 |
| `string_save_fuzzer` | Bug 5 |

For Bug 3 (UBSan), ensure `-fsanitize=undefined` is included. For Bug 4 (stack overflow), you may need `ulimit -s unlimited` or `-Wl,-z,stacksize=...`.

---

## Expected Sanitizer Output

### Bug 1 — ASan
```
==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at ... in JsonDeserializer::parseNumericValue
...
'buffer_' ... is located in the stack of frame #N for function 'parse'
```

### Bug 2 — ASan
```
==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1 at ... in Utf8::encodeCodepoint
...
'buf' ... is located in the stack of frame #N
```

### Bug 3 — UBSan
```
parseNumber.hpp:200:18: runtime error: signed integer overflow:
999999999 * 10 cannot be represented in type 'int'
```

### Bug 4 — ASan
```
==ERROR: AddressSanitizer: stack-overflow on address ...
    #0 JsonDeserializer::parseArray(...)
    #1 JsonDeserializer::parseVariant(...)
    #2 JsonDeserializer::parseArray(...)
    ...
```

### Bug 5 — ASan
```
==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1 at ... in StringBuilder::save
...
allocated ... of size N here
```

---

---

## Build System Integration

The five harnesses are integrated into the existing fuzzing build system identically to the original `json_fuzzer` and `msgpack_fuzzer`.

### Directory structure added

| Directory | Purpose |
|-----------|---------|
| `numeric_overflow_corpus/` | Fuzzer-generated corpus (git-ignored) |
| `numeric_overflow_seed_corpus/` | Seed: 17-digit number (trigger for Bug 1) |
| `unicode_escape_corpus/` | Fuzzer-generated corpus (git-ignored) |
| `unicode_escape_seed_corpus/` | Seed: raw bytes `D8 3D DE 00` (surrogate pair trigger for Bug 2) |
| `float_exponent_corpus/` | Fuzzer-generated corpus (git-ignored) |
| `float_exponent_seed_corpus/` | Seed: 10-digit exponent digits (trigger for Bug 3) |
| `deep_nesting_corpus/` | Fuzzer-generated corpus (git-ignored) |
| `deep_nesting_seed_corpus/` | Seed: 200 `[` bytes (trigger depth for Bug 4) |
| `string_save_corpus/` | Fuzzer-generated corpus (git-ignored) |
| `string_save_seed_corpus/` | Seed: 31 printable chars (trigger for Bug 5) |

### Makefile (OSS-Fuzz)

All five harnesses are listed in the `all` target. The existing pattern rules handle compilation, seed corpus zipping, and `.options` file generation automatically:

```makefile
$(OUT)/numeric_overflow_fuzzer
$(OUT)/numeric_overflow_fuzzer_seed_corpus.zip
$(OUT)/numeric_overflow_fuzzer.options
# ... (same pattern for each harness)
```

### CMakeLists.txt (local / CI via CTest)

Five `add_fuzzer()` calls were added inside the existing Clang ≥ 6 guard:

```cmake
add_fuzzer(numeric_overflow)
add_fuzzer(unicode_escape)
add_fuzzer(float_exponent)
add_fuzzer(deep_nesting)
add_fuzzer(string_save)
```

Each produces a CTest test that compiles the harness with `-fsanitize=fuzzer`, runs it against its corpus and seed corpus for 5 seconds (`-max_total_time=5`), and tags it with the `Fuzzing` label — the same configuration used by `json_fuzzer` and `msgpack_fuzzer`.

---

## Changelog

### 2026-03-04 — Removed original fuzzers; replaced biased seeds with unbiased seeds

#### Removed fuzzers

`json_fuzzer.cpp` and `msgpack_fuzzer.cpp` (the upstream OSS-Fuzz harnesses) were deleted from the repository. All references were removed from the build system:

- **`CMakeLists.txt`:** Removed the `json_reproducer` and `msgpack_reproducer` executable targets and the `add_fuzzer(json)` / `add_fuzzer(msgpack)` calls.
- **`Makefile`:** Removed `$(OUT)/json_fuzzer`, `$(OUT)/json_fuzzer_seed_corpus.zip`, `$(OUT)/json_fuzzer.options`, and the three equivalent `msgpack_fuzzer` entries from the `all` target.

The five bug-specific harnesses and their build entries are unchanged.

#### Seed corpus replacement

All five seed corpora previously contained the exact bug-trigger input (biased seeds). These were replaced with minimal, structurally valid inputs so that an external mutation engine starts from a neutral position and must discover the vulnerable input through guided mutation.

| Harness | Old seed (biased) | New seed (unbiased) | Seed bytes |
|---------|-------------------|---------------------|------------|
| `numeric_overflow` | `12345678901234567` (17-digit trigger) | `0` | `30` |
| `float_exponent` | `9999999999` (10-digit exponent trigger) | `5` (→ `1e5`) | `35` |
| `deep_nesting` | 200 × `[` (trigger depth) | `[` (depth 1 → `[0]`) | `5B` |
| `string_save` | 31-char string `ABCDE…` (exact boundary trigger) | `hi` (2-char string) | `68 69` |
| `unicode_escape` | Raw surrogate-pair bytes `D8 3D DE 00` | `\x00\x41` (→ `\u0041` = 'A', BMP only) | `00 41` |

The harness input format is preserved in each case — the new seeds are legal inputs to the same parsing paths, just far from the boundary that triggers the bug.

---

*This report documents intentional research vulnerabilities. The upstream ArduinoJson library does not contain these bugs.*
