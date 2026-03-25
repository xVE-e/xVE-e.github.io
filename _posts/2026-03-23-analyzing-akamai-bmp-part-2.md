---
layout: article
title: "Analyzing Akamai BMP 4.1.3 - Part 2: Native Library Deep Dive"
---

# Analyzing Akamai BMP 4.1.3 - Part 2

[PART 1](/2026/03/23/analyzing-akamai-bmp-part-1.html) | App showcase: Iberia 14.81.0 | IDA Pro: 9.3

## 1. Analyzing the post-decompress lib

The decompiler often misidentified the number of arguments and return values for the polymorphic dispatcher, i used a secret technique to get around this using asm.

As we saw earlier, sub_25E0AC is a large polymorphic dispatcher.

```plaintext
sub_25E0AC(string_ptr)                    → strlen or string copy
sub_25E0AC(string_ptr, 0x8641, 0xFFFFFFFF) → string deobfuscation
sub_25E0AC(plaintext, output, len, key, iv) → AES-128-CBC encrypt
sub_25E0AC(qword_2466A8)                  → MT19937 extract
```

![graphsub_25E0AC](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ltslpy9ahjbh28sen0fx.png)

**JNI Entry Points**

| VA        | Java Name                         | Purpose                                                  |
|-----------|-----------------------------------|----------------------------------------------------------|
| 0x9D394   | SensorDataBuilder.buildN          | Main entry: serialize + encrypt sensor data              |
| 0x9D074   | SensorDataBuilder.encryptKeyN     | Generate session ID (20-char base62 → base64)            |
| 0xA0144   | addOne                            | Set MT flag dword_247A38                                 |
| 0xA0150   | sampleTest                        | Set MT flag dword_247A3C                                 |
| 0xA015C   | presentData                       | Set MT flag dword_247A40                                 |
| 0xA0168   | testOne                           | Set MT flag dword_247A44                                 |

**Internal Functions (Called by buildN)**

| VA        | Size  | Name         | Purpose                                                                 |
|-----------|-------|--------------|----------------------------------------------------------------------|
| `0x9ED74` | 0xAFC | `sub_9ED74`  | Core encrypt+format: MT → AES → HMAC → b64 → header assembly         |
| `0x9EAF0` | 0x34  | `sub_9EAF0`  | Crypto context singleton getter                                      |
| `0x9EB24` | 0x250 | `sub_9EB24`  | One-time key initialization                                          |
| `0x9E840` | 0x1D0 | `sub_9E840`  | LCG-based string deobfuscation                                       |
| `0x9E660` | 0xF8  | `sub_9E660`  | RSA_public_encrypt wrapper                                           |
| `0x9E594` | 0x90  | `sub_9E594`  | HMAC-SHA256 wrapper                                                  |
| `0x9E620` | 0x24  | `sub_9E620`  | RAND_bytes wrapper                                                   |
| `0x9E75C` | 0xE0  | `sub_9E75C`  | Base64 encode (OpenSSL BIO)                                          |
| `0x9FAD0` | 0x130 | `sub_9FAD0`  | MT19937 bounded random                                               |
| `0x9F91C` | 0xFC  | `sub_9F91C`  | C++ stringstream initialization                                      |
| `0x9FDF8` | 0xD0  | `sub_9FDF8`  | Stringstream write (string)                                          |
| `0x1CFD2C`| 0x158 | `sub_1CFD2C` | Stringstream write (integer)                                         |
| `0x9DBD0` | 0x98  | `sub_9DBD0`  | JNI CallIntMethodV wrapper                                           |

### 1.1. Serialization Pipeline

**Function: `Java_com_cyberfend_cyfsecurity_SensorDataBuilder_buildN` @ 0x9D394**

| Property | Value |
|----------|-------|
| Size | `0x83C` (2108 bytes) |
| Input | `ArrayList<Pair<String, String>>` — 28 entries from Java |
| Output | Encrypted header string `"6,a,{rsa1},{rsa2}${b64}${timing}"` |

![sub_9D394graph](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/smfk7qjzeb28fsi59s5k.png)

**Step-by-step from Assembly**

**Phase 1**: JNI Environment Setup (0x9D3CC–0x9D54C)

The function begins by resolving all required JNI references prior to data extraction:

```cpp
FindClass("android/os/Build$VERSION")
GetStaticFieldID("SDK_INT", "I")
GetStaticIntField()                         → must be >= 1 (sanity check)
FindClass("java/util/ArrayList")
GetMethodID("size",  "()I")                 → pair_count
GetMethodID("get",   "(I)Ljava/lang/Object;")
FindClass("android/util/Pair")
GetFieldID("first",  "Ljava/lang/Object;")
GetFieldID("second", "Ljava/lang/Object;")
```

**Phase 2**: Pair Vector Extraction (0x9D554–0x9D6A8)

Each element of the input `ArrayList` is extracted via a JNI iteration loop over indices $i \in [0,\ \text{pair\\_count} - 1]$:

```java
pair  = ArrayList.get(i)
key   = GetStringUTFChars(pair.first)
value = GetStringUTFChars(pair.second)
```

Pairs are stored in a C++ vector as 48-byte structs with the layout:

$$\text{struct PairEntry} = \underbrace{\text{key}}_{\text{std::string, 24 B}} \;\|\; \underbrace{\text{value}}_{\text{std::string, 24 B}}$$

The 24-byte `std::string` layout corresponds to the standard libc++ small-string-optimized (SSO) representation on AArch64.

**Phase 3**: Output Initialization from First Pair (0x9D6F8–0x9D724)

The **value field of the first pair** (index 0) is used as the initial content of the serialized output buffer; its key is discarded. In the observed execution context, this value is the SDK version string `"4.1.3"`.

**Phase 4**: Separator String Deobfuscation (0x9D728–0x9D768)

The separator literal is stored obfuscated in `.rodata` and decoded at runtime. The encoded form `"WUfOL#f}+"` is passed to a `.pb` dispatcher alongside the constant `0x8641`, which drives a substitution-based decode:

```arm
9d728  ADRL  X9, aWufolF         ; load encoded string "WUfOL#f}+"
9d738  STRB  W8, [SP, #var_90]   ; SSO length field = 9
9d744  STUR  X9, [SP, #var_90+1] ; copy encoded bytes onto stack
9d748  ADD   X8, SP, #var_78     ; destination buffer = var_78
9d750  MOV   W1, #0x8641         ; deobfuscation constant
9d754  MOV   W2, #0xFFFFFFFF     ; flag
9d758  BL    sub_25E0AC          ; decode → "-1,2,-94," stored in var_78
```

**Phase 5**: Pair Serialization Loop (0x9D76C–0x9D84C)

Pairs at indices $i \in [1,\, \mathsf{pair\\_count} - 1]$ are serialized in order. Each iteration appends to the output buffer with the pattern:

$$\mathtt{output} \mathrel{+}= \mathtt{separator} \;\Vert\; \mathtt{key}_i \;\Vert\; \text{","} \;\Vert\; \mathtt{value}_i$$

The struct stride is 48 bytes (`ADD X22, X22, #0x30`).

```arm
9d7b0  ADD   X0, SP, #var_60    ; output string ptr
9d7b4  BL    sub_25E0AC         ; append(output, separator)
9d7d4  LDRB  W9, [X8]           ; load key SSO flag (offset +0)
9d7f0  BL    sub_1CDC48         ; append(output, key)
9d7f8  MOV   X1, X20            ; X20 = "," literal @ 0x51163
9d7fc  BL    sub_1CE08C         ; append(output, ",")
9d81c  LDRB  W9, [X8, #0x18]    ; load value SSO flag (offset +24)
9d83c  BL    sub_1CDC48         ; append(output, value)
9d840  ADD   X22, X22, #0x30    ; advance to next struct (stride = 48)
9d844  ADD   X24, X24, #1       ; i++
9d84c  B.NE  loop_start
```

**Phase 6**: `SECURITY_PATCH` Field Appended via JNI (0x9D850–0x9D92C)

After exhausting the input vector, the function retrieves `Build.VERSION.SECURITY_PATCH` directly from the Android runtime via JNI reflection, bypassing the Java-side pair list entirely:

```arm
9d888  ADRL  X2, aSecurityPatch    ; field name "SECURITY_PATCH"
9d890  ADRL  X3, aLjavaLangStrin   ; descriptor "Ljava/lang/String;"
9d8a4  BLR   X8                    ; GetStaticFieldID
9d8bc  BLR   X8                    ; GetStaticObjectField
9d8d4  BLR   X8                    ; GetStringUTFChars → X20 = e.g. "2025-04-01"
```

The value is appended with a dedicated tag identifier `-164`:

$$\mathsf{output} \mathrel{+}= \textrm{"-1,2,-94,"} \;\Vert\; \textrm{"-164,"} \;\Vert\; \mathsf{SECURITY\\_PATCH}$$

The native-side injection of `SECURITY_PATCH` — absent from the Java-supplied pair list — constitutes an integrity signal that cannot be trivially spoofed by intercepting the Java layer alone.

**Phase 7**: Encryption and Formatting (0x9D930–0x9D96C)

The assembled plaintext is passed to the shared cryptographic context singleton and encrypted via `sub_9ED74`, which implements the same AES-128-CBC + HMAC-SHA256 pipeline.

```arm
9d930  BL    sub_9EAF0     ; acquire crypto context singleton
9d964  ADD   X8, SP, #var_90   ; output buffer
9d968  ADD   X1, SP, #var_B0   ; plaintext string
9d96c  BL    sub_9ED74     ; encrypt + assemble → "6,a,{rsa1},{rsa2}${b64}${timing}"
```

**Phase 8**: Return to Java (0x9D99C–0x9D9AC)

```arm
9d99c  BLR   X8           ; NewStringUTF(output_cstr)
9d9ac  ; return jstring
```

**Serialization Format**

```plaintext
4.1.3-1,2,-94,-90,{val}-1,2,-94,-91,{val}-1,2,-94,-70,-1,2,-94,-80,...-1,2,-94,-164,{SECURITY_PATCH}
```

- First: SDK version (pair 0 value only)
- Then: `{separator}{key},{value}` for each remaining pair
- Last: `{separator}-164,{SECURITY_PATCH}` (from JNI)

---

## 2. Cryptographic Pipeline — sub_9ED74

**Function: `sub_9ED74` @ 0x9ED74**

| Property | Value |
|----------|-------|
| Size | `0xAFC` (2812 bytes) |
| Calling convention | `__usercall` — X8 = output ptr, X0 = crypto context, X1 = plaintext |
| Input | Crypto context (from `sub_9EAF0`), serialized sensor plaintext |
| Output | `"6,a,{rsa1},{rsa2}${base64(IV+cipher+HMAC)}${timing}"` |

### 2.1 Phase 1: Separator Decode

Employs the same deobfuscation routine as `buildN`: the encoded string `"WUfOL#f}+"` is decoded with constant `0x8641`, yielding the separator `"-1,2,-94,"`.

### 2.2 Phase 2: MT19937 PRNG Initialization

Two atomic guard flags gate one-time initialization of the Mersenne Twister state:

- `byte_2466A0` — controls MT state array initialization
- `byte_247A30` — controls seeding from `clock_gettime(CLOCK_REALTIME)`

The seeding routine implements the standard MT19937 initialization recurrence:

$$\mathtt{state}[i] = i + 1812433253 \cdot \bigl(\mathtt{state}[i-1] \oplus (\mathtt{state}[i-1] \gg 30)\bigr), \quad i \in [1, 623]$$

### 2.3 Phase 3: Verification Value Generation

Five sampling ranges are loaded from `.rodata`:

| Variable  | Range     | Conditional Flag                  | Semantic    |
|-----------|-----------|-----------------------------------|-------------|
| `var_188` | [1, 1000] | — (unconditional)                 | base values |
| `var_190` | [1, 6]    | `dword_247A38` (`addOne`)         | optional    |
| `var_198` | [1, 7]    | `dword_247A3C` (`sampleTest`)     | optional    |
| `var_1A0` | [1, 8]    | `dword_247A40` (`presentData`)    | optional    |
| `var_1A8` | [1, 4]    | `dword_247A44` (`testOne`)        | optional    |

Four verification values are derived through a chained XOR construction:

$$\text{val}_1 = v_{14} + 7 \cdot v_{13}$$

$$\text{val}_2 = \left(v_{16} + 8 \cdot v_{15}\right) \oplus \text{val}_1$$

$$\text{val}_3 = \left(v_{18} + 9 \cdot v_{17}\right) \oplus \text{val}_2$$

$$\text{val}_4 = \left(v_{20} + 5 \cdot v_{19}\right) \oplus \text{val}_3$$

### 2.4 Phase 4: AES-128-CBC Encryption

A fresh 16-byte IV is generated per invocation via `RAND_bytes()`. The output layout is:

$$\mathsf{ciphertext\\_blob} = \mathrm{IV}_{16} \;\Vert\; \mathrm{AES\text{-}128\text{-}CBC}(\mathsf{plaintext},\, k_{\mathrm{AES}},\, \mathrm{IV})$$

### 2.5 Phase 5: HMAC-SHA256 Authentication

The authentication tag is computed over the full `IV || ciphertext` blob:

$$\mathtt{tag} = \mathrm{HMAC\text{-}SHA256}\!\left(k_{\mathrm{HMAC}},\; \mathrm{IV} \,\Vert\, \mathtt{ciphertext}\right)$$

### 2.6 Phase 6: Final Assembly

The authenticated ciphertext is assembled into a contiguous binary blob:

$$\mathtt{output\_bin} = \mathrm{IV}_{16} \;\Vert\; \mathtt{ciphertext}_{n} \;\Vert\; \mathrm{HMAC}_{32}$$

Total length: $n + 48$ bytes. The blob is then Base64-encoded.

**Final header format:**

$$\mathtt{header} = \mathrm{Segment\_A} \;\Vert\; \textrm{"\$"} \;\Vert\; \mathtt{b64} \;\Vert\; \textrm{"\$"} \;\Vert\; \mathrm{Segment\_B}$$

---

## 3. Mersenne Twister Verification

### 3.1 MT19937 Implementation

The native code employs a standard MT19937 PRNG, confirmed by three structural markers: a 624-element state array at `qword_2466A8`, the initialization multiplier `1812433253`, and a twist operation matching the reference implementation.

### 3.2 Bounded Random Sampling

```c
int mt_rand_range(int lo, int hi) {
    int range = hi - lo + 1;
    int result;
    do {
        result = mt_extract() % range;
    } while (result >= range);
    return lo + result;
}
```

### 3.3 Flag Behavior

The four control flags are set by the JNI entry points `addOne`, `sampleTest`, `presentData`, and `testOne`. Their static value in the binary is `0xFFFFFFFF` (not equal to 1), rendering all conditional terms zero by default.

---

## 4. Key Initialization — sub_9EB24

Invoked when `ctx[40] == 0` (uninitialized). Executes once per process lifetime.

### 4.1 Key Buffer Allocation

```arm
9eb5c  BL    sub_25E0AC    ; ctx[0]  = malloc(17)  → AES key buffer  (16 B + null)
9ec54  BL    sub_20AF7C    ; ctx[8]  = malloc(17)  → IV buffer       (16 B + null)
9ec64  BL    sub_25E0AC    ; ctx[16] = malloc(33)  → HMAC key buffer (32 B + null)
```

### 4.2 RSA Public Key Deobfuscation

268 bytes of obfuscated key material are loaded from `off_245030` and decoded via the LCG substitution cipher with seed `63`.

### 4.3 Session Key Generation

```arm
; AES key: 16 random bytes, RSA-encrypted, Base64-encoded → ctx[24]
9ec38  BL    sub_9E660     ; RSA_public_encrypt(pem_key, rand_16)
9ec48  BL    sub_9E75C     ; base64(encrypted) → ctx[24]

; HMAC key: 32 random bytes, RSA-encrypted, Base64-encoded → ctx[32]
9ec9c  BL    sub_9E660     ; RSA_public_encrypt(pem_key, rand_32)
9eca8  BL    sub_9E75C     ; base64(encrypted) → ctx[32]
```

---

## 5. String Deobfuscation

### 5.1 Native: LCG Substitution Cipher

```python
def build_charset():
    return [ch for ch in range(32, 127) if ch not in (34, 39, 92)]

def lcg_decode(data: bytes, seed: int) -> bytes:
    charset = build_charset()
    n   = len(charset)
    lcg = seed
    out = []
    for byte in data:
        idx   = charset.index(byte)
        shift = ((lcg >> 8) & 0xFFFF) % n
        out.append(charset[(idx - shift + n) % n])
        lcg = (lcg * 65793 + 4282663) & 0x7FFFFF
    return bytes(out)
```

### 5.2 Java: XOR Table Cipher

```python
def build_table(size: int = 32768) -> list[int]:
    table, prev = [0] * size, 3
    for i in range(size):
        val    = prev ^ i
        prev   = (prev + val + 88) % 63
        table[i] = prev
    return table

def decode_kpR(encoded: str) -> str:
    table = build_table()
    return ''.join(chr(ord(c) ^ table[i]) for i, c in enumerate(encoded))
```

---

## 6. Java-Side Architecture

### 6.1 CYFManager.buildSensorData()

The primary Java entry point orchestrates the full sensor data pipeline:

1. Evaluate event count thresholds to select fast path or full path
2. Collect data from 12+ sensor subsystems
3. Assemble a `LinkedHashMap<String, String>` with ~25 entries
4. Convert to `ArrayList<Pair<String, String>>`
5. Invoke native `buildN(pairs)` → encrypted header
6. Append `$[3]..$[6]` sections: Proof-of-Work, CCA token, signal, metadata

### 6.2 Fast Path (event count < 16)

When both `GA` and `IIT` accumulators hold fewer than 16 events **and** `EG.D.isValid()` is true, the function returns cached sensor data from `EG.D.get()`.

### 6.3 Sensor Collector Classes

| Class      | Alias         | Data Collected                                              |
|------------|---------------|-------------------------------------------------------------|
| `C0005GA`  | `EG.GA`       | Accelerometer, gyroscope, magnetometer (orientation)        |
| `C0009GN`  | `EG.GN/McP.IIT` | Motion analysis, jerk derivatives (9 axes)               |
| `C0022KG`  | `EG.KG`       | Touch events (DOWN/MOVE/UP with coordinates)                |
| `C0018K`   | `EG.K`        | Text input events (keystroke timing)                        |
| `C0054Z`   | `EG.Z`        | EditText field metadata                                     |
| `C0008GK`  | `EG.GK`       | Activity lifecycle (resume/pause events)                    |
| `C0006GE`  | `EG.GE`       | Device info (40+ fields)                                    |
| `C0051Vw`  | `EG.Vw/KWS`   | System fingerprint, device ID                               |
| `C0001C`   | `EG.C`        | DCI/JavaScript bridge (WebView challenges)                  |
| `C0002D`   | `EG.D`        | CPR signal cache                                            |
| `C0042U`   | `EG.U`        | Proof-of-Work responses                                     |
| `C0038M`   | `EG.M`        | CCA challenge tokens                                        |

---

> **Last-minute update:** I wrote this article in a hurry due to lack of time, I ended up forgetting to provide something tangible and useful for you, here is the SensorData decryptor, make sure you are using **Frida 17.8.2** and the correct version of Iberia.

![blabla](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/2sv1nbhbvsro5d61qi0m.png)

**How to use:**

1. Hook the app:
```console
frida -U -f com.iberia.android -l hook.js
```
2. After the app opens, trigger login or smth
3. Look for these log lines:
```plaintext
[AKM] SESSION_KEY_16: 59bf28fde390277c14dff6247116a39e    ← this is SESSION_KEY
[AKM] HMAC_KEY_32:    a5ed42ba...f5af23fc                  ← this is HMAC_KEY
```
4. Paste the keys in `decrypt_sensor.py`, run, be happy

---
[decrypt_sensor.py](https://github.com/xVE-e/akamaibmpstrings/blob/main/decrypt_sensor.py) | [hook.js](https://github.com/xVE-e/akamaibmpstrings/blob/main/hook.js)

*I'm going to rest here, wait for part 3.*
Telegram: @vxigl
Discord: @xve_e
