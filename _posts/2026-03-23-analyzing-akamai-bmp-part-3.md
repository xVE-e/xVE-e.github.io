---
layout: article
title: "Analyzing Akamai BMP 4.1.3 - Part 3: Final Layer"
---

# Analyzing Akamai BMP 4.1.3 - Part 3

[PART 1](/2026/03/23/analyzing-akamai-bmp-part-1.html) | [PART 2](/2026/03/23/analyzing-akamai-bmp-part-2.html) | App showcase: Iberia 14.81.0

In part 2 we reversed the native crypto pipeline — AES-128-CBC, HMAC-SHA256, RSA key exchange, MT19937. We know *how* the data is encrypted. Now going look at java layer.

## 1. The Encoding Pipeline

Sensor float arrays (accelerometer, gyroscope, magnetometer) go through a multi-stage compression pipeline before serialization:

```
float[] raw_events
    │
    ▼
truncate to prev_power_of_2(count)
    │
    ▼
┌──────────────────────────────────────────┐
│   Try BOTH paths, pick shorter           │
│           (threshold: 20 chars)          │
├───────────────────┬──────────────────────┤
│ Path A (prefix 2) │ Path B (prefix 1)    │
│ Direct quantize   │ DCT-II + shrink(0.6) │
│                   │ extract DC coef      │
│ find min/max      │ find min/max of rest │
│ quantize(60,'A')  │ quantize(60,'A')     │
│ RLE encode        │ RLE encode           │
│ CRC32(rle)        │ CRC32(rle)           │
├───────────────────┼──────────────────────┤
│ 2;min;max;crc;rle │ 1;min;max;dc;crc;rle │
└───────────────────┴──────────────────────┘
```

Relevant classes:

| Class | Alias | Role |
|-------|-------|------|
| `C0020KE` | EG.KE | Encoding orchestrator |
| `C0015Gx` | EG.Gx | Quantize / shrinkCoef |
| `C0040R` | EG.R | RLE encode/decode |
| `C0033Ks` | EG.Ks | DCT-II transform |
| `C0049VO` | EG.VO | Custom CRC32 |

## 1.1 CRC32

It uses a hardcoded 256-entry lookup table with a custom polynomial.
The CRC is computed on the **RLE-encoded string**

```python
CRC32_TABLE = [
    3523407757, 2768625435, 1007455905, 1259060791,
    3580832660, 2724731650, 996231864,  1281784366,
    # ... 256 entries total
]

def akamai_crc32(s):
    crc = 0
    for ch in s:
        idx = (crc & 0xFF) ^ ord(ch)
        crc = ((crc >> 8) ^ CRC32_TABLE[idx]) & 0xFFFFFFFF
    return crc
```

The initial value is 0, you can't use any ots-CRC library — you need the exact table.

## 1.2 RLE Encoding

Simple one, standard run-length encoding on the quantized character string:

```python
def rle_encode(s):
    # "AAABBC" → "3A2BC"
    # count=1 → no prefix
```


## 1.3 Quantization

Maps float values to 60 bins across ASCII range 65–125 (`A` through `}`):

$$\text{bin} = \left\lfloor \frac{v - v_{\min}}{(v_{\max} - v_{\min})\,/\,60} \right\rfloor + 65$$

Characters `.` (46) and `\` (92) are swapped via a function called `vYfAM()` to avoid serialization conflicts. Since `\` falls within the range [65, 125] but `.` doesn't, in practice only `\` gets swapped to `.`.

Effective charset: ```A B C D E F G H I J K L M N O P Q R S T U V W X Y Z [ . ] ^ _ ` a b c d e f g h i j k l m n o p q r s t u v w x y z { | }```

## 1.4 DCT-II Transform

`C0033Ks.dqjarL()` implements a standard Type-II Discrete Cosine Transform using the split-radix recursive algorithm. Requires power-of-2 input length.

The code is buried under hundreds of lines of anti-tamper dead code — blocks that check variables like `JBm` and `jfT` against constants, branching into unreachable infinite loops. Strip all of that and the actual DCT is textbook.

After DCT, `shrinkCoef(coeffs, 0.6)` zeros out any coefficient whose absolute value is below the 60th percentile — lossy compression that reduces the RLE output by 20+ characters.

The encoder (C0020KE) tries **both** raw quantize and DCT, picks the shorter output. If DCT doesn't save at least 20 characters raw wins.

## 1.5 Orientation Data (keys -142, -144)

`C0005GA` (EG.GA) collects accelerometer, gyroscope, and magnetometer events.

Processing:
1. Truncate events to `prev_power_of_2(count)`
2. Compute orientation via `SensorManager.getRotationMatrix()` + `getOrientation()`
3. Convert radians to degrees, negate azimuth and pitch
4. Encode 4 arrays: azimuth, pitch, roll, timing deltas

**Key -142** (data): `{azimuth_enc}:{pitch_enc}:{roll_enc}` — 3 axes joined by `:`

**Key -144** (summary): timing delta encoding (same pipeline, `shrink=0.0`)


## 1.6 Motion Data (keys -143, -145)

`C0009GN` (EG.GN / McP.IIT) — same pipeline but 9 axes: gravity XYZ, accelerometer XYZ, gyroscope XYZ.

## 2. The Feistel Cipher

`C0004F` implements a 16-round Feistel network. for **checksumming** in key `-115`.

Round function:

$$f(v, k, r) = v \oplus \mathrm{ROL}_{32}(k, r)$$

```python
def feistel_encode(value_64, key_32):
    lo, hi = value_64 & 0xFFFFFFFF, (value_64 >> 32) & 0xFFFFFFFF
    for r in range(16):
        hi, lo = lo, (hi ^ f(lo, key_32, r)) & 0xFFFFFFFF
    return (hi << 32) | lo
```

Used by `CYFManager.GQRJZH()`:

```python
def gqrjzh(touch_duration, event_count, elapsed_time):
    packed = (touch_duration << 32) | event_count
    return feistel_encode(packed, elapsed_time)
```

The class name is literally `"FeistelCipher"` (decoded from the obfuscated string) ```"pzD~s\\FJSoM\`L"``` via yet another XOR table — this one using constant `+111` instead of kpR's `+88`

## 2.1 stringToInt — ASCII Checksum

`C0034Kw.stringToInt()` — used in key `-100`:

```python
def string_to_int(s):
    return sum(ord(c) for c in s if ord(c) < 128)
```

That's Sum of ASCII values. Appended to the device fingerprint as integrity check:

$$\text{key}_{-100} = \text{fingerprint} \;\Vert\; \text{","} \;\Vert\; \text{stringToInt(fp)} \;\Vert\; \text{","} \;\Vert\; \text{Random.nextInt()} \;\Vert\; \text{","} \;\Vert\; \lfloor\text{initTS} / 2\rfloor$$

## 2.2 Touch Events (key -117)

`C0022KG` (EG.KG). Format per event — **8 fields**

```
{type},{delta_ms},{x},{y},{pointer_count},1,{tool_type},-1;
```

The `1` (source) and `-1` (edge_flags) are hardcoded baked into kpR-decoded separator strings:

- `kpR("3&*")` → `",1,"`
- `kpR("3:7\u001f")` → `",-1;"`

Event types:

| Android action | type |
|---|---|
| `ACTION_DOWN` (0), `ACTION_POINTER_DOWN` (5) | **2** |
| `ACTION_UP` (1), `ACTION_POINTER_UP` (6) | **3** |
| `ACTION_MOVE` (2) | **1** |

Delta is relative to the previous event's `MotionEvent.getEventTime()`. Coordinates rounded to integer via `DecimalFormat("#")`.

Max: 50 MOVE + 50 UP/DOWN events.

## 2.3 Lifecycle Events (key -103)

```
{event_type},{timestamp_ms};
```

Resume = `3`, Pause = `2`. Timestamp is `System.currentTimeMillis()` — absolute wall clock, not uptime. Max 10 events.

## 2.4 Text Input (key -108)

```
{event_type},{delta_ms},{view_id_checksum}[,{key_type}];
```

`key_type` omitted when `-1` (focus events). Values: `0`=lowercase, `3`=space, `4`=delete, `5`=uppercase, `1`=paste. Password fields force `key_type=0`.

## 2.5 Device Fingerprint (key -100)

`C0028KT.getInfo()` builds ~39 comma-separated fields. Some are URL-encoded via `C0034Kw.encode()` — a custom percent-encoder that passes printable ASCII (33–126) except `"`, `%`, `'`, `,`, `\`.

The fingerprint includes: screen dimensions, battery, locale, Build properties (MODEL, MANUFACTURER, FINGERPRINT, HARDWARE, TAGS, TYPE, etc.), Android ID, keyboard status, ADB status, and more.

## 2.6 Three String Deobfuscation Variants

All three use the same structure — XOR table with different constants:

| Method | Class | Constant | Used for |
|--------|-------|----------|----------|
| `kpR` | `C0018K` | `+88` | Most Java strings |
| `kfF` | `C0004F` | `+111` | Feistel internals |
| `GVJ` | `C0040R` | `+120` | DCT/quantize internals |

```python
def build_table(constant, size=32767):
    table, prev = [0] * size, 3
    for i in range(size):
        val = prev ^ i
        prev = (prev + val + constant) % 63
        table[i] = prev
    return table
```

## 3. Server-side things

>Well, things are a bit out of my league here. I don't work with JavaScript or web logic; I only work in the mobile field. Also, I don't know if these fields are trivial and if the server accepts a sensor without them. You should test this and check it yourself. In Iberia, two of these fields come from the request responses, and the other of them is from the output of an Akamai JavaScript that runs on a webview.

  **ServerSignal** = serversidesignal from `GET /_bm/get_params`

  **CPRToken** = token from `GET /_bm/get_info` + ~ + result from js challenge

   **CPRSignal** = locally generated: ```System.currentTimeMillis() + "|" + SystemClock.uptimeMillis() + "|"```

For testing i used a Frida script that captures the cprtoken for me; perhaps there are solvers for handle it, I have no idea.

```javascript
'use strict';
var done = false;
Java.perform(function() {
    var Mon = Java.use('com.cyberfend.cyfsecurity.CYFMonitor');
    Mon.getSensorData.implementation = function() {
        var header = this.getSensorData();
        if (!done) {
            done = true;
            var parts = header.split('$');
            var s6 = parts[6] || '';
            var p6 = s6.split('&&&');
            console.log('SERVER_SIGNAL=' + (parts[5] || ''));
            console.log('CPR_SIGNAL=' + (p6[0] || ''));
            console.log('DEVICE_ID=' + (p6[1] || ''));
            console.log('CPR_TOKEN=' + (p6[2] || ''));
        }
        return header;
    };
    console.log('[CPR] Ready — do the login');
});
```

You can capture a CPR token from a real device and then use the generator without problems; it worked for 150 login requests using 5 cprtokens from 5 real devices

## 4. Finally, end

The full sensor data flow:

```
Java collectors → 28 Pair<String,String>
    │
    ▼
native buildN (Part 2)
    │  serialize with "-1,2,-94," separator
    │  append -164,SECURITY_PATCH
    │  append -170,MT_verification
    │  AES-128-CBC + HMAC-SHA256 + base64
    ▼
"6,a,{rsa1},{rsa2}${b64}${timing}"
    │
    ▼
Java buildSensorData
    │  append $[3] PoW
    │  append $[4] CCA token
    │  append $[5] server signal
    │  append $[6] cpr_signal&&&device_id&&&cpr_token&&&4.1.3
    ▼
X-acf-sensor-data header
```

## 4.1 PoW

A simple generator that produces valid sensor data, golang writed, fully cryptographically valid

[bmp413](https://github.com/xVE-e/akamaibmpstrings/blob/main/bmp413/bmp413.go)



---


>Notes: I barely had time to test this, i did some tests, but not many, unfortunately I'm very busy working on paid projects, and at the same time I didn't want to leave you waiting a month for part 3. There might be something to improve if you're looking for a perfect solver. This is just an educational article, it serves as a guide. This doesn't mean that bmp413.go doesn't work, it just means that it's definitely not something I recommend putting into large scale. Thank you to the more than 300 readers, I love you all.

Telegram: @vxigl
Discord: @xve_e
