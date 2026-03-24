---
layout: article
title: "Analyzing Akamai BMP 4.1.3 - Part 1: For Noobs, Learn"
---

# Analyzing Akamai BMP 4.1.3 - Part 1

App showcase: Iberia 14.81.0 | IDA Pro: 9.3

## 1. Initial analysis

Well, I already had some prior knowledge of how Akamai worked, after loading the library in Ida, which I found very strange initially:

![firsts functions](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ghkjkuofqcenpwyzimhq.png)

The library is over 2MB, and the low number of functions made me realize something was wrong. So I went to check the exports:

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/veyathi4v0w2fdby7vnn.png)

I try disasm addresses of the exported functions:

`initializeKeyN @ 0x9d060`
`encryptKeyN @ 0x9d074`
`decryptN @ 0x9d18c`
`buildN @ 0x9d394 <-- prob generates the sensor data`

The decompilation failed because this isn't even a functional arm64 instruction:

```plaintext
0x9d060: bytes=1094e857b4b328ef  -> NOT a valid ARM64 instruction
0x9d394: bytes=a23908369f7bcc23  -> NOT a valid ARM64 instruction
```

The bytes appeared to be random data, not opcodes. The native code is encrypted on disk.

strings before:

![before](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/o4vs9sxpvrovjoq9lrsv.png)

## 2. Decompression using unicorn

IDA only recognized 8 functions in the entire binary (of ~1.5MB of .text!). Among them:

- `.init_proc` @ 0x2cdc20 — function that runs automatically when the .so file is loaded by Android
- `sub_2CBF50` @ 0x2cbf50 — huge function (0x1CC8 bytes) called by .init_proc

Decompiling .init_proc revealed:

```cpp
void init_proc() {
    sub_2CBF50();  // <-- the unpacker
}
```

### 2.1. Analyzing the unpacker (sub_2CBF50)

This is the centerpiece.

**`.spd` (Section Protection Data) data structure**

The table is located at address VA `0x2CDCC0` with this layout:

```plaintext
0x2CDCC0: checksum/magic (0x15043297f10b7863)
0x2CDCC8: outer_count = 2 (how many encrypted sections)
0x2CDCD0: start of entries
```

Each external entrance has:

```plaintext
qword[0]: section offset (VA) e.g.: 0x000000 (.text+.rodata)
qword[1]: section size e.g.: 0x2116E0
qword[2]: flags (for mprotect) e.g.: 5 (RX)
qword[3]: number of subsections e.g.: 3
```

Each subsection has:

```plaintext
14 qwords = 28 32-bit round keys (cipher keys)
1 checksum/sentinel qword
1 padding qword
```

Then: offset, size, and more keys for the next subsection

The encrypted sections found:

| Section                         | VA        | Size               | Subsections |
|---------------------------------|-----------|--------------------|-------------|
| Segment 1 (code + rodata)       | 0x000000  | 0x2116E0 (~2MB)    | 3           |
| Segment 2 (.pb + extras)        | 0x254000  | 0x079F68 (~490KB)  | 1           |

**The cipher: Speck-like block cipher**

The algorithm is a custom block cipher inspired by the [NSA's Speck](https://en.wikipedia.org/wiki/Speck_%28cipher%29), operating on 64-bit blocks (2×32 bits) with 28 rounds.

Each round does:

```c
xor_val = hi XOR lo
rot3 = ROR32(xor_val, 3) // right rotation 3 bits

sub_val = (round_key XOR hi) - rot3 // subtraction mod 2^32
rot24 = ROR32(sub_val, 24) // = ROL8 (left rotation 8)
hi = rot24 XOR rot3
lo = rot24
```

It operates in CBC ([Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)) mode: each decrypted block is XORed with the previous ciphertext, creating a chain dependency.

The code has two paths:

- **NEON path**: uses ARM64 SIMD instructions to process 2 blocks at a time (128 bits) — performance optimization
- **Scalar path**: processes 1 block of 64 bits at a time — fallback

In addition, for some sections there is an XOR mode (when flags & 1 == 1) that uses the round keys as PRNG to generate a keystream, and applies byte-by-byte XOR (masking with & 0x7F).

**Auxiliary Functions**

```plaintext
sub_2540C0 → trampoline to sub_254314 → mprotect() wrapper to mark memory as RWX before writing
sub_2540E0 → trampoline to loc_25429C → instruction cache flush (required on ARM after modifying code)
sub_254148 → returns the base address (0, since it is PIE)
sub_2CBF38 → returns a pointer to 0x2CDCC0 (.spd table)
sub_2CBF44 → returns a pointer to 0x2CDCC8 (entry count)
```

### 2.3. Script to get the decompressed libakamaibmp.so

I used [Unicorn Engine](https://github.com/unicorn-engine/unicorn)

Unicorn script [dec.py](https://github.com/xVE-e/akamaibmpstrings/blob/main/dec.py)

```console
root@xVE:$ sha256sum libakamaibmp.so
ed963b92b7cb4b7859305102f04edd627ab5c60dd7622dccc4d926d5cfba78fd
root@xVE:$ python3 dec.py
[*] Akamai BMP 4.1.3
[*] Input:  libakamaibmp.so
[*] Output: libakamaibmp_dec.so
  Mapped LOAD: file 0x0 -> VA 0x0 (0x2116e0 bytes)
  Mapped LOAD: file 0x2116e0 -> VA 0x2156e0 (0x2b928 bytes)
  Mapped LOAD: file 0x23d008 -> VA 0x245008 (0x1678 bytes)
  Mapped LOAD: file 0x248000 -> VA 0x250000 (0xa66 bytes)
  Mapped LOAD: file 0x24c000 -> VA 0x254000 (0x79f68 bytes)
[*] Emulating sub_2CBF50 @ 0x2CBF50...
[+] Emulation completed successfully!
  Patched segment VA 0x0 (0x2116e0 bytes)
  Patched segment VA 0x254000 (0x79f68 bytes)
[+] 2 segments patched
[+] Written: libakamaibmp_dec.so (2909936 bytes)
  initializeKeyN       @ VA 0x9d060 -> file 0x9d060: VALID ARM64
  encryptKeyN          @ VA 0x9d074 -> file 0x9d074: VALID ARM64
  decryptN             @ VA 0x9d18c -> file 0x9d18c: VALID ARM64
  buildN               @ VA 0x9d394 -> file 0x9d394: VALID ARM64
root@xVE:$ sha256sum libakamaibmp_dec.so
416b1e5364cb735532fd3ef476dfa394b31206dd901a58e86a1cfac3f1f35b31
```

## 3. After-Decompression

The changes are extreme; after decompression, all the strings in .rodata became visible, and hundreds of new functions became visible.

![after](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/qqkd3ijkbm3d0fctrlb5.png)

With the readable strings in the .rodata file, it's already possible to identify that akamaibmp doesn't depend on the [APEX](https://source.android.com/docs/core/ota/apex) Android openssl, and has its own embedded openssl.

![functions after](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/dgptdu4l61vwaonn9ef5.png)

Well, great, it's improved significantly, but the .pb segment still has unreadable strings

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/b6h8m3tnmnzkiqjrgovr.png)

.pb is much cooler than just strings, there's a gigantic polymorphic function `sub_25E0AC` used for everything (11719 xrefs)

The strings in the .pb are XORed using 0x55.

**.pb strings decoded (only 13, have more)**

```plaintext
/data/local/bin/su
/data/local/xbin/su
/sbin/su
/su/bin/su
/system/bin/su
/system/bin/.ext/su
/system/bin/failsafe/su
/system/sd/xbin/su
/system/usr/we-need-root/su
/system/xbin/su
/cache/su
/data/su
/proc/self/mounts
```

The .pb participates in some kind of root detection, which isn't very clear yet, but sounds trivial.

.pb is certainly trivial, but during your search, I noticed a 680kb gap in .text, 680kb without functions, It seems that IDA is encountering some problems in this section; you will have to resolve the functions manually, as the auto-analysis didn't catch it.

![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/cq7kpqiru72xvezzubw3.png)

+170 funcs solved manually

Well, .pb is good, it has many functions, very useful, but there isn't much left to decrypt or decode.

This saga will have 3 parts. The first part is the simplest; we are just cleaning up the library and making it a readable environment. In part two, we will address cryptography, and in the last part, we will have a functional sensor generator. Stay tuned!

---

*Analysis done in 37 minutes*

Telegram: @vxigl
Discord: @vx7nyvek or @xve_e
