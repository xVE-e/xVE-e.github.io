---
layout: article
title: "DexProtector Bypass"
---

# DexProtector Bypass

## anti deception warning

> You probably won't learn anything here, I'm just showing you that I did it

**Explanations**: After reverse-engineering Akamai BMP, I decided to analyze something a little different: a powerful Android RASP used by many banks, especially Revolut (also used in iFood). Unlike the Akamai article, this one was completely motivated by financial gain. Well, as skilled as I am, it's difficult to find reverse engineering work on Android, since this one was paid. It will be more about showing the results I achieved than actually showing how I did it :) I need to eat, hire me!

(Everything I'm saying here assumes you've already read [Romain Thomas's article](https://www.romainthomas.fr/post/26-01-dexprotector/); if you haven't, go read it. It's incredible.)


**1**: **Key derivation**

Deriving the master key is surprisingly simple; it's possible to derive it offline. However, deriving the subkeys (these are child keys used to decrypt specific assets) is more difficult.

**2**: **Assets**

Many assets are trivial. Generally, se.dat and classes.dat are the most important. se.dat is very cool, good work Licel.
se.dat contains the strings table. Unlike Romain Thomas, I found the use of Redex unnecessary, at least in the apps I encountered. Maybe it's because I'm lazy, but at least in Revolut, 90% of the strings are trivial. Dexprotector obfuscates parts of the code that aren't sensitive, such as pieces of libraries like okhttp and retrofit, and other things. So I didn't really want to use Redex, although I used it later just out of curiosity. In the end, it didn't matter much. Redex is just for de-obscuring, For my use it was trivial, we cared more about the RASP.

**3**: **RASP**
This one is really cool, I spent 2 months trying to crack it universally. Contrary to what you might think, the obfuscation of libdp.so isn't that heavy; it's difficult to understand, but it doesn't have heavy CFF or anything like that.

They use extremely innovative techniques for detecting Frida, ptrace, xposed, and any trampoline. Fortunately, I managed to use a workaround to circumvent this temporarily. With this workaround, I was able to analyze the behavior of libdp.so at runtime more easily.

The first step is to neutralize the pre-rasp, one of the first detection layers.

In addition, you need to circumvent the self-sabotage; dexprotector doesn't decrypt the assets if rtld is contaminated. Besides neutralizing the entire rasp chain, this is the most complicated part; I used the clean copy technique.

to derive the key you need some calculated values ​​from the configuration DEX. I call it config dex, it has something like 2 functions and things like that, and there you get the values ​​to derive the key.

**few strings:**
![strings](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/t2u9hkh90e1xjfpxh2q1.png)

**config dex:**
![config](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/h760twadcm6h8twvt776.png)

![configg](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ktgz0rvvg3xtp3secj9k.png)

ENDD, here's a sample video of my Frida script bypassing the Dexprotector RASP: [youtu.be/nuUNjzY4LmQ](https://youtu.be/nuUNjzY4LmQ)


tg: @vxigl
discord: @xve_e