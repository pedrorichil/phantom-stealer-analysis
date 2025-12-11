# 🕵️‍♂️ Malware Analysis: Phantom Stealer V3

![Category](https://img.shields.io/badge/Category-InfoStealer-red)
![Platform](https://img.shields.io/badge/Platform-Windows_x64-blue)
![Analysis](https://img.shields.io/badge/Method-Static_Analysis-green)

## ⚠️ Disclaimer
**This repository is for educational and research purposes only.** The analysis details a real-world malware sample found in the wild. I am not responsible for any damage caused by the misuse of this information. The malicious binary is NOT included in this repository.

---

## 📋 Executive Summary
* **File Name:** `update_1857477.exe`
* **SHA256:** `b1d825a8af5600becc7ccfce7facc2375d402219b183d84d17c5110cc1389b79`
* **Malware Family:** Phantom Stealer V3 / Wacatac
* **Compiler:** MinGW (GCC) C++
* **Date of Analysis:** December 11, 2025
* **Analyst:** [Seu Nome/Github]

## 🛠️ Tools Used
* **Objdump:** Disassembly and header inspection.
* **Strings:** Initial triage and ASCII extraction.
* **FLOSS:** Deobfuscation of stack strings.
* **Hexdump/DD:** Memory dump inspection.

---

## 🔍 Technical Analysis

### 1. Initial Triage & Reconnaissance
The binary is a **stripped PE32+ executable**. Initial string analysis revealed network reconnaissance activity typical of stealers using legitimate APIs to geolocate the victim.

```bash
$ strings -e l update_1857477.exe | grep "http"
[https://api.ipify.org](https://api.ipify.org)
````

### 2\. Capabilities (Import Address Table)

Inspection of the IAT (`.idata`) revealed critical imports indicating the malware's intent:

  * `CryptUnprotectData` (CRYPT32.dll): Used to decrypt browser credentials/cookies.
  * `InternetConnectA` (WININET.dll): For C2 communication.
  * `WlanGetAvailableNetworkList` (wlanapi.dll): Wi-Fi profile stealing.
  * `GetClipboardData` (USER32.dll): Clipboard monitoring (crypto wallet hijacking).

### 3\. Deobfuscation & String Hunting

Standard text search for the C2 domain failed due to **Stack Strings** and custom encryption. Using **FLOSS**, I extracted hidden artifacts from the memory stack:

  * **API Endpoint:** `/api/data`
  * **Tight String (Integer):** `1096216591`
  * **Custom Alphabet:** `.,-+xX0123456789abcdef0123456789ABCDEF...`

### 4\. C2 Extraction (The "Tight String" Technique)

The malware stored the Command & Control IP address as a raw 4-byte integer to evade static signatures.

**Decoding Logic:**

1.  **Integer:** `1096216591`
2.  **Hex:** `0x415AA00F`
3.  **Little Endian:** `0F A0 5A 41`
4.  **IP Conversion:** `15.160.90.65`

### 5\. Code Reverse Engineering (Assembly)

I located the connection trigger by tracing the `InternetConnectA` call. The code snippet below shows the malware passing the decrypted C2 address (stored at `rsp+0x90`) to the `RDX` register.

```assembly
140022602: 48 8b 94 24 90 00 00    mov    rdx,QWORD PTR [rsp+0x90] ; C2 Address loaded
14002260a: c7 44 24 28 03 00 00    mov    DWORD PTR [rsp+0x28],0x3
14002261b: ff 15 7f 35 10 00       call   QWORD PTR [rip+0x10357f] ; InternetConnectA
```

Additionally, **Anti-Debugging** techniques were identified using `rdtsc` and `0xdeadbeef` checks to abort execution if analyzed dynamically.

-----

## 🚨 Indicators of Compromise (IOCs)

| Type | Value | Description |
| :--- | :--- | :--- |
| **C2 IP** | `15.160.90.65` | Attacker Infrastructure |
| **URL** | `http://15.160.90.65/api/data` | Exfiltration Endpoint (POST) |
| **Domain** | `api.ipify.org` | IP Check Service |
| **Hash** | `b1d825a8af5600becc7ccfce7facc2375d402219b183d84d17c5110cc1389b79` | Sample SHA256 |

-----

## 🛡️ Mitigation

Block traffic to `15.160.90.65` and monitor for POST requests to `/api/data` with User-Agents mimicking generic Chrome/Firefox builds on non-browser processes.



