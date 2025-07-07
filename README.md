# AV - Advanced Windows Loader & Anti-Analysis Framework

## Overview

**This** is an advanced Windows loader framework designed for stealthy code injection, anti-analysis, and evasion. It combines direct system call invocation, API hashing, anti-analysis techniques, and IAT camouflage to bypass modern security solutions and analysis environments. The project is modular, allowing for easy extension and adaptation to new evasion techniques or payloads.

---

## Features

- **Direct Syscall Invocation (HellsGate):**
  - Bypasses user-mode hooks by resolving and invoking Windows syscalls directly.
- **API Hashing:**
  - Resolves API and module addresses using custom hash functions, avoiding suspicious imports.
- **Anti-Analysis Techniques:**
  - Mouse click monitoring (detects sandbox inactivity)
  - Self-deletion (removes loader after execution)
  - Delayed execution (evades automated analysis)
- **IAT Camouflage:**
  - Populates the Import Address Table with benign API references to appear less suspicious.
- **CRT-Free Utilities:**
  - Custom implementations of common CRT functions and debug output for maximum portability.
- **Modular Design:**
  - Easily extend or modify anti-analysis, injection, or utility routines.

---

## Architecture & Main Components

- **main.c**: Entry point. Initializes syscalls, optionally runs anti-analysis, and injects the RC4-decrypted payload into a target process.
- **inject.c**: Core loader logic. Handles syscall/API table setup, process/thread enumeration, RC4 decryption, and remote injection/hijacking.
- **AntiAnalysis.c**: Implements anti-analysis routines (mouse click logger, self-deletion, delay via syscalls).
- **HellsGate.c**: Implements the HellsGate technique for direct syscall invocation.
- **ApiHashing.c**: Custom API and module hashing for stealthy dynamic resolution.
- **Hijacking.c**: Thread hijacking and shellcode injection logic.
- **WinApi.c**: CRT-free replacements and string hashing utilities.
- **IatCamoflouage.h**: Functions to populate the IAT with harmless API references.
- **Structs.h / typedef.h**: Windows internal structures, enums, and API typedefs.
- **Debug.h**: CRT-free debug output macros and helpers.
- **Common.h**: Central header for prototypes, constants, and shared structures.

---

## Anti-Analysis Techniques

- **Mouse Click Monitoring:**
  - Requires user interaction (mouse clicks) to proceed, detecting sandbox inactivity.
- **Self-Deletion:**
  - Marks the loader for deletion after execution, removing traces.
- **Delayed Execution:**
  - Uses direct syscalls to sleep, evading automated/fast analysis.
- **IAT Camouflage:**
  - Optionally populates the IAT with benign APIs to evade static analysis.

---

## Usage Instructions

### 1. Prerequisites
- Windows (x64 recommended)
- Visual Studio (or compatible C/C++ compiler)

### 2. Building the Project
1. Open `AV.sln` in Visual Studio.
2. Build the solution (Release x64 recommended).
3. The output binary will be in the appropriate build directory.

### 3. Configuration
- **Target Process:**
  - The loader injects into a process name deobfuscated at runtime (default: `msedge.exe`).
  - To change the target, modify the obfuscated string in `DeobfuscateProcessName()` in `AntiAnalysis.c`.
- **Anti-Analysis:**
  - To enable anti-analysis, uncomment `#define ANTI_ANALYSIS` in `main.c`.
- **Payload:**
  - The RC4-encrypted payload is embedded in `main.c` as `Rc4CipherText`.
  - Replace this array with your own encrypted shellcode as needed.
- **IAT Camouflage:**
  - Optionally call `CleanIatCamouflage()` in `main.c` to populate the IAT with benign APIs.

### 4. Running
- If anti-analysis is enabled, interact with the mouse to pass the checks.
- The loader will inject the decrypted payload into the target process and hijack a thread to execute it.

---

## Extending the Project
- **Unhook NTDLL**
  - Modern EDRs use hooked ntdll.dll , the next step is unhooke it 
- **Custom Anti-Analysis:**
  - Implement new routines in `AntiAnalysis.c` and add them to the `AntiAnalysis()` function.

- **CRT-Free/Custom Utilities:**
  - Add replacements or helpers in `WinApi.c` or `Debug.h` as needed.

---

## Legal & Disclaimer

This project is for educational and research purposes only. Use it only in environments and on systems you own or have explicit permission to test. The authors are not responsible for any misuse or damage caused by this software.

---

## Credits
- Inspired by HellsGate, SysWhispers, and Maldev Academy.
- See comments in source files for further references and attributions. 