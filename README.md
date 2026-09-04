# Lua Proprietary Format Generator & Anti-Decompiler Security Suite

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/)
[![Lua 5.1 & 5.5](https://img.shields.io/badge/lua-5.1%20%7C%205.5-blue.svg)](https://www.lua.org/)
[![Decompiler Protection](https://img.shields.io/badge/luadec-blocked-success.svg)](luadec)
[![Architecture](https://img.shields.io/badge/architecture-DDD%20%2F%20Hexagonal-blueviolet.svg)](gen_random_protocol)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**gen_lua_format** is a high-performance **proprietary Lua bytecode format generator, compiler, and anti-reverse-engineering security suite** in Python, built following the Domain-Driven Design (DDD) & Hexagonal Architecture principles of **[gen_random_protocol](https://github.com/bivex/gen_random_protocol)**.

It generates cryptographically seeded, customized Lua binary chunk formats for **Lua 5.1 (38 opcodes)** and **Lua 5.5 (85 opcodes)** that **completely block and defeat decompilers and disassemblers (such as `luadec`, `unluac`, `ChunkSpy`, and `LAT`)**, while guaranteeing 100% operational execution both via a native compiled C VM runner and via a pure Lua in-memory loader (`loader.lua`).

---

## 📐 Domain-Driven Hexagonal Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │                  CLI / Presentation                    │
               │                   (gen_lua_format.py)                  │
               └───────────────────────────┬────────────────────────────┘
                                           │
                                           ▼
               ┌────────────────────────────────────────────────────────┐
               │                  Application Service                   │
               │        (lua_format/application/format_service.py)       │
               └───────────┬───────────────────────────────┬────────────┘
                           │                               │
                           ▼                               ▼
    ┌──────────────────────────────────────┐    ┌──────────────────────────────────────┐
    │             Domain Layer             │    │            Adapters Layer            │
    │  - LuaFormatGenerator (Seeded RNG)   │    │  - StandardLua51Reader / Writer      │
    │  - FormatProfile (Entity & Spec)     │    │  - ProprietaryLuaReader / Writer     │
    │  - Lua 5.1 & 5.5 OpCode Matrix       │    │  - InstructionBitfieldCodec (5.1/5.5)│
    │  - Bitfield Layouts & XOR Transform  │    │  - 22-Byte Framing Envelope Codec    │
    │  - Constant Tag Remapping            │    │  - CRunnerEmitter (lua_runner.c)     │
    │  - Proto Section Reordering          │    │  - LuaLoaderEmitter (loader.lua)     │
    │  - 22B Wire Framing (from gen_proto) │    │  - MarkdownDocEmitter (RFC Spec)     │
    │  - HMAC-SHA256 Auth Trailer          │    │  - ManifestEmitter (JSON / YAML)     │
    └──────────────────────────────────────┘    └──────────────────────────────────────┘
```

---

## 🛡️ Anti-Decompiler Security Layers (`luadec` / `unluac`)

| Security Layer | Implementation Details | Anti-Decompiler Impact |
|---|---|---|
| **1. Custom Header Signature** | Replaces standard `\x1bLua` with random or configured 4-byte magic (e.g., `\x7fU52`, `\x1bSEC`, `\x00PLU`). | `luadec` immediately crashes or aborts with: `bad header in precompiled chunk` or `unexpected symbol` (Exit code 1). |
| **2. Opcode Permutation (5.1: 38 ops, 5.5: 85 ops)** | Bijective pseudo-random shuffling of all VM instructions based on cryptographic seed. | Even if header checks are bypassed, `luadec` maps instructions to incorrect AST nodes, causing syntax corruption or decompiler segfaults. |
| **3. Bitfield Layout Customization** | Reorders and shifts bit positions for registers (`OP_A_C_B`, `B_C_A_OP`, `5.5_OP_A_k_B_C`, `5.5_C_B_k_A_OP`, `5.5_k_B_C_A_OP`, etc.). | Decompilers fail to extract A, B, C, k, Bx, Ax, and sJ registers. |
| **4. Instruction Word XOR Masking** | 32-bit pseudo-random mask applied to raw instruction words (`ins ^ xor_mask`). | Instruction stream appears as high-entropy random data. |
| **5. Constant Type Tag Shuffling** | Remaps standard type tags (`TNIL`, `TBOOLEAN`, `TNUMBER`, `TSTRING`). | Constant tables become unparsable by standard tools. |
| **6. Proto Section Reordering** | Customizes chunk serialization order (Code, Constants, Subprotos, Debug). | Standard parsers read numbers as strings, causing fatal parsing errors or buffer overflows. |
| **7. String Obfuscation** | XOR-masked string payloads and lengths. | Strings and symbols are hidden from `strings`, decompilers, and hex editors. |
| **8. 22-Byte Framing Envelope** | Encapsulates chunk inside `gen_random_protocol` 22B wire header with CRC-32 and HMAC-SHA256. | Protocol-level integrity and authentication barrier. |

---

## 🚀 Quick Start (CLI)

### 1. Automated Anti-Luadec Verification
Runs an end-to-end verification pipeline:
1. Compiles `.lua` to standard `.luac`
2. Verifies that standard `luadec` successfully decompiles `.luac` (proves baseline vulnerability)
3. Encodes `.luac` into the proprietary format `.luc`
4. Attempts `luadec` decompilation on `.luc` -> **verifies that luadec FAILS / is blocked**
5. Executes `.luc` with native C VM Runner -> verifies successful execution
6. Executes `.luc` with Pure Lua In-Memory Loader -> verifies successful execution
7. Decodes `.luc` back with authorized key and verifies 100% roundtrip consistency.

```bash
python3 gen_lua_format.py verify
```

---

### 2. Generate a Proprietary Format Profile
```bash
# Generate a hardened Lua 5.1 profile with RFC spec, C runner, and Lua loader
python3 gen_lua_format.py generate -lv 5.1 --seed a1b2c3d4e5f60718293a4b5c6d7e8f90 --name MY_SECURE_LUA -o out/my_format_51 --build-runner

# Generate a hardened Lua 5.5 profile (85 opcodes)
python3 gen_lua_format.py generate -lv 5.5 --seed 9876543210fedcba9876543210fedcba --preset hardened -o out/my_format_55
```
Output artifacts generated in output directory:
- `LUA_FORMAT_SPEC.md` — RFC-style documentation of the format and opcode translation matrix;
- `format_profile.yaml` / `format_manifest.json` — Machine-readable format profile;
- `lua_custom_runner.c` — Standalone C runner source code;
- `lua_runner` — Compiled native runner binary (when `--build-runner` is passed);
- `loader.lua` — Pure Lua in-memory loader script.

---

### 3. Protect Lua Scripts (Encode)
```bash
python3 gen_lua_format.py protect myscript.lua -o out/my_format_51/myscript.luc --profile out/my_format_51/format_profile.yaml
```

---

### 4. Verify luadec Rejection
```bash
./luadec/luadec/luadec out/my_format/myscript.luc
# Output: luadec: out/my_format/myscript.luc:1: unexpected symbol near '...' (Exit code: 1)
```

---

### 5. Execute the Protected Format

#### Method A: Native C Runner (High-Performance Execution)
```bash
./out/my_format/lua_runner out/my_format/myscript.luc
```

#### Method B: Pure Lua In-Memory Loader (No C Recompilation Required)
```bash
./luadec/lua-5.1/src/lua out/my_format/loader.lua out/my_format/myscript.luc
```

#### Method C: Integration in Existing Lua Codebases
```lua
local loader = require("loader")
local protected_func = loader.loadfile("myscript.luc")
protected_func("arg1", "arg2")
```

---

### 6. Authorized Recovery / Decoding (Decode)
```bash
python3 gen_lua_format.py unprotect out/my_format/myscript.luc -o out/my_format/recovered.luac --profile out/my_format/format_profile.yaml

# The recovered .luac can be decompiled again by authorized tools:
./luadec/luadec/luadec out/my_format/recovered.luac
```

---

## 🧪 Running Automated Test Suite

```bash
python3 -m unittest discover -s lua_format/tests
```

The test suite covers:
- Opcode permutation matrices and bi-directional encoding/decoding;
- All bitfield layouts (`OP_A_C_B`, `OP_A_B_C`, `A_OP_C_B`, `B_C_A_OP`, `C_B_A_OP`, `A_B_C_OP`);
- Instruction XOR masking and string obfuscation;
- Nested functions, closures, upvalues, varargs, loops, and metatables;
- Anti-luadec rejection assertions across multiple presets (`hardened`, `popcap_style`, random seeds);
- Output consistency verification across C Runner and Pure Lua Loader.

---

## 📜 License

MIT License. See [LICENSE](LICENSE) for details.
