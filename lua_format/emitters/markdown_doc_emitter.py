"""
Markdown RFC Specification Emitter for Proprietary Lua Formats.
"""

from lua_format.domain.models import OPCODE_NAMES, NUM_OPCODES
from lua_format.domain.profile import FormatProfile


class MarkdownDocEmitter:
    """Emits detailed RFC markdown documentation for a proprietary Lua bytecode format."""

    def __init__(self, profile: FormatProfile) -> None:
        self.p = profile

    def emit(self) -> str:
        p = self.p

        # Opcode table rows
        op_rows = []
        for std_op in range(NUM_OPCODES):
            name = OPCODE_NAMES[std_op]
            prop_op = p.opcode_map.get(std_op, std_op)
            op_rows.append(f"| `0x{std_op:02X}` (`{std_op:2d}`) | `OP_{name}` | `0x{prop_op:02X}` (`{prop_op:2d}`) |")
        opcode_table = "\n".join(op_rows)

        # Constant tag table rows
        tag_names = {0: "LUA_TNIL", 1: "LUA_TBOOLEAN", 3: "LUA_TNUMBER", 4: "LUA_TSTRING"}
        tag_rows = []
        for std_t, name in tag_names.items():
            prop_t = p.const_tag_map.get(std_t, std_t)
            tag_rows.append(f"| `0x{std_t:02X}` | `{name}` | `0x{prop_t:02X}` |")
        tag_table = "\n".join(tag_rows)

        # Section sequence
        sec_rows = []
        for idx, sec in enumerate(p.proto_section_order, start=1):
            sec_rows.append(f"{idx}. `{sec}`")
        section_list = "\n".join(sec_rows)

        doc = f"""# Proprietary Lua Bytecode Specification: {p.name}

- **Format Profile Name:** `{p.name}`
- **Entropy Seed:** `{p.seed}`
- **Target Lua VM:** Lua 5.1 (PUC-Rio compatible)
- **Endianness:** `{p.endianness}`
- **Bitfield Layout:** `{p.bitfield_layout}`
- **Instruction XOR Mask:** `0x{p.instruction_xor_mask:08X}`
- **String Obfuscation:** `{p.string_encoding}` (Key: `0x{p.string_xor_key:02X}`)
- **22-Byte Framing Envelope:** `{"ENABLED" if p.envelope.enabled else "DISABLED"}`
- **Integrity / Authentication:** `{"CRC-32 + " + str(p.envelope.auth) if p.envelope.enabled else "Native Header"}`

---

## 1. Architectural Overview & Threat Mitigation

This proprietary format is designed to provide binary protection against standard Lua reverse-engineering tools (such as `luadec`, `unluac`, `ChunkSpy`, and `LAT`).

### Defense Layers
1. **Signature & Header Scrambling:** Replaces standard `\\x1bLua` with `{repr(p.magic)[1:]}` (`{p.magic.hex()}`), causing standard decompilers to immediately abort with syntax errors or bad header exceptions.
2. **Opcode Permutation:** All 38 Lua 5.1 virtual machine opcodes are shuffled via seed `{p.seed[:8]}...`. Any bypass of header checks results in invalid instruction dispatch, invalid branch destinations, or decompiler segmentation faults.
3. **Instruction Bitfield Scrambling & XOR Masking:** Instruction words are encoded using the `{p.bitfield_layout}` layout and bitwise XOR masked with `0x{p.instruction_xor_mask:08X}`.
4. **Constant Type Tag Shuffling:** Data types (NIL, BOOLEAN, NUMBER, STRING) are mapped to non-standard integer tags.
5. **Proto Section Reordering:** Chunk serialization order is altered from standard order to `{ ' -> '.join(p.proto_section_order) }`.
6. **Multi-layer Envelope Framing (Optional):** Pre-pended with a 22-byte canonical protocol frame containing CRC-32 checksum and HMAC-SHA256 authentication.

---

## 2. Global Chunk Header (12 Bytes)

| Offset (Bytes) | Field Name | Proprietary Value | Description |
|---|---|---|---|
| `0 .. 3` | `magic` | `{repr(p.magic)[1:]}` (`0x{p.magic.hex().upper()}`) | Proprietary Signature constant |
| `4` | `version` | `0x{p.version:02X}` | VM Version byte |
| `5` | `format` | `0x{p.format_version:02X}` | Format identification version |
| `6` | `endianness` | `0x01` (little) / `0x00` (big) | Wire byte order |
| `7` | `size_int` | `0x04` | `sizeof(int)` |
| `8` | `size_size_t` | `0x08` (or `0x04`) | `sizeof(size_t)` |
| `9` | `size_instruction` | `0x04` | `sizeof(Instruction)` |
| `10` | `size_lua_number` | `0x08` | `sizeof(lua_Number)` |
| `11` | `integral_flag` | `0x00` | Floating-point double precision |

---

## 3. Opcode Translation Matrix

| Standard Opcode | Mnemonic | Proprietary Opcode |
|---|---|---|
{opcode_table}

---

## 4. Constant Type Tag Mapping

| Standard Tag | Constant Type | Proprietary Wire Tag |
|---|---|---|
{tag_table}

---

## 5. Proto Serialization Sequence

Every function prototype (chunk and sub-prototypes) in this format is serialized in the following strict order:

{section_list}

---

## 6. Execution & Verification

### Executing with Native C Runner
```bash
gcc -O2 -I luadec/lua-5.1/src lua_custom_runner.c luadec/lua-5.1/src/liblua.a -lm -o lua_runner
./lua_runner script.luc
```

### Executing with Pure Lua In-Memory Loader
```bash
./luadec/lua-5.1/src/lua loader.lua script.luc
```

### Anti-Decompilation Verification
```bash
# Standard luadec will fail to parse or decompile the proprietary chunk:
./luadec/luadec/luadec script.luc
# Exit Code: 1 (bad header in precompiled chunk / unexpected symbol)
```
"""
        return doc
