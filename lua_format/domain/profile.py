"""
Domain Profile and Specification for Proprietary Lua Bytecode Formats.
Supports Lua 5.1 and Lua 5.5.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import json


SUPPORTED_BITFIELD_LAYOUTS_51 = [
    "OP_A_C_B",   # Standard Lua 5.1: OP (0..5), A (6..13), C (14..22), B (23..31)
    "OP_A_B_C",   # Alternate:        OP (0..5), A (6..13), B (14..22), C (23..31)
    "A_OP_C_B",   # Alternate:        A (0..7),  OP (8..13), C (14..22), B (23..31)
    "B_C_A_OP",   # PopCap/Reverse:   B (0..8),  C (9..17),  A (18..25), OP (26..31)
    "C_B_A_OP",   # Alternate:        C (0..8),  B (9..17),  A (18..25), OP (26..31)
    "A_B_C_OP",   # Alternate:        A (0..7),  B (8..16),  C (17..25), OP (26..31)
]

SUPPORTED_BITFIELD_LAYOUTS_55 = [
    "5.5_OP_A_k_B_C",  # Standard Lua 5.5: OP (0..6), A (7..14), k (15), B (16..23), C (24..31)
    "5.5_OP_A_k_C_B",  # Alternate:        OP (0..6), A (7..14), k (15), C (16..23), B (24..31)
    "5.5_OP_k_B_C_A",  # Alternate:        OP (0..6), k (7), B (8..15), C (16..23), A (24..31)
    "5.5_C_B_k_A_OP",  # Reverse:          C (0..7),  B (8..15),  k (16), A (17..24), OP (25..31)
    "5.5_k_B_C_A_OP",  # Alternate:        k (0),     B (1..8),   C (9..16), A (17..24), OP (25..31)
    "5.5_B_C_k_A_OP",  # Alternate:        B (0..7),  C (8..15),  k (16), A (17..24), OP (25..31)
]

SUPPORTED_BITFIELD_LAYOUTS = SUPPORTED_BITFIELD_LAYOUTS_51 + SUPPORTED_BITFIELD_LAYOUTS_55

SUPPORTED_SECTION_ORDERS = [
    ["header_info", "code", "constants", "subprotos", "debug"],          # Standard
    ["header_info", "constants", "code", "subprotos", "debug"],          # Constants first
    ["header_info", "subprotos", "code", "constants", "debug"],          # Subprotos first
    ["header_info", "constants", "subprotos", "code", "debug"],          # Data first, code last
    ["header_info", "code", "subprotos", "constants", "debug"],          # Code then subprotos
]


@dataclass
class EnvelopeConfig:
    enabled: bool = False
    magic: int = 0x50524F54            # "PROT" in ASCII
    version: int = 0x0100              # v1.0
    session_id: int = 0x1337BEEF
    sequence: int = 1
    auth: Optional[str] = None         # None | "hmac-sha256"
    auth_key: bytes = b"default_secret_key_32_bytes!!"


@dataclass
class FormatProfile:
    name: str
    seed: str
    lua_version: str = "5.1"           # "5.1" | "5.5"
    magic: bytes = b"\x1bSEC"
    version: int = 0x51
    format_version: int = 0
    endianness: str = "little"         # "little" | "big"
    size_int: int = 4
    size_size_t: int = 8               # 4 or 8
    size_instruction: int = 4
    size_lua_number: int = 8
    integral: int = 0
    
    # Opcode mapping: std_op -> prop_op
    opcode_map: Dict[int, int] = field(default_factory=dict)
    inv_opcode_map: Dict[int, int] = field(default_factory=dict)
    
    # Instruction layout & transformation
    bitfield_layout: str = "OP_A_C_B"
    instruction_xor_mask: int = 0x00000000
    
    # Constant tag mapping: std_tag -> prop_tag
    const_tag_map: Dict[int, int] = field(default_factory=dict)
    inv_const_tag_map: Dict[int, int] = field(default_factory=dict)
    
    # Proto serialization ordering
    proto_section_order: List[str] = field(default_factory=lambda: ["header_info", "code", "constants", "subprotos", "debug"])
    strip_debug: bool = False
    
    # String obfuscation
    string_encoding: str = "raw"       # "raw" | "xor"
    string_xor_key: int = 0x00
    
    # Multi-layer envelope framing (from gen_random_protocol)
    envelope: EnvelopeConfig = field(default_factory=EnvelopeConfig)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "seed": self.seed,
            "lua_version": self.lua_version,
            "magic_hex": self.magic.hex(),
            "magic_repr": repr(self.magic),
            "version": self.version,
            "format_version": self.format_version,
            "endianness": self.endianness,
            "size_int": self.size_int,
            "size_size_t": self.size_size_t,
            "size_instruction": self.size_instruction,
            "size_lua_number": self.size_lua_number,
            "integral": self.integral,
            "opcode_map": {int(k): int(v) for k, v in self.opcode_map.items()},
            "bitfield_layout": self.bitfield_layout,
            "instruction_xor_mask": f"0x{self.instruction_xor_mask:08X}",
            "const_tag_map": {int(k): int(v) for k, v in self.const_tag_map.items()},
            "proto_section_order": self.proto_section_order,
            "strip_debug": self.strip_debug,
            "string_encoding": self.string_encoding,
            "string_xor_key": f"0x{self.string_xor_key:02X}",
            "envelope": {
                "enabled": self.envelope.enabled,
                "magic": f"0x{self.envelope.magic:08X}",
                "version": f"0x{self.envelope.version:04X}",
                "session_id": f"0x{self.envelope.session_id:08X}",
                "auth": self.envelope.auth,
                "auth_key_hex": self.envelope.auth_key.hex(),
            }
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'FormatProfile':
        magic = bytes.fromhex(data["magic_hex"]) if "magic_hex" in data else b"\x1bSEC"
        opcode_map = {int(k): int(v) for k, v in data.get("opcode_map", {}).items()}
        inv_opcode_map = {v: k for k, v in opcode_map.items()}
        
        const_tag_map = {int(k): int(v) for k, v in data.get("const_tag_map", {}).items()}
        inv_const_tag_map = {v: k for k, v in const_tag_map.items()}
        
        xor_mask = data.get("instruction_xor_mask", 0)
        if isinstance(xor_mask, str):
            xor_mask = int(xor_mask, 16 if xor_mask.startswith("0x") else 10)
            
        str_xor = data.get("string_xor_key", 0)
        if isinstance(str_xor, str):
            str_xor = int(str_xor, 16 if str_xor.startswith("0x") else 10)

        env_data = data.get("envelope", {})
        env_magic = env_data.get("magic", "0x50524F54")
        env_magic_int = int(env_magic, 16) if isinstance(env_magic, str) else env_magic
        
        env_ver = env_data.get("version", "0x0100")
        env_ver_int = int(env_ver, 16) if isinstance(env_ver, str) else env_ver
        
        env_sess = env_data.get("session_id", "0x1337BEEF")
        env_sess_int = int(env_sess, 16) if isinstance(env_sess, str) else env_sess
        
        auth_key_hex = env_data.get("auth_key_hex", "")
        auth_key = bytes.fromhex(auth_key_hex) if auth_key_hex else b"default_secret_key_32_bytes!!"

        envelope = EnvelopeConfig(
            enabled=env_data.get("enabled", False),
            magic=env_magic_int,
            version=env_ver_int,
            session_id=env_sess_int,
            auth=env_data.get("auth", None),
            auth_key=auth_key,
        )

        return cls(
            name=data["name"],
            seed=data["seed"],
            lua_version=data.get("lua_version", "5.1"),
            magic=magic,
            version=data.get("version", 0x51),
            format_version=data.get("format_version", 0),
            endianness=data.get("endianness", "little"),
            size_int=data.get("size_int", 4),
            size_size_t=data.get("size_size_t", 8),
            size_instruction=data.get("size_instruction", 4),
            size_lua_number=data.get("size_lua_number", 8),
            integral=data.get("integral", 0),
            opcode_map=opcode_map,
            inv_opcode_map=inv_opcode_map,
            bitfield_layout=data.get("bitfield_layout", "OP_A_C_B"),
            instruction_xor_mask=xor_mask,
            const_tag_map=const_tag_map,
            inv_const_tag_map=inv_const_tag_map,
            proto_section_order=data.get("proto_section_order", ["header_info", "code", "constants", "subprotos", "debug"]),
            strip_debug=data.get("strip_debug", False),
            string_encoding=data.get("string_encoding", "raw"),
            string_xor_key=str_xor,
            envelope=envelope
        )
