"""
Proprietary Lua Format Generator Domain Service.
Supports Lua 5.1 and Lua 5.5 bytecode generation.
"""

import hashlib
import os
from random import Random
from typing import Optional

from lua_format.domain.models import NUM_OPCODES, NUM_OPCODES_55, StandardConstantTag
from lua_format.domain.profile import (
    EnvelopeConfig, FormatProfile,
    SUPPORTED_BITFIELD_LAYOUTS_51, SUPPORTED_BITFIELD_LAYOUTS_55, SUPPORTED_SECTION_ORDERS
)


def make_seed() -> str:
    """Generate a random 32-character hexadecimal seed."""
    return os.urandom(16).hex()


class LuaFormatGenerator:
    """Domain service for generating randomized or preset proprietary Lua format profiles."""

    def __init__(self, rng: Random, seed: str) -> None:
        self.rng = rng
        self.seed = seed

    def _generate_magic(self, name: str) -> bytes:
        # Generates a 4-byte signature that breaks standard "\x1bLua"
        lead_bytes = [0x1B, 0x7F, 0x00, 0x50, 0x4C]
        lead = self.rng.choice(lead_bytes)
        letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        b2 = ord(self.rng.choice(letters))
        b3 = ord(self.rng.choice(letters))
        b4 = ord(self.rng.choice(letters))
        return bytes([lead, b2, b3, b4])

    def generate(self,
                 name: Optional[str] = None,
                 lua_version: str = "5.1",
                 endianness: Optional[str] = None,
                 bitfield_layout: Optional[str] = None,
                 instruction_xor: bool = True,
                 string_xor: bool = True,
                 strip_debug: bool = False,
                 envelope: bool = False,
                 auth_hmac: bool = False,
                 compression: str = "none",
                 preset: Optional[str] = None) -> FormatProfile:
        """Generate a complete proprietary format profile for Lua 5.1 or Lua 5.5."""
        if not name:
            short_seed = self.seed[:6].upper()
            ver_tag = "55" if lua_version == "5.5" else "51"
            name = f"LUA{ver_tag}_PROPRIETARY_{short_seed}"

        # 1. Opcode permutation
        n_ops = NUM_OPCODES_55 if lua_version == "5.5" else NUM_OPCODES
        opcodes = list(range(n_ops))
        self.rng.shuffle(opcodes)
        opcode_map = {std_op: prop_op for std_op, prop_op in enumerate(opcodes)}
        inv_opcode_map = {prop_op: std_op for std_op, prop_op in opcode_map.items()}

        # 2. Constant tags permutation
        std_tags = [
            StandardConstantTag.TNIL,
            StandardConstantTag.TBOOLEAN,
            StandardConstantTag.TNUMBER,
            StandardConstantTag.TSTRING
        ]
        shuffled_tags = list(std_tags)
        self.rng.shuffle(shuffled_tags)
        const_tag_map = {std: prop for std, prop in zip(std_tags, shuffled_tags)}
        inv_const_tag_map = {prop: std for std, prop in const_tag_map.items()}

        # 3. Bitfield layout
        if lua_version == "5.5":
            layout = bitfield_layout or self.rng.choice(SUPPORTED_BITFIELD_LAYOUTS_55)
        else:
            layout = bitfield_layout or self.rng.choice(SUPPORTED_BITFIELD_LAYOUTS_51)

        # 4. Instruction XOR mask
        xor_mask = self.rng.randint(0x01010101, 0xFFFFFFFF) if instruction_xor else 0x00000000

        # 5. Magic signature
        magic = self._generate_magic(name)

        # 6. Endianness
        endian = endianness or self.rng.choice(["little", "little"])  # Default mostly little-endian

        # 7. Section order
        section_order = self.rng.choice(SUPPORTED_SECTION_ORDERS)

        # 8. String encoding
        str_enc = "xor" if string_xor else "raw"
        str_key = self.rng.randint(0x11, 0xEF) if string_xor else 0x00

        # 9. Envelope configuration (Gen-Random-Protocol 22B header)
        env_magic = 0x50524F54 ^ self.rng.randint(0x00010000, 0x7FFF0000)
        env_config = EnvelopeConfig(
            enabled=envelope or auth_hmac,
            magic=env_magic,
            version=0x0100,
            session_id=self.rng.randint(0x10000000, 0xFFFFFFFE),
            sequence=1,
            auth="hmac-sha256" if auth_hmac else None,
            auth_key=hashlib.sha256(self.seed.encode()).digest()
        )

        version_byte = 0x55 if lua_version == "5.5" else 0x51

        # Handle Presets
        if preset == "popcap_style":
            layout = "5.5_C_B_k_A_OP" if lua_version == "5.5" else "B_C_A_OP"
            xor_mask = 0x00000000
            str_enc = "raw"
            str_key = 0x00
            magic = b"\x1bPop"
            section_order = ["header_info", "code", "constants", "subprotos", "debug"]
        elif preset == "hardened":
            layout = "5.5_C_B_k_A_OP" if lua_version == "5.5" else "B_C_A_OP"
            env_config.enabled = True
            env_config.auth = "hmac-sha256"
            str_enc = "xor"
            strip_debug = True
        elif preset in ("apultra_hardened", "ultra_hardened"):
            layout = "5.5_C_B_k_A_OP" if lua_version == "5.5" else "B_C_A_OP"
            env_config.enabled = True
            env_config.auth = "hmac-sha256"
            str_enc = "xor"
            strip_debug = True
            compression = "apultra"

        return FormatProfile(
            name=name,
            seed=self.seed,
            lua_version=lua_version,
            magic=magic,
            version=version_byte,
            format_version=self.rng.randint(0, 10),
            endianness=endian,
            size_int=4,
            size_size_t=8,
            size_instruction=4,
            size_lua_number=8,
            integral=0,
            opcode_map=opcode_map,
            inv_opcode_map=inv_opcode_map,
            bitfield_layout=layout,
            instruction_xor_mask=xor_mask,
            const_tag_map=const_tag_map,
            inv_const_tag_map=inv_const_tag_map,
            proto_section_order=section_order,
            strip_debug=strip_debug,
            string_encoding=str_enc,
            string_xor_key=str_key,
            compression=compression,
            envelope=env_config
        )
