"""
Unit and roundtrip tests for standard and proprietary codecs.
"""

import subprocess
import tempfile
from pathlib import Path
from random import Random
import unittest

from lua_format.domain.generator import LuaFormatGenerator
from lua_format.domain.models import LuaChunk, Instruction
from lua_format.codecs.standard_codec import StandardLua51Reader, StandardLua51Writer
from lua_format.codecs.proprietary_codec import ProprietaryLuaReader, ProprietaryLuaWriter


LUA_CODE_SAMPLES = [
    """
    local x = 10
    local y = 20
    print("Sum:", x + y)
    """,
    """
    function factorial(n)
        if n == 0 then return 1 else return n * factorial(n - 1) end
    end
    print("Fact 5:", factorial(5))
    """,
    """
    local t = { a = 1, b = "hello", c = { 10, 20, 30 } }
    for k, v in pairs(t) do
        print(k, v)
    end
    """,
    """
    local function counter(start)
        local c = start
        return function()
            c = c + 1
            return c
        end
    end
    local inc = counter(100)
    print(inc(), inc(), inc())
    """
]


class TestLuaCodecs(unittest.TestCase):

    def setUp(self):
        self.luac_bin = Path("luadec/lua-5.1/src/luac").resolve()
        self.lua_bin = Path("luadec/lua-5.1/src/lua").resolve()

    def _compile_lua(self, lua_source: str) -> bytes:
        with tempfile.NamedTemporaryFile(suffix=".lua", mode="w", delete=False) as f_src:
            f_src.write(lua_source)
            src_path = f_src.name
        luac_path = src_path + "c"
        try:
            subprocess.run([str(self.luac_bin), "-o", luac_path, src_path], check=True)
            with open(luac_path, "rb") as f:
                return f.read()
        finally:
            Path(src_path).unlink(missing_ok=True)
            Path(luac_path).unlink(missing_ok=True)

    def test_standard_codec_roundtrip(self):
        for code in LUA_CODE_SAMPLES:
            orig_bytes = self._compile_lua(code)
            reader = StandardLua51Reader(orig_bytes)
            chunk = reader.read_chunk()
            
            writer = StandardLua51Writer(size_size_t=chunk.header.size_size_t)
            reserialized = writer.write_chunk(chunk)
            
            # Re-read reserialized and check proto structure
            reader2 = StandardLua51Reader(reserialized)
            chunk2 = reader2.read_chunk()
            
            self.assertEqual(len(chunk.main_proto.code), len(chunk2.main_proto.code))
            self.assertEqual(len(chunk.main_proto.constants), len(chunk2.main_proto.constants))

    def test_proprietary_codec_roundtrip_all_presets(self):
        rng = Random(42)
        gen = LuaFormatGenerator(rng, "testseed1234567890abcdef12345678")

        presets = [None, "popcap_style", "hardened"]
        for preset in presets:
            profile = gen.generate(preset=preset)
            for code in LUA_CODE_SAMPLES:
                std_bytes = self._compile_lua(code)
                chunk = StandardLua51Reader(std_bytes).read_chunk()
                
                # Write to proprietary
                prop_writer = ProprietaryLuaWriter(profile)
                prop_bytes = prop_writer.write_chunk(chunk)
                
                # Verify that proprietary bytes differ significantly from standard
                self.assertNotEqual(prop_bytes[:4], b"\x1bLua")
                
                # Read from proprietary
                prop_reader = ProprietaryLuaReader(prop_bytes, profile)
                recovered_chunk = prop_reader.read_chunk()
                
                # Re-encode to standard and check with Lua VM!
                std_writer = StandardLua51Writer(size_size_t=chunk.header.size_size_t)
                reconstructed_std = std_writer.write_chunk(recovered_chunk)
                
                # Run reconstructed standard with standard Lua VM to verify correctness!
                with tempfile.NamedTemporaryFile(suffix=".luac", delete=False) as f:
                    f.write(reconstructed_std)
                    tmp_luac = f.name
                try:
                    res = subprocess.run([str(self.lua_bin), tmp_luac], capture_output=True, text=True, check=True)
                    self.assertTrue(len(res.stdout) > 0)
                finally:
                    Path(tmp_luac).unlink(missing_ok=True)


    def test_lua55_instruction_encoding_decoding_roundtrip(self):
        from lua_format.codecs.instruction_codec import (
            decode_standard_instruction,
            encode_standard_instruction,
            encode_proprietary_instruction,
            decode_proprietary_instruction,
            LAYOUT_DEFINITIONS_55
        )
        from lua_format.domain.models import Lua55OpMode, NUM_OPCODES_55

        # Test cases for each Lua 5.5 instruction format mode
        test_instructions = [
            # iABC: MOVE R(A) R(B)
            Instruction(op=0, a=5, b=12, c=0, k=0, mode=Lua55OpMode.iABC),
            # ivABC: GETVARG R(A) C R(B)
            Instruction(op=83, a=2, b=4, c=7, k=1, mode=Lua55OpMode.ivABC),
            # iABx: LOADK R(A) Kst(Bx)
            Instruction(op=3, a=10, bx=12345, mode=Lua55OpMode.iABx),
            # iAsBx: LOADI R(A) sBx
            Instruction(op=1, a=8, sbx=-32000, mode=Lua55OpMode.iAsBx),
            # iAx: EXTRAARG Ax
            Instruction(op=82, ax=16777200, mode=Lua55OpMode.iAx),
            # isJ: JMP sJ
            Instruction(op=56, sj=-500, mode=Lua55OpMode.isJ),
        ]

        # 1. Standard encode/decode roundtrip
        for ins in test_instructions:
            raw = encode_standard_instruction(ins, lua_version="5.5")
            decoded = decode_standard_instruction(raw, lua_version="5.5")
            self.assertEqual(ins.op, decoded.op)
            if ins.mode not in (Lua55OpMode.iAx, Lua55OpMode.isJ):
                self.assertEqual(ins.a, decoded.a)
            if ins.mode in (Lua55OpMode.iABC, Lua55OpMode.ivABC):
                self.assertEqual(ins.b, decoded.b)
                self.assertEqual(ins.c, decoded.c)
                self.assertEqual(ins.k, decoded.k)
            elif ins.mode == Lua55OpMode.iABx:
                self.assertEqual(ins.bx, decoded.bx)
            elif ins.mode == Lua55OpMode.iAsBx:
                self.assertEqual(ins.sbx, decoded.sbx)
            elif ins.mode == Lua55OpMode.iAx:
                self.assertEqual(ins.ax, decoded.ax)
            elif ins.mode == Lua55OpMode.isJ:
                self.assertEqual(ins.sj, decoded.sj)

        # 2. Proprietary encode/decode roundtrip across all 5.5 layouts & XOR masks
        rng = Random(12345)
        shuffled_ops = list(range(NUM_OPCODES_55))
        rng.shuffle(shuffled_ops)
        opcode_map = {std_op: prop_op for prop_op, std_op in enumerate(shuffled_ops)}
        inv_map = {prop_op: std_op for prop_op, std_op in enumerate(shuffled_ops)}
        xor_masks = [0, 0xA5A5A5A5, 0xFFFFFFFF, 0x12345678]

        for layout in LAYOUT_DEFINITIONS_55.keys():
            for xor_mask in xor_masks:
                for ins in test_instructions:
                    prop_raw = encode_proprietary_instruction(
                        ins, layout=layout, opcode_map=opcode_map, xor_mask=xor_mask, lua_version="5.5"
                    )
                    recovered = decode_proprietary_instruction(
                        prop_raw, layout=layout, inv_opcode_map=inv_map, xor_mask=xor_mask, lua_version="5.5"
                    )
                    self.assertEqual(ins.op, recovered.op, f"Opcode mismatch in {layout} xor=0x{xor_mask:08X}")
                    if ins.mode not in (Lua55OpMode.iAx, Lua55OpMode.isJ):
                        self.assertEqual(ins.a, recovered.a, f"A mismatch in {layout}")
                    if ins.mode in (Lua55OpMode.iABC, Lua55OpMode.ivABC):
                        self.assertEqual(ins.b, recovered.b, f"B mismatch in {layout}")
                        self.assertEqual(ins.c, recovered.c, f"C mismatch in {layout}")
                        self.assertEqual(ins.k, recovered.k, f"k mismatch in {layout}")
                    elif ins.mode == Lua55OpMode.iABx:
                        self.assertEqual(ins.bx, recovered.bx, f"Bx mismatch in {layout}")
                    elif ins.mode == Lua55OpMode.iAsBx:
                        self.assertEqual(ins.sbx, recovered.sbx, f"sBx mismatch in {layout}")
                    elif ins.mode == Lua55OpMode.iAx:
                        self.assertEqual(ins.ax, recovered.ax, f"Ax mismatch in {layout}")
                    elif ins.mode == Lua55OpMode.isJ:
                        self.assertEqual(ins.sj, recovered.sj, f"sJ mismatch in {layout}")

    def test_lua55_profile_generation(self):
        from lua_format.application.format_service import LuaFormatService
        from lua_format.domain.models import NUM_OPCODES_55
        service = LuaFormatService()

        for preset in ["hardened", "popcap_style", "stealth"]:
            profile = service.generate_profile(lua_version="5.5", preset=preset)
            self.assertEqual(profile.lua_version, "5.5")
            self.assertEqual(len(profile.opcode_map), NUM_OPCODES_55)
            self.assertEqual(len(profile.inv_opcode_map), NUM_OPCODES_55)
            self.assertTrue(profile.bitfield_layout.startswith("5.5_"))

    def test_apultra_codec_roundtrip(self):
        from lua_format.codecs.compression_codec import ApultraCodec
        codec = ApultraCodec()
        
        sample_bytes = b"local x = 10; print(x + 20); for i=1,100 do print(i) end\n" * 20
        compressed = codec.compress(sample_bytes)
        self.assertLess(len(compressed), len(sample_bytes))
        
        decompressed = codec.decompress(compressed)
        self.assertEqual(decompressed, sample_bytes)


if __name__ == "__main__":
    unittest.main()
