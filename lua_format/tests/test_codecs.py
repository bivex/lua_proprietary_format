"""
Unit and roundtrip tests for standard and proprietary codecs.
"""

import subprocess
import tempfile
from pathlib import Path
from random import Random
import unittest

from lua_format.domain.generator import LuaFormatGenerator
from lua_format.domain.models import LuaChunk
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


if __name__ == "__main__":
    unittest.main()
