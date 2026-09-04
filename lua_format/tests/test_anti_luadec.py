"""
Automated Anti-Luadec and Multi-Runtime Verification Tests.
Verifies that:
1. Standard luadec can decompile standard luac files.
2. Standard luadec CANNOT decompile proprietary formats (fails/rejects).
3. Generated Native C Runner executes the proprietary format chunks natively.
4. Generated Pure Lua In-Memory Loader executes the proprietary format chunks.
5. Roundtrip authorized decoding restores functional standard bytecode.
"""

from pathlib import Path
import unittest
from lua_format.application.format_service import LuaFormatService


TEST_PROGRAMS = [
    # 1. Simple Arithmetic & Printing
    """
    local a = 123
    local b = 456
    print("Product:", a * b)
    """,
    # 2. Control Flow, Loops, & Tables
    """
    local sum = 0
    for i = 1, 10 do
        if i % 2 == 0 then
            sum = sum + i
        end
    end
    print("Sum of evens:", sum)
    """,
    # 3. Closures and Upvalues
    """
    local function make_adder(x)
        return function(y)
            return x + y
        end
    end
    local add10 = make_adder(10)
    print("Add10(5):", add10(5))
    print("Add10(20):", add10(20))
    """,
    # 4. Complex Data Structures and Varargs
    """
    local function collect(...)
        local args = { ... }
        local res = {}
        for i, v in ipairs(args) do
            res[#res + 1] = tostring(v):upper()
        end
        return table.concat(res, ", ")
    end
    print("Collected:", collect("apple", "banana", "cherry"))
    """
]


class TestAntiLuadecAndRuntimes(unittest.TestCase):

    def setUp(self):
        self.service = LuaFormatService()

    def test_anti_luadec_protection_hardened_preset(self):
        profile = self.service.generate_profile(seed_hex="112233445566778899aabbccddeeff00", preset="hardened")
        for idx, code in enumerate(TEST_PROGRAMS):
            res = self.service.verify_pipeline(sample_lua_code=code, profile=profile)
            self.assertTrue(res["standard_luadec_success"], f"Sample {idx}: Standard luadec should succeed on standard luac")
            self.assertTrue(res["anti_luadec_protected"], f"Sample {idx}: Standard luadec MUST FAIL on proprietary format!")
            self.assertTrue(res["c_runner_success"], f"Sample {idx}: C runner failed to execute!")
            self.assertTrue(res["lua_loader_success"], f"Sample {idx}: Pure Lua loader failed to execute!")
            self.assertTrue(res["output_match"], f"Sample {idx}: Outputs did not match!")

    def test_anti_luadec_protection_popcap_preset(self):
        profile = self.service.generate_profile(seed_hex="aabbccddeeff00112233445566778899", preset="popcap_style")
        for idx, code in enumerate(TEST_PROGRAMS):
            res = self.service.verify_pipeline(sample_lua_code=code, profile=profile)
            self.assertTrue(res["standard_luadec_success"], f"Sample {idx}: Standard luadec should succeed on standard luac")
            self.assertTrue(res["anti_luadec_protected"], f"Sample {idx}: Standard luadec MUST FAIL on proprietary format!")
            self.assertTrue(res["c_runner_success"], f"Sample {idx}: C runner failed to execute!")
            self.assertTrue(res["lua_loader_success"], f"Sample {idx}: Pure Lua loader failed to execute!")
            self.assertTrue(res["output_match"], f"Sample {idx}: Outputs did not match!")

    def test_anti_luadec_protection_apultra_compressed(self):
        profile = self.service.generate_profile(
            seed_hex="3344556677889900aabbccddeeff0011",
            preset="apultra_hardened"
        )
        self.assertEqual(profile.compression, "apultra")
        for idx, code in enumerate(TEST_PROGRAMS):
            res = self.service.verify_pipeline(sample_lua_code=code, profile=profile)
            self.assertTrue(res["standard_luadec_success"], f"Sample {idx}: Standard luadec should succeed on standard luac")
            self.assertTrue(res["anti_luadec_protected"], f"Sample {idx}: Standard luadec MUST FAIL on compressed proprietary format!")
            self.assertTrue(res["c_runner_success"], f"Sample {idx}: C runner failed on apultra compressed chunk!")
            self.assertTrue(res["lua_loader_success"], f"Sample {idx}: Pure Lua loader failed on apultra compressed chunk!")
            self.assertTrue(res["output_match"], f"Sample {idx}: Outputs did not match!")


if __name__ == "__main__":
    unittest.main()
