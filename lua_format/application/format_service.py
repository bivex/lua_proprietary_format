"""
Application Format Service for orchestrating Lua proprietary format generation,
bytecode encoding/decoding, native C runner building, pure Lua loader emitting,
and anti-luadec verification.
"""

import json
import os
from pathlib import Path
from random import Random
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

from lua_format.domain.generator import LuaFormatGenerator, make_seed
from lua_format.domain.profile import FormatProfile
from lua_format.codecs.standard_codec import StandardLua51Reader, StandardLua51Writer
from lua_format.codecs.proprietary_codec import ProprietaryLuaReader, ProprietaryLuaWriter
from lua_format.emitters.c_runner_emitter import CRunnerEmitter
from lua_format.emitters.lua_loader_emitter import LuaLoaderEmitter
from lua_format.emitters.markdown_doc_emitter import MarkdownDocEmitter
from lua_format.emitters.manifest_emitter import ManifestEmitter


class LuaFormatService:
    """Application service for Lua Proprietary Formats."""

    def __init__(self,
                 workspace_root: Optional[Path] = None,
                 luac_bin: Optional[Path] = None,
                 lua_bin: Optional[Path] = None,
                 luadec_bin: Optional[Path] = None,
                 liblua_a: Optional[Path] = None,
                 lua_inc: Optional[Path] = None) -> None:
        self.root = workspace_root or Path.cwd()
        self.luac_bin = luac_bin or (self.root / "luadec/lua-5.1/src/luac").resolve()
        self.lua_bin = lua_bin or (self.root / "luadec/lua-5.1/src/lua").resolve()
        self.luadec_bin = luadec_bin or (self.root / "luadec/luadec/luadec").resolve()
        self.liblua_a = liblua_a or (self.root / "luadec/lua-5.1/src/liblua.a").resolve()
        self.lua_inc = lua_inc or (self.root / "luadec/lua-5.1/src").resolve()

    def generate_profile(self,
                         seed_hex: Optional[str] = None,
                         name: Optional[str] = None,
                         preset: Optional[str] = None,
                         endianness: Optional[str] = None,
                         bitfield_layout: Optional[str] = None,
                         instruction_xor: bool = True,
                         string_xor: bool = True,
                         strip_debug: bool = False,
                         envelope: bool = False,
                         auth_hmac: bool = False,
                         out_dir: Optional[Path] = None) -> FormatProfile:
        seed = seed_hex if seed_hex else make_seed()
        seed_bytes = bytes.fromhex(seed)
        seed_int = int.from_bytes(seed_bytes, "big")
        rng = Random(seed_int)

        gen = LuaFormatGenerator(rng, seed)
        profile = gen.generate(
            name=name,
            endianness=endianness,
            bitfield_layout=bitfield_layout,
            instruction_xor=instruction_xor,
            string_xor=string_xor,
            strip_debug=strip_debug,
            envelope=envelope,
            auth_hmac=auth_hmac,
            preset=preset
        )

        if out_dir:
            out_dir = Path(out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)

            # 1. Spec doc
            doc_md = MarkdownDocEmitter(profile).emit()
            (out_dir / "LUA_FORMAT_SPEC.md").write_text(doc_md)

            # 2. JSON & YAML manifest
            manifest = ManifestEmitter(profile)
            (out_dir / "format_manifest.json").write_text(manifest.emit_json())
            (out_dir / "format_profile.yaml").write_text(manifest.emit_yaml())

            # 3. Standalone C runner
            c_runner = CRunnerEmitter(profile).emit()
            (out_dir / "lua_custom_runner.c").write_text(c_runner)

            # 4. Pure Lua loader
            lua_loader = LuaLoaderEmitter(profile).emit()
            (out_dir / "loader.lua").write_text(lua_loader)

        return profile

    def load_profile(self, path: Path) -> FormatProfile:
        content = path.read_text()
        if path.suffix in (".json",):
            data = json.loads(content)
            return FormatProfile.from_dict(data)
        elif path.suffix in (".yaml", ".yml"):
            # Simple YAML parser or JSON fallback
            try:
                import yaml
                data = yaml.safe_load(content)
                if "format_profile" in data:
                    data = data["format_profile"]
                return FormatProfile.from_dict(data)
            except ImportError:
                # Fallback to json if json inside
                return FormatProfile.from_dict(json.loads(content))
        else:
            return FormatProfile.from_dict(json.loads(content))

    def encode_file(self,
                    input_file: Path,
                    output_file: Path,
                    profile: FormatProfile) -> Path:
        input_path = Path(input_file)
        output_path = Path(output_file)

        # If input is .lua source code, compile with luac first
        if input_path.suffix == ".lua":
            with tempfile.NamedTemporaryFile(suffix=".luac", delete=False) as tmp_f:
                tmp_luac = Path(tmp_f.name)
            try:
                subprocess.run([str(self.luac_bin), "-o", str(tmp_luac), str(input_path)], check=True)
                std_bytes = tmp_luac.read_bytes()
            finally:
                tmp_luac.unlink(missing_ok=True)
        else:
            std_bytes = input_path.read_bytes()

        chunk = StandardLua51Reader(std_bytes).read_chunk()
        prop_bytes = ProprietaryLuaWriter(profile).write_chunk(chunk)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(prop_bytes)
        return output_path

    def decode_file(self,
                    input_file: Path,
                    output_file: Path,
                    profile: FormatProfile) -> Path:
        input_path = Path(input_file)
        output_path = Path(output_file)

        prop_bytes = input_path.read_bytes()
        chunk = ProprietaryLuaReader(prop_bytes, profile).read_chunk()

        std_writer = StandardLua51Writer(size_size_t=profile.size_size_t)
        std_bytes = std_writer.write_chunk(chunk)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(std_bytes)
        return output_path

    def build_c_runner(self,
                       c_source_path: Path,
                       binary_output_path: Path) -> Path:
        binary_output_path = Path(binary_output_path)
        binary_output_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            "gcc", "-O2",
            f"-I{self.lua_inc}",
            str(c_source_path),
            str(self.liblua_a),
            "-lm",
            "-o", str(binary_output_path)
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"C runner compilation failed:\n{res.stderr}")
        return binary_output_path

    def verify_pipeline(self,
                        sample_lua_code: Optional[str] = None,
                        profile: Optional[FormatProfile] = None) -> Dict[str, object]:
        if not profile:
            profile = self.generate_profile(preset="hardened")

        code = sample_lua_code or """
function fib(n)
    if n <= 1 then return n end
    return fib(n - 1) + fib(n - 2)
end
local tab = { message = "Protected Lua", num = fib(10) }
print(tab.message .. " - Result: " .. tostring(tab.num))
"""
        results = {}

        with tempfile.TemporaryDirectory() as tmp_dir_str:
            tmp_dir = Path(tmp_dir_str)
            src_lua = tmp_dir / "sample.lua"
            std_luac = tmp_dir / "sample.luac"
            prop_luc = tmp_dir / "sample.luc"
            decoded_luac = tmp_dir / "recovered.luac"
            runner_c = tmp_dir / "runner.c"
            runner_bin = tmp_dir / "runner"
            loader_lua = tmp_dir / "loader.lua"

            src_lua.write_text(code)

            # 1. Standard compilation
            subprocess.run([str(self.luac_bin), "-o", str(std_luac), str(src_lua)], check=True)

            # 2. Check standard luadec works on standard luac
            res_std_luadec = subprocess.run(
                [str(self.luadec_bin), str(std_luac)],
                capture_output=True, text=True, errors="replace"
            )
            results["standard_luadec_success"] = (res_std_luadec.returncode == 0)
            results["standard_luadec_output"] = res_std_luadec.stdout.strip()

            # 3. Protect into proprietary format
            self.encode_file(std_luac, prop_luc, profile)
            results["proprietary_file_size"] = prop_luc.stat().st_size

            # 4. Attempt luadec on proprietary format -> MUST FAIL!
            res_prop_luadec = subprocess.run(
                [str(self.luadec_bin), str(prop_luc)],
                capture_output=True, text=True, errors="replace"
            )
            results["anti_luadec_protected"] = (res_prop_luadec.returncode != 0)
            results["anti_luadec_returncode"] = res_prop_luadec.returncode
            results["anti_luadec_error_msg"] = res_prop_luadec.stderr.strip()

            # 5. Build and run native C runner
            runner_c.write_text(CRunnerEmitter(profile).emit())
            self.build_c_runner(runner_c, runner_bin)
            res_c_runner = subprocess.run([str(runner_bin), str(prop_luc)], capture_output=True, text=True)
            results["c_runner_success"] = (res_c_runner.returncode == 0)
            results["c_runner_stdout"] = res_c_runner.stdout.strip()

            # 6. Run with pure Lua loader
            loader_lua.write_text(LuaLoaderEmitter(profile).emit())
            res_lua_loader = subprocess.run(
                [str(self.lua_bin), str(loader_lua), str(prop_luc)],
                capture_output=True, text=True
            )
            results["lua_loader_success"] = (res_lua_loader.returncode == 0)
            results["lua_loader_stdout"] = res_lua_loader.stdout.strip()

            # 7. Authorized Decode
            self.decode_file(prop_luc, decoded_luac, profile)
            res_recovered = subprocess.run([str(self.lua_bin), str(decoded_luac)], capture_output=True, text=True)
            results["recovered_execution_success"] = (res_recovered.returncode == 0)
            results["recovered_stdout"] = res_recovered.stdout.strip()

            # Check matching output
            results["output_match"] = (
                results["c_runner_stdout"] == results["lua_loader_stdout"] == results["recovered_stdout"]
            )

        return results
