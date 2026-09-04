"""
Command-line Interface for Lua Proprietary Format Generator and Runtime System.
"""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from lua_format.application.format_service import LuaFormatService
from lua_format.domain.generator import make_seed
from lua_format.domain.profile import SUPPORTED_BITFIELD_LAYOUTS


def print_banner():
    print("""
  ==================================================================
   🔒 Lua Proprietary Format Generator & Anti-Decompiler Suite (VIQ)
   Based on gen_random_protocol (Hexagonal Architecture)
  ==================================================================
""")


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="gen_lua_format",
        description="Proprietary Lua 5.1 Bytecode Format Generator & Anti-Luadec Security Suite"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: generate
    p_gen = subparsers.add_parser("generate", help="Generate a new proprietary Lua format profile")
    p_gen.add_argument("-n", "--name", type=str, help="Format profile name (e.g. VIPER_LUA)")
    p_gen.add_argument("--seed", type=str, help="32-hex character seed for reproducibility")
    p_gen.add_argument("--preset", choices=["popcap_style", "hardened", "stealth"], help="Format security preset")
    p_gen.add_argument("--layout", choices=SUPPORTED_BITFIELD_LAYOUTS, help="Instruction bitfield layout")
    p_gen.add_argument("--no-xor", action="store_true", help="Disable instruction XOR masking")
    p_gen.add_argument("--envelope", action="store_true", help="Wrap chunk in 22-byte protocol framing")
    p_gen.add_argument("--auth-hmac", action="store_true", help="Enable HMAC-SHA256 frame authentication")
    p_gen.add_argument("-o", "--output-dir", type=Path, default=Path("out/lua_format"), help="Output directory")
    p_gen.add_argument("--build-runner", action="store_true", help="Compile native C runner executable")

    # Command: protect / encode
    p_enc = subparsers.add_parser("protect", help="Encode .lua or .luac into proprietary format")
    p_enc.add_argument("input", type=Path, help="Input .lua source or .luac standard bytecode")
    p_enc.add_argument("-o", "--output", type=Path, required=True, help="Output proprietary .luc file")
    p_enc.add_argument("--profile", type=Path, help="Path to format_profile.json or .yaml")
    p_enc.add_argument("--preset", choices=["popcap_style", "hardened", "stealth"], help="Preset if no profile file")
    p_enc.add_argument("--seed", type=str, help="Seed if no profile file")

    # Command: unprotect / decode
    p_dec = subparsers.add_parser("unprotect", help="Decode proprietary format back to standard .luac")
    p_dec.add_argument("input", type=Path, help="Input proprietary .luc file")
    p_dec.add_argument("-o", "--output", type=Path, required=True, help="Output standard .luac file")
    p_dec.add_argument("--profile", type=Path, help="Path to format_profile.json or .yaml")
    p_dec.add_argument("--preset", choices=["popcap_style", "hardened", "stealth"], help="Preset if no profile file")
    p_dec.add_argument("--seed", type=str, help="Seed if no profile file")

    # Command: run
    p_run = subparsers.add_parser("run", help="Execute proprietary bytecode via Pure Loader or Native Runner")
    p_run.add_argument("input", type=Path, help="Input proprietary .luc file")
    p_run.add_argument("--loader", type=Path, help="Path to generated loader.lua (or uses embedded profile)")
    p_run.add_argument("--runner", type=Path, help="Path to compiled native C runner binary")
    p_run.add_argument("args", nargs="*", help="Arguments to pass to script")

    # Command: verify
    p_ver = subparsers.add_parser("verify", help="Run automated verification pipeline against luadec and check execution")
    p_ver.add_argument("--input", type=Path, help="Optional custom Lua script to verify")
    p_ver.add_argument("--preset", choices=["popcap_style", "hardened", "stealth"], default="hardened", help="Preset")
    p_ver.add_argument("--seed", type=str, help="Entropy seed")

    args = parser.parse_args(argv)

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    service = LuaFormatService()

    if args.command == "generate":
        print_banner()
        profile = service.generate_profile(
            seed_hex=args.seed,
            name=args.name,
            preset=args.preset,
            bitfield_layout=args.layout,
            instruction_xor=not args.no_xor,
            envelope=args.envelope or args.auth_hmac,
            auth_hmac=args.auth_hmac,
            out_dir=args.output_dir
        )
        print(f"[+] Format Profile Generated : {profile.name}")
        print(f"    Seed                     : {profile.seed}")
        print(f"    Magic Signature          : {repr(profile.magic)} ({profile.magic.hex()})")
        print(f"    Bitfield Layout          : {profile.bitfield_layout}")
        print(f"    Instruction XOR Mask     : 0x{profile.instruction_xor_mask:08X}")
        print(f"    String Encoding          : {profile.string_encoding} (Key 0x{profile.string_xor_key:02X})")
        print(f"    22B Envelope Framing     : {'YES' if profile.envelope.enabled else 'NO'}")
        print(f"    Output Directory         : {args.output_dir.resolve()}\n")
        print(f"    Wrote: {args.output_dir / 'LUA_FORMAT_SPEC.md'}")
        print(f"    Wrote: {args.output_dir / 'format_manifest.json'}")
        print(f"    Wrote: {args.output_dir / 'format_profile.yaml'}")
        print(f"    Wrote: {args.output_dir / 'lua_custom_runner.c'}")
        print(f"    Wrote: {args.output_dir / 'loader.lua'}")

        if args.build_runner:
            runner_bin = args.output_dir / "lua_runner"
            service.build_c_runner(args.output_dir / "lua_custom_runner.c", runner_bin)
            print(f"    Compiled Native Runner   : {runner_bin}")

        print(f"\n[+] To encode a script: python gen_lua_format.py protect myscript.lua -o myscript.luc --profile {args.output_dir / 'format_profile.yaml'}")
        return 0

    elif args.command == "protect":
        if args.profile:
            profile = service.load_profile(args.profile)
        else:
            profile = service.generate_profile(seed_hex=args.seed, preset=args.preset or "hardened")
        
        out_path = service.encode_file(args.input, args.output, profile)
        print(f"[+] Protected '{args.input}' -> '{out_path}' ({out_path.stat().st_size} bytes)")
        return 0

    elif args.command == "unprotect":
        if args.profile:
            profile = service.load_profile(args.profile)
        else:
            profile = service.generate_profile(seed_hex=args.seed, preset=args.preset or "hardened")
        
        out_path = service.decode_file(args.input, args.output, profile)
        print(f"[+] Recovered '{args.input}' -> '{out_path}' ({out_path.stat().st_size} bytes)")
        return 0

    elif args.command == "verify":
        print_banner()
        print(f"[*] Running Automated Anti-Luadec and Multi-Runtime Verification...")
        custom_code = args.input.read_text() if args.input else None
        profile = service.generate_profile(seed_hex=args.seed, preset=args.preset)

        res = service.verify_pipeline(sample_lua_code=custom_code, profile=profile)

        print("\n" + "="*70)
        print(f" 1. Standard Lua Bytecode (.luac):")
        print(f"    - Decompilable by standard luadec  : {'YES (Vulnerable)' if res['standard_luadec_success'] else 'NO'}")
        print(f"\n 2. Proprietary Protected Bytecode (.luc):")
        print(f"    - File Size                       : {res['proprietary_file_size']} bytes")
        print(f"    - Standard Luadec Decompilation   : {'BLOCKED (PROTECTED ✅)' if res['anti_luadec_protected'] else 'FAILED ❌'}")
        print(f"    - Luadec Error Output             : {res['anti_luadec_error_msg']}")
        print(f"\n 3. Execution Verification:")
        print(f"    - Native C Runner Execution       : {'PASS ✅' if res['c_runner_success'] else 'FAIL ❌'}")
        print(f"    - Pure Lua In-Memory Loader       : {'PASS ✅' if res['lua_loader_success'] else 'FAIL ❌'}")
        print(f"    - Authorized Decoded Execution    : {'PASS ✅' if res['recovered_execution_success'] else 'FAIL ❌'}")
        print(f"    - Output Consistency              : {'MATCH 100% ✅' if res['output_match'] else 'MISMATCH ❌'}")
        print(f"\n    Program Output: {res['c_runner_stdout']}")
        print("="*70 + "\n")

        if res["anti_luadec_protected"] and res["output_match"]:
            print("[SUCCESS] All security & runtime guarantees verified!\n")
            return 0
        else:
            print("[FAILURE] Some checks failed!\n")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
