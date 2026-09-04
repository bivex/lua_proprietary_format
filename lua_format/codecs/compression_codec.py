"""
Apultra (aPLib) Compression & Decompression Codec.
Provides optimal LZ compression using the apultra tool,
and pure-Python / C decompressors for unpacking in memory.
"""

import os
from pathlib import Path
import subprocess
import tempfile
from typing import Optional


class ApultraCodec:
    """Codec for compressing and decompressing payloads using apultra (aPLib)."""

    def __init__(self, apultra_bin: Optional[Path] = None) -> None:
        if apultra_bin and Path(apultra_bin).exists():
            self.bin = Path(apultra_bin).resolve()
        else:
            # Look in repository workspace
            workspace_root = Path(__file__).resolve().parent.parent.parent
            candidate = workspace_root / "apultra" / "apultra"
            if candidate.exists():
                self.bin = candidate
            else:
                self.bin = None

    def _ensure_binary(self) -> Path:
        if self.bin and self.bin.exists():
            return self.bin
        
        # Try compiling if source directory exists
        workspace_root = Path(__file__).resolve().parent.parent.parent
        apultra_dir = workspace_root / "apultra"
        if apultra_dir.exists() and (apultra_dir / "Makefile").exists():
            subprocess.run(["make", "-C", str(apultra_dir)], check=True, capture_output=True)
            candidate = apultra_dir / "apultra"
            if candidate.exists():
                self.bin = candidate
                return self.bin
        raise RuntimeError("apultra binary not found and could not be built from apultra/ directory.")

    def compress(self, data: bytes, max_window: Optional[int] = None) -> bytes:
        """Compress data bytes with apultra."""
        if not data:
            return b""
        
        ap_bin = self._ensure_binary()
        with tempfile.TemporaryDirectory() as td:
            t = Path(td)
            in_file = t / "input.bin"
            out_file = t / "output.ap"
            in_file.write_bytes(data)

            cmd = [str(ap_bin)]
            if max_window:
                cmd.extend(["-w", str(max_window)])
            cmd.extend([str(in_file), str(out_file)])

            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"apultra compression failed: {res.stderr}")
            
            return out_file.read_bytes()

    def decompress(self, data: bytes) -> bytes:
        """Decompress apultra (aPLib) compressed bytes using pure Python algorithm."""
        if not data:
            return b""
        
        return self.decompress_python(data)

    @staticmethod
    def decompress_python(data: bytes) -> bytes:
        """Pure-Python aPLib (apultra) decompressor implementation."""
        in_pos = 0
        in_len = len(data)
        if in_len == 0:
            return b""

        out_bytes = bytearray()
        cur_bit_mask = 0
        bits = 0
        follows_literal = 3
        rep_match_offset = 0

        def read_byte() -> int:
            nonlocal in_pos
            if in_pos >= in_len:
                raise EOFError("Unexpected EOF in apultra stream")
            b = data[in_pos]
            in_pos += 1
            return b

        def read_bit() -> int:
            nonlocal cur_bit_mask, bits
            if cur_bit_mask == 0:
                if in_pos >= in_len:
                    return -1
                bits = read_byte()
                cur_bit_mask = 128
            bit = 1 if (bits & 128) else 0
            bits = (bits << 1) & 0xFF
            cur_bit_mask >>= 1
            return bit

        def read_4bits() -> int:
            val = 0
            for i in range(3, -1, -1):
                bit = read_bit()
                if bit < 0:
                    raise EOFError("Unexpected EOF reading 4bits")
                val |= (bit << i)
            return val

        def read_gamma2() -> int:
            v = 1
            while True:
                b2 = read_bit()
                if b2 < 0:
                    raise EOFError("Unexpected EOF in gamma2 bit")
                v = (v << 1) | b2
                bit = read_bit()
                if bit < 0:
                    raise EOFError("Unexpected EOF in gamma2 flag")
                if not bit:
                    break
            return v

        # First byte is always literal
        out_bytes.append(read_byte())

        while True:
            res = read_bit()
            if res < 0:
                break

            if res == 0:
                # 0: Literal
                out_bytes.append(read_byte())
                follows_literal = 3
            else:
                res = read_bit()
                if res < 0:
                    break

                if res == 0:
                    # 10: 8+n bits offset match
                    offset_hi = read_gamma2()
                    offset_hi -= follows_literal
                    if offset_hi >= 0:
                        lo = read_byte()
                        match_offset = (offset_hi << 8) | lo
                        match_len = read_gamma2()
                        if match_offset < 128 or match_offset >= 32000:
                            match_len += 2
                        elif match_offset >= 1280:
                            match_len += 1
                        rep_match_offset = match_offset
                    else:
                        match_offset = rep_match_offset
                        match_len = read_gamma2()

                    follows_literal = 2
                    for _ in range(match_len):
                        src_pos = len(out_bytes) - match_offset
                        if src_pos < 0:
                            raise ValueError("Invalid match offset in apultra stream")
                        out_bytes.append(out_bytes[src_pos])
                else:
                    res = read_bit()
                    if res < 0:
                        break

                    if res == 0:
                        # 110: 7-bit offset + 1-bit length
                        cmd = read_byte()
                        if cmd == 0:
                            # EOD marker
                            break
                        match_offset = cmd >> 1
                        match_len = (cmd & 1) + 2
                        follows_literal = 2
                        rep_match_offset = match_offset
                        for _ in range(match_len):
                            src_pos = len(out_bytes) - match_offset
                            if src_pos < 0:
                                raise ValueError("Invalid 7-bit match offset")
                            out_bytes.append(out_bytes[src_pos])
                    else:
                        # 111: 4-bit offset
                        offset_4b = read_4bits()
                        follows_literal = 3
                        if offset_4b != 0:
                            src_pos = len(out_bytes) - offset_4b
                            if src_pos < 0:
                                raise ValueError("Invalid 4-bit match offset")
                            out_bytes.append(out_bytes[src_pos])
                        else:
                            out_bytes.append(0)

        return bytes(out_bytes)
