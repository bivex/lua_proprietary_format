"""
Standard Lua 5.1 Bytecode (.luac) Binary Reader and Writer.
"""

import struct
from typing import Optional
from lua_format.domain.models import (
    ChunkHeader, Constant, Instruction, LocVar, LuaChunk, Proto, StandardConstantTag
)
from lua_format.codecs.instruction_codec import (
    decode_standard_instruction, encode_standard_instruction
)


class StandardLua51Reader:
    """Reader for official Lua 5.1 compiled binary bytecode."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0
        self.endian = "<"
        self.size_int = 4
        self.size_size_t = 8
        self.size_instruction = 4
        self.size_number = 8

    def _read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(f"Unexpected EOF while reading {n} bytes at offset {self.pos}")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _read_byte(self) -> int:
        return self._read_bytes(1)[0]

    def _read_int(self) -> int:
        b = self._read_bytes(self.size_int)
        fmt = f"{self.endian}i" if self.size_int == 4 else f"{self.endian}q"
        return struct.unpack(fmt, b)[0]

    def _read_size_t(self) -> int:
        b = self._read_bytes(self.size_size_t)
        fmt = f"{self.endian}I" if self.size_size_t == 4 else f"{self.endian}Q"
        return struct.unpack(fmt, b)[0]

    def _read_number(self) -> float:
        b = self._read_bytes(self.size_number)
        fmt = f"{self.endian}d" if self.size_number == 8 else f"{self.endian}f"
        return struct.unpack(fmt, b)[0]

    def _read_string(self) -> Optional[str]:
        size = self._read_size_t()
        if size == 0:
            return None
        raw = self._read_bytes(size)
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    def read_header(self) -> ChunkHeader:
        sig = self._read_bytes(4)
        if sig != b"\x1bLua":
            raise ValueError(f"Invalid Lua signature: {sig!r} (expected b'\\x1bLua')")
        
        version = self._read_byte()
        if version != 0x51:
            raise ValueError(f"Unsupported Lua version: 0x{version:02X} (expected 0x51)")

        format_ver = self._read_byte()
        endian_byte = self._read_byte()
        self.endian = "<" if endian_byte == 1 else ">"
        
        self.size_int = self._read_byte()
        self.size_size_t = self._read_byte()
        self.size_instruction = self._read_byte()
        self.size_number = self._read_byte()
        integral = self._read_byte()

        return ChunkHeader(
            signature=sig,
            version=version,
            format_version=format_ver,
            endianness=endian_byte,
            size_int=self.size_int,
            size_size_t=self.size_size_t,
            size_instruction=self.size_instruction,
            size_lua_number=self.size_number,
            integral_flag=integral
        )

    def read_proto(self, parent_source: Optional[str] = None) -> Proto:
        source = self._read_string()
        if source is None and parent_source:
            source = parent_source
        elif source is None:
            source = ""

        line_defined = self._read_int()
        last_line_defined = self._read_int()
        nups = self._read_byte()
        numparams = self._read_byte()
        is_vararg = self._read_byte()
        maxstacksize = self._read_byte()

        # Code
        size_code = self._read_int()
        code = []
        for _ in range(size_code):
            raw_ins = struct.unpack(f"{self.endian}I", self._read_bytes(4))[0]
            ins = decode_standard_instruction(raw_ins)
            code.append(ins)

        # Constants
        size_k = self._read_int()
        constants = []
        for _ in range(size_k):
            tag = self._read_byte()
            if tag == StandardConstantTag.TNIL:
                val = None
            elif tag == StandardConstantTag.TBOOLEAN:
                val = (self._read_byte() != 0)
            elif tag == StandardConstantTag.TNUMBER:
                val = self._read_number()
            elif tag == StandardConstantTag.TSTRING:
                val = self._read_string()
            else:
                raise ValueError(f"Unknown constant type tag {tag} at offset {self.pos}")
            constants.append(Constant(tag=tag, value=val))

        # Sub-protos
        size_p = self._read_int()
        subprotos = []
        for _ in range(size_p):
            subprotos.append(self.read_proto(parent_source=source))

        # Debug info
        size_lineinfo = self._read_int()
        lineinfo = [self._read_int() for _ in range(size_lineinfo)]

        size_locvars = self._read_int()
        locvars = []
        for _ in range(size_locvars):
            vname = self._read_string() or ""
            startpc = self._read_int()
            endpc = self._read_int()
            locvars.append(LocVar(varname=vname, startpc=startpc, endpc=endpc))

        size_upvalues = self._read_int()
        upvalues = [self._read_string() or "" for _ in range(size_upvalues)]

        return Proto(
            source=source,
            linedefined=line_defined,
            lastlinedefined=last_line_defined,
            nups=nups,
            numparams=numparams,
            is_vararg=is_vararg,
            maxstacksize=maxstacksize,
            code=code,
            constants=constants,
            subprotos=subprotos,
            lineinfo=lineinfo,
            locvars=locvars,
            upvalues=upvalues
        )

    def read_chunk(self) -> LuaChunk:
        hdr = self.read_header()
        proto = self.read_proto()
        return LuaChunk(header=hdr, main_proto=proto)


class StandardLua51Writer:
    """Writer for official Lua 5.1 compiled binary bytecode."""

    def __init__(self, size_size_t: int = 8, endian: str = "<") -> None:
        self.size_size_t = size_size_t
        self.endian = endian
        self.out = bytearray()

    def _write_bytes(self, b: bytes) -> None:
        self.out.extend(b)

    def _write_byte(self, v: int) -> None:
        self.out.append(v & 0xFF)

    def _write_int(self, v: int) -> None:
        self.out.extend(struct.pack(f"{self.endian}i", v))

    def _write_size_t(self, v: int) -> None:
        fmt = f"{self.endian}I" if self.size_size_t == 4 else f"{self.endian}Q"
        self.out.extend(struct.pack(fmt, v))

    def _write_number(self, v: float) -> None:
        self.out.extend(struct.pack(f"{self.endian}d", float(v)))

    def _write_string(self, s: Optional[str]) -> None:
        if s is None or s == "":
            self._write_size_t(0)
        else:
            raw = s.encode("utf-8") + b"\x00"
            self._write_size_t(len(raw))
            self._write_bytes(raw)

    def write_header(self, header: Optional[ChunkHeader] = None) -> None:
        self._write_bytes(b"\x1bLua")
        self._write_byte(0x51)
        self._write_byte(0)
        endian_byte = header.endianness if header else (1 if self.endian == "<" else 0)
        self._write_byte(endian_byte)
        self._write_byte(header.size_int if header else 4)
        self._write_byte(self.size_size_t)
        self._write_byte(header.size_instruction if header else 4)
        self._write_byte(header.size_lua_number if header else 8)
        self._write_byte(header.integral_flag if header else 0)

    def write_proto(self, p: Proto, parent_source: Optional[str] = None, strip: bool = False) -> None:
        src = None if (p.source == parent_source or strip) else p.source
        self._write_string(src)
        self._write_int(p.linedefined)
        self._write_int(p.lastlinedefined)
        self._write_byte(p.nups)
        self._write_byte(p.numparams)
        self._write_byte(p.is_vararg)
        self._write_byte(p.maxstacksize)

        # Code
        self._write_int(len(p.code))
        for ins in p.code:
            raw = encode_standard_instruction(ins, lua_version="5.1")
            self.out.extend(struct.pack(f"{self.endian}I", raw))

        # Constants
        self._write_int(len(p.constants))
        for k in p.constants:
            self._write_byte(k.tag)
            if k.tag == StandardConstantTag.TNIL:
                pass
            elif k.tag == StandardConstantTag.TBOOLEAN:
                self._write_byte(1 if k.value else 0)
            elif k.tag == StandardConstantTag.TNUMBER:
                self._write_number(k.value)
            elif k.tag == StandardConstantTag.TSTRING:
                self._write_string(k.value)

        # Subprotos
        self._write_int(len(p.subprotos))
        for sub in p.subprotos:
            self.write_proto(sub, parent_source=p.source, strip=strip)

        # Debug
        if strip:
            self._write_int(0)  # lineinfo
            self._write_int(0)  # locvars
            self._write_int(0)  # upvalues
        else:
            self._write_int(len(p.lineinfo))
            for line in p.lineinfo:
                self._write_int(line)

            self._write_int(len(p.locvars))
            for lv in p.locvars:
                self._write_string(lv.varname)
                self._write_int(lv.startpc)
                self._write_int(lv.endpc)

            self._write_int(len(p.upvalues))
            for uv in p.upvalues:
                self._write_string(uv)

    def write_chunk(self, chunk: LuaChunk, strip: bool = False) -> bytes:
        self.out = bytearray()
        self.write_header(chunk.header)
        self.write_proto(chunk.main_proto, strip=strip)
        return bytes(self.out)
