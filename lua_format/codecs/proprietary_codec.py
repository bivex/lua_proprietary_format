"""
Proprietary Lua Bytecode Reader and Writer.
Applies custom magic, opcode mapping, bitfield layouts, XOR masks, constant tag shuffling,
section reordering, string obfuscation, and envelope framing.
"""

import struct
from typing import Optional
from lua_format.domain.models import (
    ChunkHeader, Constant, Instruction, LocVar, LuaChunk, Proto, StandardConstantTag
)
from lua_format.domain.profile import FormatProfile
from lua_format.codecs.instruction_codec import (
    decode_proprietary_instruction, encode_proprietary_instruction
)
from lua_format.codecs.envelope_codec import unwrap_envelope, wrap_envelope


class ProprietaryLuaWriter:
    """Serializes Lua AST into custom proprietary binary chunk."""

    def __init__(self, profile: FormatProfile) -> None:
        self.p = profile
        self.endian = "<" if profile.endianness == "little" else ">"
        self.out = bytearray()

    def _write_bytes(self, b: bytes) -> None:
        self.out.extend(b)

    def _write_byte(self, v: int) -> None:
        self.out.append(v & 0xFF)

    def _write_int(self, v: int) -> None:
        self.out.extend(struct.pack(f"{self.endian}i", v))

    def _write_size_t(self, v: int) -> None:
        fmt = f"{self.endian}I" if self.p.size_size_t == 4 else f"{self.endian}Q"
        self.out.extend(struct.pack(fmt, v))

    def _write_number(self, v: float) -> None:
        self.out.extend(struct.pack(f"{self.endian}d", float(v)))

    def _encode_string(self, s: Optional[str]) -> None:
        if s is None or s == "":
            self._write_size_t(0)
            return

        raw = s.encode("utf-8") + b"\x00"
        if self.p.string_encoding == "xor" and self.p.string_xor_key != 0:
            raw = bytes(b ^ self.p.string_xor_key for b in raw)

        self._write_size_t(len(raw))
        self._write_bytes(raw)

    def write_header(self) -> None:
        self._write_bytes(self.p.magic)
        self._write_byte(self.p.version)
        self._write_byte(self.p.format_version)
        self._write_byte(1 if self.p.endianness == "little" else 0)
        self._write_byte(self.p.size_int)
        self._write_byte(self.p.size_size_t)
        self._write_byte(self.p.size_instruction)
        self._write_byte(self.p.size_lua_number)
        self._write_byte(self.p.integral)

    def write_code_section(self, proto: Proto) -> None:
        self._write_int(len(proto.code))
        for ins in proto.code:
            encoded_u32 = encode_proprietary_instruction(
                ins=ins,
                layout=self.p.bitfield_layout,
                opcode_map=self.p.opcode_map,
                xor_mask=self.p.instruction_xor_mask,
                lua_version=self.p.lua_version
            )
            self.out.extend(struct.pack(f"{self.endian}I", encoded_u32))

    def write_constants_section(self, proto: Proto) -> None:
        self._write_int(len(proto.constants))
        for k in proto.constants:
            prop_tag = self.p.const_tag_map.get(k.tag, k.tag)
            self._write_byte(prop_tag)
            if k.tag == StandardConstantTag.TNIL:
                pass
            elif k.tag == StandardConstantTag.TBOOLEAN:
                self._write_byte(1 if k.value else 0)
            elif k.tag == StandardConstantTag.TNUMBER:
                self._write_number(k.value)
            elif k.tag == StandardConstantTag.TSTRING:
                self._encode_string(k.value)

    def write_subprotos_section(self, proto: Proto) -> None:
        self._write_int(len(proto.subprotos))
        for sub in proto.subprotos:
            self.write_proto(sub, parent_source=proto.source)

    def write_debug_section(self, proto: Proto) -> None:
        if self.p.strip_debug:
            self._write_int(0)  # lineinfo
            self._write_int(0)  # locvars
            self._write_int(0)  # upvalues
        else:
            self._write_int(len(proto.lineinfo))
            for line in proto.lineinfo:
                self._write_int(line)

            self._write_int(len(proto.locvars))
            for lv in proto.locvars:
                self._encode_string(lv.varname)
                self._write_int(lv.startpc)
                self._write_int(lv.endpc)

            self._write_int(len(proto.upvalues))
            for uv in proto.upvalues:
                self._encode_string(uv)

    def write_header_info_section(self, proto: Proto, parent_source: Optional[str]) -> None:
        src = None if (proto.source == parent_source or self.p.strip_debug) else proto.source
        self._encode_string(src)
        self._write_int(proto.linedefined)
        self._write_int(proto.lastlinedefined)
        self._write_byte(proto.nups)
        self._write_byte(proto.numparams)
        self._write_byte(proto.is_vararg)
        self._write_byte(proto.maxstacksize)

    def write_proto(self, proto: Proto, parent_source: Optional[str] = None) -> None:
        for section in self.p.proto_section_order:
            if section == "header_info":
                self.write_header_info_section(proto, parent_source)
            elif section == "code":
                self.write_code_section(proto)
            elif section == "constants":
                self.write_constants_section(proto)
            elif section == "subprotos":
                self.write_subprotos_section(proto)
            elif section == "debug":
                self.write_debug_section(proto)

    def write_chunk(self, chunk: LuaChunk) -> bytes:
        self.out = bytearray()
        self.write_header()
        self.write_proto(chunk.main_proto)
        raw_payload = bytes(self.out)

        # Wrap in 22-byte protocol envelope if configured
        if self.p.envelope.enabled:
            return wrap_envelope(raw_payload, self.p.envelope)
        return raw_payload


class ProprietaryLuaReader:
    """Deserializes custom proprietary binary chunk back into Lua AST."""

    def __init__(self, data: bytes, profile: FormatProfile) -> None:
        # Unwrap 22-byte envelope if present
        payload, _ = unwrap_envelope(data, profile.envelope)
        self.data = payload
        self.p = profile
        self.pos = 0
        self.endian = "<" if profile.endianness == "little" else ">"

    def _read_bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError(f"Unexpected EOF while reading {n} bytes at offset {self.pos}")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _read_byte(self) -> int:
        return self._read_bytes(1)[0]

    def _read_int(self) -> int:
        b = self._read_bytes(self.p.size_int)
        fmt = f"{self.endian}i" if self.p.size_int == 4 else f"{self.endian}q"
        return struct.unpack(fmt, b)[0]

    def _read_size_t(self) -> int:
        b = self._read_bytes(self.p.size_size_t)
        fmt = f"{self.endian}I" if self.p.size_size_t == 4 else f"{self.endian}Q"
        return struct.unpack(fmt, b)[0]

    def _read_number(self) -> float:
        b = self._read_bytes(self.p.size_lua_number)
        fmt = f"{self.endian}d" if self.p.size_lua_number == 8 else f"{self.endian}f"
        return struct.unpack(fmt, b)[0]

    def _decode_string(self) -> Optional[str]:
        size = self._read_size_t()
        if size == 0:
            return None
        raw = bytearray(self._read_bytes(size))
        if self.p.string_encoding == "xor" and self.p.string_xor_key != 0:
            raw = bytearray(b ^ self.p.string_xor_key for b in raw)
        if raw.endswith(b"\x00"):
            raw = raw[:-1]
        return raw.decode("utf-8", errors="replace")

    def read_header(self) -> ChunkHeader:
        sig = self._read_bytes(len(self.p.magic))
        if sig != self.p.magic:
            raise ValueError(f"Proprietary signature mismatch: {sig!r} (expected {self.p.magic!r})")

        ver = self._read_byte()
        fmt_ver = self._read_byte()
        endian_byte = self._read_byte()
        self.endian = "<" if endian_byte == 1 else ">"
        
        s_int = self._read_byte()
        s_sizet = self._read_byte()
        s_ins = self._read_byte()
        s_num = self._read_byte()
        integral = self._read_byte()

        return ChunkHeader(
            signature=sig,
            version=ver,
            format_version=fmt_ver,
            endianness=endian_byte,
            size_int=s_int,
            size_size_t=s_sizet,
            size_instruction=s_ins,
            size_lua_number=s_num,
            integral_flag=integral
        )

    def read_code_section(self, proto: Proto) -> None:
        size_code = self._read_int()
        code = []
        for _ in range(size_code):
            raw_u32 = struct.unpack(f"{self.endian}I", self._read_bytes(4))[0]
            ins = decode_proprietary_instruction(
                raw_u32=raw_u32,
                layout=self.p.bitfield_layout,
                inv_opcode_map=self.p.inv_opcode_map,
                xor_mask=self.p.instruction_xor_mask,
                lua_version=self.p.lua_version
            )
            code.append(ins)
        proto.code = code

    def read_constants_section(self, proto: Proto) -> None:
        size_k = self._read_int()
        constants = []
        for _ in range(size_k):
            prop_tag = self._read_byte()
            std_tag = self.p.inv_const_tag_map.get(prop_tag, prop_tag)
            if std_tag == StandardConstantTag.TNIL:
                val = None
            elif std_tag == StandardConstantTag.TBOOLEAN:
                val = (self._read_byte() != 0)
            elif std_tag == StandardConstantTag.TNUMBER:
                val = self._read_number()
            elif std_tag == StandardConstantTag.TSTRING:
                val = self._decode_string()
            else:
                raise ValueError(f"Unknown proprietary constant tag {prop_tag} at offset {self.pos}")
            constants.append(Constant(tag=std_tag, value=val))
        proto.constants = constants

    def read_subprotos_section(self, proto: Proto) -> None:
        size_p = self._read_int()
        subprotos = []
        for _ in range(size_p):
            sub = Proto()
            self.read_proto_body(sub, parent_source=proto.source)
            subprotos.append(sub)
        proto.subprotos = subprotos

    def read_debug_section(self, proto: Proto) -> None:
        size_lineinfo = self._read_int()
        proto.lineinfo = [self._read_int() for _ in range(size_lineinfo)]

        size_locvars = self._read_int()
        locvars = []
        for _ in range(size_locvars):
            vname = self._decode_string() or ""
            startpc = self._read_int()
            endpc = self._read_int()
            locvars.append(LocVar(varname=vname, startpc=startpc, endpc=endpc))
        proto.locvars = locvars

        size_upvalues = self._read_int()
        proto.upvalues = [self._decode_string() or "" for _ in range(size_upvalues)]

    def read_header_info_section(self, proto: Proto, parent_source: Optional[str]) -> None:
        source = self._decode_string()
        if source is None and parent_source:
            source = parent_source
        elif source is None:
            source = ""
        proto.source = source
        proto.linedefined = self._read_int()
        proto.lastlinedefined = self._read_int()
        proto.nups = self._read_byte()
        proto.numparams = self._read_byte()
        proto.is_vararg = self._read_byte()
        proto.maxstacksize = self._read_byte()

    def read_proto_body(self, proto: Proto, parent_source: Optional[str] = None) -> None:
        for section in self.p.proto_section_order:
            if section == "header_info":
                self.read_header_info_section(proto, parent_source)
            elif section == "code":
                self.read_code_section(proto)
            elif section == "constants":
                self.read_constants_section(proto)
            elif section == "subprotos":
                self.read_subprotos_section(proto)
            elif section == "debug":
                self.read_debug_section(proto)

    def read_chunk(self) -> LuaChunk:
        hdr = self.read_header()
        proto = Proto()
        self.read_proto_body(proto)
        return LuaChunk(header=hdr, main_proto=proto)
