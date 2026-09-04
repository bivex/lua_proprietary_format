"""
Domain Entity and Value Object Models for Lua 5.1 and Lua 5.5 Bytecode and Custom Chunks.
"""

from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, List, Optional, Tuple, Union


# ==============================================================================
# Lua 5.1 Opcodes and Models
# ==============================================================================

class OpCode(IntEnum):
    OP_MOVE = 0
    OP_LOADK = 1
    OP_LOADBOOL = 2
    OP_LOADNIL = 3
    OP_GETUPVAL = 4
    OP_GETGLOBAL = 5
    OP_GETTABLE = 6
    OP_SETGLOBAL = 7
    OP_SETUPVAL = 8
    OP_SETTABLE = 9
    OP_NEWTABLE = 10
    OP_SELF = 11
    OP_ADD = 12
    OP_SUB = 13
    OP_MUL = 14
    OP_DIV = 15
    OP_MOD = 16
    OP_POW = 17
    OP_UNM = 18
    OP_NOT = 19
    OP_LEN = 20
    OP_CONCAT = 21
    OP_JMP = 22
    OP_EQ = 23
    OP_LT = 24
    OP_LE = 25
    OP_TEST = 26
    OP_TESTSET = 27
    OP_CALL = 28
    OP_TAILCALL = 29
    OP_RETURN = 30
    OP_FORLOOP = 31
    OP_FORPREP = 32
    OP_TFORLOOP = 33
    OP_SETLIST = 34
    OP_CLOSE = 35
    OP_CLOSURE = 36
    OP_VARARG = 37


NUM_OPCODES = 38

OPCODE_NAMES = [
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB",
    "MUL", "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP",
    "EQ", "LT", "LE", "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN",
    "FORLOOP", "FORPREP", "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG"
]

NAME_TO_OPCODE = {name: OpCode(i) for i, name in enumerate(OPCODE_NAMES)}


class OpMode(IntEnum):
    iABC = 0
    iABx = 1
    iAsBx = 2


class OpArgMask(IntEnum):
    OpArgN = 0  # argument is not used
    OpArgU = 1  # argument is used
    OpArgR = 2  # argument is a register or a jump offset
    OpArgK = 3  # argument is a constant or register/constant


OP_MODES: List[Tuple[int, int, OpArgMask, OpArgMask, OpMode]] = [
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iABC),   # OP_MOVE
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgN, OpMode.iABx),   # OP_LOADK
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgU, OpMode.iABC),   # OP_LOADBOOL
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iABC),   # OP_LOADNIL
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgN, OpMode.iABC),   # OP_GETUPVAL
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgN, OpMode.iABx),   # OP_GETGLOBAL
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgK, OpMode.iABC),   # OP_GETTABLE
    (0, 0, OpArgMask.OpArgK, OpArgMask.OpArgN, OpMode.iABx),   # OP_SETGLOBAL
    (0, 0, OpArgMask.OpArgU, OpArgMask.OpArgN, OpMode.iABC),   # OP_SETUPVAL
    (0, 0, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_SETTABLE
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgU, OpMode.iABC),   # OP_NEWTABLE
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgK, OpMode.iABC),   # OP_SELF
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_ADD
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_SUB
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_MUL
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_DIV
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_MOD
    (0, 1, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_POW
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iABC),   # OP_UNM
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iABC),   # OP_NOT
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iABC),   # OP_LEN
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgR, OpMode.iABC),   # OP_CONCAT
    (0, 0, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iAsBx),  # OP_JMP
    (1, 0, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_EQ
    (1, 0, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_LT
    (1, 0, OpArgMask.OpArgK, OpArgMask.OpArgK, OpMode.iABC),   # OP_LE
    (1, 1, OpArgMask.OpArgR, OpArgMask.OpArgU, OpMode.iABC),   # OP_TEST
    (1, 1, OpArgMask.OpArgR, OpArgMask.OpArgU, OpMode.iABC),   # OP_TESTSET
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgU, OpMode.iABC),   # OP_CALL
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgU, OpMode.iABC),   # OP_TAILCALL
    (0, 0, OpArgMask.OpArgU, OpArgMask.OpArgN, OpMode.iABC),   # OP_RETURN
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iAsBx),  # OP_FORLOOP
    (0, 1, OpArgMask.OpArgR, OpArgMask.OpArgN, OpMode.iAsBx),  # OP_FORPREP
    (1, 0, OpArgMask.OpArgN, OpArgMask.OpArgU, OpMode.iABC),   # OP_TFORLOOP
    (0, 0, OpArgMask.OpArgU, OpArgMask.OpArgU, OpMode.iABC),   # OP_SETLIST
    (0, 0, OpArgMask.OpArgN, OpArgMask.OpArgN, OpMode.iABC),   # OP_CLOSE
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgN, OpMode.iABx),   # OP_CLOSURE
    (0, 1, OpArgMask.OpArgU, OpArgMask.OpArgN, OpMode.iABC),   # OP_VARARG
]


# ==============================================================================
# Lua 5.5 Opcodes and Models
# ==============================================================================

LUA55_OPCODE_NAMES = [
    "MOVE", "LOADI", "LOADF", "LOADK", "LOADKX", "LOADFALSE", "LFALSESKIP",
    "LOADTRUE", "LOADNIL", "GETUPVAL", "SETUPVAL", "GETTABUP", "GETTABLE",
    "GETI", "GETFIELD", "SETTABUP", "SETTABLE", "SETI", "SETFIELD", "NEWTABLE",
    "SELF", "ADDI", "ADDK", "SUBK", "MULK", "MODK", "POWK", "DIVK", "IDIVK",
    "BANDK", "BORK", "BXORK", "SHRI", "SHLI", "ADD", "SUB", "MUL", "MOD", "POW",
    "DIV", "IDIV", "BAND", "BOR", "BXOR", "SHL", "SHR", "MMBIN", "MMBINI",
    "MMBINK", "UNM", "BNOT", "NOT", "LEN", "CONCAT", "CLOSE", "TBC", "JMP",
    "EQ", "LT", "LE", "EQK", "EQI", "LTI", "LEI", "GTI", "GEI", "TEST", "TESTSET",
    "CALL", "TAILCALL", "RETURN", "RETURN0", "RETURN1", "FORLOOP", "FORPREP",
    "TFORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARG",
    "VARARGPREP", "EXTRAARG", "GETVARG", "ERRNNIL"
]

NUM_OPCODES_55 = len(LUA55_OPCODE_NAMES)  # 85

LUA55_NAME_TO_OPCODE = {name: i for i, name in enumerate(LUA55_OPCODE_NAMES)}


class Lua55OpMode(IntEnum):
    iABC = 0
    iABx = 1
    iAsBx = 2
    iAx = 3
    isJ = 4
    ivABC = 5


LUA55_OPMODES: List[Lua55OpMode] = [
    Lua55OpMode.iABC,   # MOVE
    Lua55OpMode.iAsBx,  # LOADI
    Lua55OpMode.iAsBx,  # LOADF
    Lua55OpMode.iABx,   # LOADK
    Lua55OpMode.iABx,   # LOADKX
    Lua55OpMode.iABC,   # LOADFALSE
    Lua55OpMode.iABC,   # LFALSESKIP
    Lua55OpMode.iABC,   # LOADTRUE
    Lua55OpMode.iABC,   # LOADNIL
    Lua55OpMode.iABC,   # GETUPVAL
    Lua55OpMode.iABC,   # SETUPVAL
    Lua55OpMode.iABC,   # GETTABUP
    Lua55OpMode.iABC,   # GETTABLE
    Lua55OpMode.iABC,   # GETI
    Lua55OpMode.iABC,   # GETFIELD
    Lua55OpMode.iABC,   # SETTABUP
    Lua55OpMode.iABC,   # SETTABLE
    Lua55OpMode.iABC,   # SETI
    Lua55OpMode.iABC,   # SETFIELD
    Lua55OpMode.iABC,   # NEWTABLE
    Lua55OpMode.iABC,   # SELF
    Lua55OpMode.iABC,   # ADDI
    Lua55OpMode.iABC,   # ADDK
    Lua55OpMode.iABC,   # SUBK
    Lua55OpMode.iABC,   # MULK
    Lua55OpMode.iABC,   # MODK
    Lua55OpMode.iABC,   # POWK
    Lua55OpMode.iABC,   # DIVK
    Lua55OpMode.iABC,   # IDIVK
    Lua55OpMode.iABC,   # BANDK
    Lua55OpMode.iABC,   # BORK
    Lua55OpMode.iABC,   # BXORK
    Lua55OpMode.iABC,   # SHRI
    Lua55OpMode.iABC,   # SHLI
    Lua55OpMode.iABC,   # ADD
    Lua55OpMode.iABC,   # SUB
    Lua55OpMode.iABC,   # MUL
    Lua55OpMode.iABC,   # MOD
    Lua55OpMode.iABC,   # POW
    Lua55OpMode.iABC,   # DIV
    Lua55OpMode.iABC,   # IDIV
    Lua55OpMode.iABC,   # BAND
    Lua55OpMode.iABC,   # BOR
    Lua55OpMode.iABC,   # BXOR
    Lua55OpMode.iABC,   # SHL
    Lua55OpMode.iABC,   # SHR
    Lua55OpMode.iABC,   # MMBIN
    Lua55OpMode.iABC,   # MMBINI
    Lua55OpMode.iABC,   # MMBINK
    Lua55OpMode.iABC,   # UNM
    Lua55OpMode.iABC,   # BNOT
    Lua55OpMode.iABC,   # NOT
    Lua55OpMode.iABC,   # LEN
    Lua55OpMode.iABC,   # CONCAT
    Lua55OpMode.iABC,   # CLOSE
    Lua55OpMode.iABC,   # TBC
    Lua55OpMode.isJ,    # JMP
    Lua55OpMode.iABC,   # EQ
    Lua55OpMode.iABC,   # LT
    Lua55OpMode.iABC,   # LE
    Lua55OpMode.iABC,   # EQK
    Lua55OpMode.iABC,   # EQI
    Lua55OpMode.iABC,   # LTI
    Lua55OpMode.iABC,   # LEI
    Lua55OpMode.iABC,   # GTI
    Lua55OpMode.iABC,   # GEI
    Lua55OpMode.iABC,   # TEST
    Lua55OpMode.iABC,   # TESTSET
    Lua55OpMode.iABC,   # CALL
    Lua55OpMode.iABC,   # TAILCALL
    Lua55OpMode.iABC,   # RETURN
    Lua55OpMode.iABC,   # RETURN0
    Lua55OpMode.iABC,   # RETURN1
    Lua55OpMode.iABx,   # FORLOOP
    Lua55OpMode.iABx,   # FORPREP
    Lua55OpMode.iABx,   # TFORPREP
    Lua55OpMode.iABC,   # TFORCALL
    Lua55OpMode.iABx,   # TFORLOOP
    Lua55OpMode.iABC,   # SETLIST
    Lua55OpMode.iABx,   # CLOSURE
    Lua55OpMode.iABC,   # VARARG
    Lua55OpMode.iABC,   # VARARGPREP
    Lua55OpMode.iAx,    # EXTRAARG
    Lua55OpMode.ivABC,  # GETVARG
    Lua55OpMode.iABx,   # ERRNNIL
]


class StandardConstantTag(IntEnum):
    TNIL = 0
    TBOOLEAN = 1
    TNUMBER = 3
    TSTRING = 4


@dataclass
class Instruction:
    op: int                    # OpCode (0..37 for 5.1, 0..84 for 5.5)
    a: int = 0                 # 8 bits (0..255)
    b: int = 0                 # 9 bits (5.1) or 8 bits (5.5)
    c: int = 0                 # 9 bits (5.1) or 8 bits (5.5)
    k: int = 0                 # 1 bit flag (5.5)
    bx: int = 0                # 18 bits (5.1) or 17 bits (5.5)
    sbx: int = 0               # signed bx
    ax: int = 0                # 25 bits (5.5)
    sj: int = 0                # signed jump (5.5)
    mode: Union[OpMode, Lua55OpMode] = OpMode.iABC

    def __post_init__(self) -> None:
        if isinstance(self.mode, OpMode):
            if self.mode == OpMode.iABx:
                self.sbx = self.bx - 131071
            elif self.mode == OpMode.iAsBx:
                self.bx = (self.sbx + 131071) & 0x3FFFF


@dataclass
class Constant:
    tag: int                   # Standard tag: 0 (nil), 1 (bool), 3 (number), 4 (string)
    value: Any                 # None, bool, float/int, str/bytes


@dataclass
class LocVar:
    varname: str
    startpc: int
    endpc: int


@dataclass
class Proto:
    source: str = ""
    linedefined: int = 0
    lastlinedefined: int = 0
    nups: int = 0
    numparams: int = 0
    is_vararg: int = 0
    maxstacksize: int = 2
    code: List[Instruction] = field(default_factory=list)
    constants: List[Constant] = field(default_factory=list)
    subprotos: List['Proto'] = field(default_factory=list)
    lineinfo: List[int] = field(default_factory=list)
    locvars: List[LocVar] = field(default_factory=list)
    upvalues: List[str] = field(default_factory=list)


@dataclass
class ChunkHeader:
    signature: bytes = b"\x1bLua"
    version: int = 0x51         # 0x51 for Lua 5.1, 0x55 for Lua 5.5
    format_version: int = 0
    endianness: int = 1         # 1 = little-endian, 0 = big-endian
    size_int: int = 4
    size_size_t: int = 8        # 4 on 32-bit, 8 on 64-bit
    size_instruction: int = 4
    size_lua_number: int = 8
    integral_flag: int = 0      # 0 = floating point double


@dataclass
class LuaChunk:
    header: ChunkHeader
    main_proto: Proto
