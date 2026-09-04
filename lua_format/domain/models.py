"""
Domain Entity and Value Object Models for Lua 5.1 Bytecode and Custom Chunks.
"""

from dataclasses import dataclass, field
from enum import IntEnum, auto
from typing import Any, List, Optional, Tuple, Union


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


# (T, A, B, C, mode)
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


class StandardConstantTag(IntEnum):
    TNIL = 0
    TBOOLEAN = 1
    TNUMBER = 3
    TSTRING = 4


@dataclass
class Instruction:
    op: int                    # Standard OpCode (0..37)
    a: int = 0                 # 8 bits (0..255)
    b: int = 0                 # 9 bits (0..511)
    c: int = 0                 # 9 bits (0..511)
    bx: int = 0                # 18 bits unsigned (0..262143)
    sbx: int = 0               # 18 bits signed (-131071..131072)
    mode: OpMode = OpMode.iABC

    def __post_init__(self) -> None:
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
    version: int = 0x51
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
