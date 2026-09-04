"""
Instruction bitfield packer, unpacker, opcode remapper, and XOR transformer.
Supports Lua 5.1 (38 opcodes, 6-bit opcodes) and Lua 5.5 (85 opcodes, 7-bit opcodes).
"""

from typing import Dict, Tuple
from lua_format.domain.models import Instruction, OP_MODES, OpMode, LUA55_OPMODES, Lua55OpMode


LAYOUT_DEFINITIONS_51 = {
    # layout: (pos_op, pos_a, pos_b, pos_c, pos_bx)
    "OP_A_C_B": (0, 6, 23, 14, 14),   # Standard Lua 5.1
    "OP_A_B_C": (0, 6, 14, 23, 14),
    "A_OP_C_B": (8, 0, 23, 14, 14),
    "B_C_A_OP": (26, 18, 0, 9, 0),    # PopCap / Reverse
    "C_B_A_OP": (26, 18, 9, 0, 0),
    "A_B_C_OP": (26, 0, 8, 17, 8),
}

LAYOUT_DEFINITIONS_55 = {
    # layout: (pos_op, pos_a, pos_k, pos_b, pos_c, pos_bx, pos_ax, pos_sj)
    "5.5_OP_A_k_B_C": (0, 7, 15, 16, 24, 15, 7, 7),  # Standard Lua 5.5
    "5.5_OP_A_k_C_B": (0, 7, 15, 24, 16, 15, 7, 7),
    "5.5_OP_k_B_C_A": (0, 24, 7, 8, 16, 7, 7, 7),
    "5.5_C_B_k_A_OP": (25, 17, 16, 8, 0, 0, 0, 0),  # Reverse
    "5.5_k_B_C_A_OP": (25, 17, 0, 1, 9, 0, 0, 0),
    "5.5_B_C_k_A_OP": (25, 17, 16, 0, 8, 0, 0, 0),
}

LAYOUT_DEFINITIONS = {**LAYOUT_DEFINITIONS_51, **LAYOUT_DEFINITIONS_55}

# 5.1 constants
SIZE_OP_51 = 6
SIZE_A_51 = 8
SIZE_B_51 = 9
SIZE_C_51 = 9
SIZE_BX_51 = 18

MASK_OP_51 = (1 << SIZE_OP_51) - 1
MASK_A_51 = (1 << SIZE_A_51) - 1
MASK_B_51 = (1 << SIZE_B_51) - 1
MASK_C_51 = (1 << SIZE_C_51) - 1
MASK_BX_51 = (1 << SIZE_BX_51) - 1
MAXARG_sBx_51 = MASK_BX_51 >> 1  # 131071

# 5.5 constants
SIZE_OP_55 = 7
SIZE_A_55 = 8
SIZE_k_55 = 1
SIZE_B_55 = 8
SIZE_C_55 = 8
SIZE_BX_55 = 17
SIZE_AX_55 = 25

MASK_OP_55 = (1 << SIZE_OP_55) - 1
MASK_A_55 = (1 << SIZE_A_55) - 1
MASK_k_55 = 1
MASK_B_55 = (1 << SIZE_B_55) - 1
MASK_C_55 = (1 << SIZE_C_55) - 1
MASK_BX_55 = (1 << SIZE_BX_55) - 1
MASK_AX_55 = (1 << SIZE_AX_55) - 1
OFFSET_sBx_55 = MASK_BX_55 >> 1      # 65535
OFFSET_sJ_55 = MASK_AX_55 >> 1       # 16777215


def decode_standard_instruction(raw_u32: int, lua_version: str = "5.1") -> Instruction:
    """Decode a standard raw 32-bit instruction into an Instruction object."""
    if lua_version == "5.5":
        op = raw_u32 & MASK_OP_55
        a = (raw_u32 >> 7) & MASK_A_55
        k = (raw_u32 >> 15) & MASK_k_55
        b = (raw_u32 >> 16) & MASK_B_55
        c = (raw_u32 >> 24) & MASK_C_55
        bx = (raw_u32 >> 15) & MASK_BX_55
        sbx = bx - OFFSET_sBx_55
        ax = (raw_u32 >> 7) & MASK_AX_55
        sj = ax - OFFSET_sJ_55
        mode = LUA55_OPMODES[op] if op < len(LUA55_OPMODES) else Lua55OpMode.iABC
        return Instruction(op=op, a=a, b=b, c=c, k=k, bx=bx, sbx=sbx, ax=ax, sj=sj, mode=mode)
    else:
        op = raw_u32 & MASK_OP_51
        a = (raw_u32 >> 6) & MASK_A_51
        c = (raw_u32 >> 14) & MASK_C_51
        b = (raw_u32 >> 23) & MASK_B_51
        bx = (raw_u32 >> 14) & MASK_BX_51
        sbx = bx - MAXARG_sBx_51
        mode = OP_MODES[op][4] if op < len(OP_MODES) else OpMode.iABC
        return Instruction(op=op, a=a, b=b, c=c, bx=bx, sbx=sbx, mode=mode)


def encode_standard_instruction(ins: Instruction, lua_version: str = "5.1") -> int:
    """Encode an Instruction object into a standard raw 32-bit integer."""
    if lua_version == "5.5":
        op = ins.op & MASK_OP_55
        a = ins.a & MASK_A_55
        if ins.mode in (Lua55OpMode.iABC, Lua55OpMode.ivABC):
            k = ins.k & MASK_k_55
            b = ins.b & MASK_B_55
            c = ins.c & MASK_C_55
            return op | (a << 7) | (k << 15) | (b << 16) | (c << 24)
        elif ins.mode == Lua55OpMode.iABx:
            bx = ins.bx & MASK_BX_55
            return op | (a << 7) | (bx << 15)
        elif ins.mode == Lua55OpMode.iAsBx:
            bx = (ins.sbx + OFFSET_sBx_55) & MASK_BX_55
            return op | (a << 7) | (bx << 15)
        elif ins.mode in (Lua55OpMode.iAx, Lua55OpMode.isJ):
            ax = ins.ax & MASK_AX_55 if ins.mode == Lua55OpMode.iAx else (ins.sj + OFFSET_sJ_55) & MASK_AX_55
            return op | (ax << 7)
        return 0
    else:
        op = ins.op & MASK_OP_51
        a = ins.a & MASK_A_51
        if ins.mode == OpMode.iABC:
            b = ins.b & MASK_B_51
            c = ins.c & MASK_C_51
            return op | (a << 6) | (c << 14) | (b << 23)
        elif ins.mode == OpMode.iABx:
            bx = ins.bx & MASK_BX_51
            return op | (a << 6) | (bx << 14)
        elif ins.mode == OpMode.iAsBx:
            bx = (ins.sbx + MAXARG_sBx_51) & MASK_BX_51
            return op | (a << 6) | (bx << 14)
        return 0


def encode_proprietary_instruction(ins: Instruction,
                                    layout: str,
                                    opcode_map: Dict[int, int],
                                    xor_mask: int = 0,
                                    lua_version: str = "5.1") -> int:
    """
    Encode an Instruction into a proprietary format instruction word.
    """
    if lua_version == "5.5" or layout.startswith("5.5_"):
        prop_op = opcode_map.get(ins.op, ins.op) & MASK_OP_55
        a = ins.a & MASK_A_55
        if layout not in LAYOUT_DEFINITIONS_55:
            layout = "5.5_OP_A_k_B_C"

        pos_op, pos_a, pos_k, pos_b, pos_c, pos_bx, pos_ax, pos_sj = LAYOUT_DEFINITIONS_55[layout]

        if ins.mode in (Lua55OpMode.iABC, Lua55OpMode.ivABC):
            k = ins.k & MASK_k_55
            b = ins.b & MASK_B_55
            c = ins.c & MASK_C_55
            raw = (prop_op << pos_op) | (a << pos_a) | (k << pos_k) | (b << pos_b) | (c << pos_c)
        elif ins.mode == Lua55OpMode.iABx:
            bx = ins.bx & MASK_BX_55
            raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
        elif ins.mode == Lua55OpMode.iAsBx:
            bx = (ins.sbx + OFFSET_sBx_55) & MASK_BX_55
            raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
        elif ins.mode == Lua55OpMode.iAx:
            ax = ins.ax & MASK_AX_55
            raw = (prop_op << pos_op) | (ax << pos_ax)
        elif ins.mode == Lua55OpMode.isJ:
            sj_encoded = (ins.sj + OFFSET_sJ_55) & MASK_AX_55
            raw = (prop_op << pos_op) | (sj_encoded << pos_sj)
        else:
            raw = 0
    else:
        prop_op = opcode_map.get(ins.op, ins.op) & MASK_OP_51
        a = ins.a & MASK_A_51

        if layout not in LAYOUT_DEFINITIONS_51:
            layout = "OP_A_C_B"

        pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS_51[layout]

        if ins.mode == OpMode.iABC:
            b = ins.b & MASK_B_51
            c = ins.c & MASK_C_51
            raw = (prop_op << pos_op) | (a << pos_a) | (b << pos_b) | (c << pos_c)
        elif ins.mode == OpMode.iABx:
            bx = ins.bx & MASK_BX_51
            raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
        elif ins.mode == OpMode.iAsBx:
            bx = (ins.sbx + MAXARG_sBx_51) & MASK_BX_51
            raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
        else:
            raw = 0

    raw = (raw ^ xor_mask) & 0xFFFFFFFF
    return raw


def decode_proprietary_instruction(raw_u32: int,
                                    layout: str,
                                    inv_opcode_map: Dict[int, int],
                                    xor_mask: int = 0,
                                    lua_version: str = "5.1") -> Instruction:
    """
    Decode a proprietary format instruction word back into a standard Instruction object.
    """
    unmasked = (raw_u32 ^ xor_mask) & 0xFFFFFFFF

    if lua_version == "5.5" or layout.startswith("5.5_"):
        if layout not in LAYOUT_DEFINITIONS_55:
            layout = "5.5_OP_A_k_B_C"

        pos_op, pos_a, pos_k, pos_b, pos_c, pos_bx, pos_ax, pos_sj = LAYOUT_DEFINITIONS_55[layout]

        prop_op = (unmasked >> pos_op) & MASK_OP_55
        std_op = inv_opcode_map.get(prop_op, prop_op)
        a = (unmasked >> pos_a) & MASK_A_55
        k = (unmasked >> pos_k) & MASK_k_55
        b = (unmasked >> pos_b) & MASK_B_55
        c = (unmasked >> pos_c) & MASK_C_55
        bx = (unmasked >> pos_bx) & MASK_BX_55
        sbx = bx - OFFSET_sBx_55
        ax = (unmasked >> pos_ax) & MASK_AX_55
        sj = ((unmasked >> pos_sj) & MASK_AX_55) - OFFSET_sJ_55

        mode = LUA55_OPMODES[std_op] if std_op < len(LUA55_OPMODES) else Lua55OpMode.iABC
        return Instruction(op=std_op, a=a, b=b, c=c, k=k, bx=bx, sbx=sbx, ax=ax, sj=sj, mode=mode)
    else:
        if layout not in LAYOUT_DEFINITIONS_51:
            layout = "OP_A_C_B"

        pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS_51[layout]

        prop_op = (unmasked >> pos_op) & MASK_OP_51
        std_op = inv_opcode_map.get(prop_op, prop_op)
        a = (unmasked >> pos_a) & MASK_A_51

        if std_op < len(OP_MODES):
            mode = OP_MODES[std_op][4]
        else:
            mode = OpMode.iABC

        if mode == OpMode.iABC:
            b = (unmasked >> pos_b) & MASK_B_51
            c = (unmasked >> pos_c) & MASK_C_51
            bx = (unmasked >> pos_bx) & MASK_BX_51
            sbx = bx - MAXARG_sBx_51
        else:
            bx = (unmasked >> pos_bx) & MASK_BX_51
            sbx = bx - MAXARG_sBx_51
            b = (bx >> SIZE_C_51) & MASK_B_51
            c = bx & MASK_C_51

        return Instruction(op=std_op, a=a, b=b, c=c, bx=bx, sbx=sbx, mode=mode)
