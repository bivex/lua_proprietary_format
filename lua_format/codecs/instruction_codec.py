"""
Instruction bitfield packer, unpacker, opcode remapper, and XOR transformer.
"""

from typing import Dict, Tuple
from lua_format.domain.models import Instruction, OP_MODES, OpMode


LAYOUT_DEFINITIONS = {
    # layout: (pos_op, pos_a, pos_b, pos_c, pos_bx)
    "OP_A_C_B": (0, 6, 23, 14, 14),   # Standard Lua 5.1
    "OP_A_B_C": (0, 6, 14, 23, 14),
    "A_OP_C_B": (8, 0, 23, 14, 14),
    "B_C_A_OP": (26, 18, 0, 9, 0),    # PopCap / Reverse
    "C_B_A_OP": (26, 18, 9, 0, 0),
    "A_B_C_OP": (26, 0, 8, 17, 8),
}

SIZE_OP = 6
SIZE_A = 8
SIZE_B = 9
SIZE_C = 9
SIZE_BX = 18

MASK_OP = (1 << SIZE_OP) - 1
MASK_A = (1 << SIZE_A) - 1
MASK_B = (1 << SIZE_B) - 1
MASK_C = (1 << SIZE_C) - 1
MASK_BX = (1 << SIZE_BX) - 1
MAXARG_sBx = MASK_BX >> 1  # 131071


def decode_standard_instruction(raw_u32: int) -> Instruction:
    """Decode a standard Lua 5.1 raw 32-bit instruction into an Instruction object."""
    op = raw_u32 & 0x3F
    a = (raw_u32 >> 6) & 0xFF
    c = (raw_u32 >> 14) & 0x1FF
    b = (raw_u32 >> 23) & 0x1FF
    bx = (raw_u32 >> 14) & 0x3FFFF

    if op < len(OP_MODES):
        _, _, _, _, mode = OP_MODES[op]
    else:
        mode = OpMode.iABC

    sbx = bx - MAXARG_sBx
    return Instruction(op=op, a=a, b=b, c=c, bx=bx, sbx=sbx, mode=mode)


def encode_standard_instruction(ins: Instruction) -> int:
    """Encode an Instruction object into a standard Lua 5.1 raw 32-bit integer."""
    op = ins.op & 0x3F
    a = ins.a & 0xFF
    if ins.mode == OpMode.iABC:
        b = ins.b & 0x1FF
        c = ins.c & 0x1FF
        return op | (a << 6) | (c << 14) | (b << 23)
    elif ins.mode == OpMode.iABx:
        bx = ins.bx & 0x3FFFF
        return op | (a << 6) | (bx << 14)
    elif ins.mode == OpMode.iAsBx:
        bx = (ins.sbx + MAXARG_sBx) & 0x3FFFF
        return op | (a << 6) | (bx << 14)
    return 0


def encode_proprietary_instruction(ins: Instruction,
                                    layout: str,
                                    opcode_map: Dict[int, int],
                                    xor_mask: int = 0) -> int:
    """
    Encode an Instruction into a proprietary format instruction word with custom
    opcode mapping, bitfield layout, and XOR mask.
    """
    prop_op = opcode_map.get(ins.op, ins.op) & MASK_OP
    a = ins.a & MASK_A

    if layout not in LAYOUT_DEFINITIONS:
        layout = "OP_A_C_B"

    pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS[layout]

    if ins.mode == OpMode.iABC:
        b = ins.b & MASK_B
        c = ins.c & MASK_C
        raw = (prop_op << pos_op) | (a << pos_a) | (b << pos_b) | (c << pos_c)
    elif ins.mode == OpMode.iABx:
        bx = ins.bx & MASK_BX
        raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
    elif ins.mode == OpMode.iAsBx:
        bx = (ins.sbx + MAXARG_sBx) & MASK_BX
        raw = (prop_op << pos_op) | (a << pos_a) | (bx << pos_bx)
    else:
        raw = 0

    raw = (raw ^ xor_mask) & 0xFFFFFFFF
    return raw


def decode_proprietary_instruction(raw_u32: int,
                                    layout: str,
                                    inv_opcode_map: Dict[int, int],
                                    xor_mask: int = 0) -> Instruction:
    """
    Decode a proprietary format instruction word back into a standard Instruction object.
    """
    unmasked = (raw_u32 ^ xor_mask) & 0xFFFFFFFF

    if layout not in LAYOUT_DEFINITIONS:
        layout = "OP_A_C_B"

    pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS[layout]

    prop_op = (unmasked >> pos_op) & MASK_OP
    std_op = inv_opcode_map.get(prop_op, prop_op)
    a = (unmasked >> pos_a) & MASK_A

    if std_op < len(OP_MODES):
        _, _, _, _, mode = OP_MODES[std_op]
    else:
        mode = OpMode.iABC

    if mode == OpMode.iABC:
        b = (unmasked >> pos_b) & MASK_B
        c = (unmasked >> pos_c) & MASK_C
        bx = (unmasked >> pos_bx) & MASK_BX
        sbx = bx - MAXARG_sBx
    else:
        bx = (unmasked >> pos_bx) & MASK_BX
        sbx = bx - MAXARG_sBx
        b = (bx >> SIZE_C) & MASK_B
        c = bx & MASK_C

    return Instruction(op=std_op, a=a, b=b, c=c, bx=bx, sbx=sbx, mode=mode)
