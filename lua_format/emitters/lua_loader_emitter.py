"""
Pure Lua In-Memory Loader Emitter.
Generates self-contained Lua script that deserializes, unscrambles,
and executes proprietary format chunks in standard Lua VM via loadstring().
Supports Lua 5.1 and Lua 5.5.
"""

from lua_format.domain.models import NUM_OPCODES, NUM_OPCODES_55
from lua_format.domain.profile import FormatProfile
from lua_format.codecs.instruction_codec import LAYOUT_DEFINITIONS


class LuaLoaderEmitter:
    """Emits standalone pure Lua loader for executing proprietary bytecode."""

    def __init__(self, profile: FormatProfile) -> None:
        self.p = profile

    def emit(self) -> str:
        p = self.p
        is_55 = (p.lua_version == "5.5" or p.bitfield_layout.startswith("5.5_"))
        num_ops = NUM_OPCODES_55 if is_55 else NUM_OPCODES

        if is_55:
            pos_op, pos_a, pos_k, pos_b, pos_c, pos_bx, pos_ax, pos_sj = LAYOUT_DEFINITIONS.get(
                p.bitfield_layout, (0, 7, 15, 16, 24, 15, 7, 7)
            )
            mask_op = "0x7F"
            mask_b = "0xFF"
            mask_c = "0xFF"
            mask_bx = "0x1FFFF"
        else:
            pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS.get(
                p.bitfield_layout, (0, 6, 23, 14, 14)
            )
            pos_k, pos_ax, pos_sj = 0, 0, 0
            mask_op = "0x3F"
            mask_b = "0x1FF"
            mask_c = "0x1FF"
            mask_bx = "0x3FFFF"

        # Opcode table Lua syntax
        op_entries = []
        for prop_op in range(num_ops):
            std_op = p.inv_opcode_map.get(prop_op, prop_op)
            op_entries.append(f"[{prop_op}] = {std_op}")
        op_table_lua = "{" + ", ".join(op_entries) + "}"

        # Const tag table Lua syntax
        tag_entries = []
        for prop_tag, std_tag in p.inv_const_tag_map.items():
            tag_entries.append(f"[{prop_tag}] = {std_tag}")
        tag_table_lua = "{" + ", ".join(tag_entries) + "}"

        # Section order Lua array
        sections_lua = "{" + ", ".join(f'"{s}"' for s in p.proto_section_order) + "}"

        magic_byte_array = "{" + ", ".join(str(b) for b in p.magic) + "}"

        lua_code = f"""--[[
  Auto-generated Pure Lua Loader for Proprietary Format: {p.name}
  Target Lua Version: {p.lua_version}
  Format Seed: {p.seed}
  Bitfield Layout: {p.bitfield_layout} | XOR Mask: 0x{p.instruction_xor_mask:08X}
  String XOR Key: 0x{p.string_xor_key:02X}
--]]

local Loader = {{}}

-- Bitwise helper arithmetic for Lua 5.1 / 5.5
local function band(a, b)
    local r, m = 0, 1
    for i = 1, 32 do
        if (a % 2 == 1) and (b % 2 == 1) then r = r + m end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        m = m * 2
        if a == 0 or b == 0 then break end
    end
    return r
end

local function bor(a, b)
    local r, m = 0, 1
    for i = 1, 32 do
        local a1, b1 = a % 2, b % 2
        if a1 == 1 or b1 == 1 then r = r + m end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        m = m * 2
        if a == 0 and b == 0 then break end
    end
    return r
end

local function bxor(a, b)
    local r, m = 0, 1
    for i = 1, 32 do
        local a1, b1 = a % 2, b % 2
        if a1 ~= b1 then r = r + m end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
        m = m * 2
        if a == 0 and b == 0 then break end
    end
    return r
end

local function rshift(a, n)
    return math.floor(a / (2 ^ n))
end

local function lshift(a, n)
    return (a * (2 ^ n)) % 4294967296
end

-- Profile Configuration
local PROP_MAGIC = {magic_byte_array}
local PROP_TO_STD_OPCODE = {op_table_lua}
local PROP_TO_STD_TAG = {tag_table_lua}
local SECTION_ORDER = {sections_lua}

local POS_OP = {pos_op}
local POS_A = {pos_a}
local POS_k = {pos_k}
local POS_B = {pos_b}
local POS_C = {pos_c}
local POS_BX = {pos_bx}

local MASK_OP = {mask_op}
local MASK_A = 0xFF
local MASK_B = {mask_b}
local MASK_C = {mask_c}
local MASK_BX = {mask_bx}

local INS_XOR_MASK = {p.instruction_xor_mask}
local STR_XOR_KEY = {p.string_xor_key}

local OP_MODES = {{
    [0] = 0, [1] = 1, [2] = 0, [3] = 0, [4] = 0, [5] = 1, [6] = 0, [7] = 1,
    [8] = 0, [9] = 0, [10] = 0, [11] = 0, [12] = 0, [13] = 0, [14] = 0, [15] = 0,
    [16] = 0, [17] = 0, [18] = 0, [19] = 0, [20] = 0, [21] = 0, [22] = 2, [23] = 0,
    [24] = 0, [25] = 0, [26] = 0, [27] = 0, [28] = 0, [29] = 0, [30] = 0, [31] = 2,
    [32] = 2, [33] = 0, [34] = 0, [35] = 0, [36] = 1, [37] = 0
}}

-- Transpiler Reader
local function create_reader(str)
    local pos = 1
    local len = string.len(str)

    -- Check 22-byte Envelope
    if len >= 22 then
        local m1, m2, m3, m4 = string.byte(str, 1, 4)
        local magic = m1 + m2*256 + m3*65536 + m4*16777216
        if magic == {p.envelope.magic} then
            local p1, p2 = string.byte(str, 17, 18)
            local pay_len = p1 + p2*256
            str = string.sub(str, 23, 22 + pay_len)
            len = string.len(str)
        end
    end

    local R = {{}}
    function R.read_bytes(n)
        if pos + n - 1 > len then error("Unexpected EOF in proprietary chunk") end
        local sub = string.sub(str, pos, pos + n - 1)
        pos = pos + n
        return sub
    end

    function R.read_byte()
        local b = string.byte(R.read_bytes(1), 1)
        return b
    end

    function R.read_int()
        local b1, b2, b3, b4 = string.byte(R.read_bytes(4), 1, 4)
        local u = b1 + b2*256 + b3*65536 + b4*16777216
        if u >= 2147483648 then u = u - 4294967296 end
        return u
    end

    function R.read_size_t(size)
        size = size or 8
        local b = {{ string.byte(R.read_bytes(size), 1, size) }}
        local val = 0
        local mul = 1
        for i = 1, size do
            val = val + b[i] * mul
            mul = mul * 256
        end
        return val
    end

    function R.read_raw_number()
        return R.read_bytes(8)
    end

    function R.read_string(size_t_len)
        local sz = R.read_size_t(size_t_len)
        if sz == 0 then return nil end
        local raw = R.read_bytes(sz)
        if STR_XOR_KEY ~= 0 then
            local t = {{}}
            for i = 1, sz do
                local c = bxor(string.byte(raw, i), STR_XOR_KEY)
                t[i] = string.char(c)
            end
            raw = table.concat(t)
        end
        if string.sub(raw, -1) == "\\0" then
            raw = string.sub(raw, 1, -2)
        end
        return raw
    end

    return R
end

-- Standard Bytecode Serializer
local function create_std_writer(size_size_t)
    size_size_t = size_size_t or 8
    local buf = {{}}

    local function w_bytes(b) table.insert(buf, b) end
    local function w_byte(v) table.insert(buf, string.char(v % 256)) end
    local function w_int(v)
        if v < 0 then v = v + 4294967296 end
        local b1 = v % 256
        local b2 = math.floor(v / 256) % 256
        local b3 = math.floor(v / 65536) % 256
        local b4 = math.floor(v / 16777216) % 256
        table.insert(buf, string.char(b1, b2, b3, b4))
    end
    local function w_size_t(v)
        for i = 1, size_size_t do
            table.insert(buf, string.char(v % 256))
            v = math.floor(v / 256)
        end
    end
    local function w_string(s)
        if not s or s == "" then
            w_size_t(0)
        else
            local s_null = s .. "\\0"
            w_size_t(string.len(s_null))
            w_bytes(s_null)
        end
    end

    local W = {{}}
    W.buf = buf
    W.w_bytes = w_bytes
    W.w_byte = w_byte
    W.w_int = w_int
    W.w_size_t = w_size_t
    W.w_string = w_string
    function W.get_data() return table.concat(buf) end
    return W
end

function Loader.transpile_to_standard(prop_binary, host_size_t)
    host_size_t = host_size_t or 8
    local R = create_reader(prop_binary)

    -- Read proprietary header
    local sig = R.read_bytes(#PROP_MAGIC)
    local ver = R.read_byte()
    local fmt = R.read_byte()
    local endian = R.read_byte()
    local s_int = R.read_byte()
    local s_sizet = R.read_byte()
    local s_ins = R.read_byte()
    local s_num = R.read_byte()
    local integral = R.read_byte()

    local function read_proto(parent_src)
        local P = {{}}
        for _, sec in ipairs(SECTION_ORDER) do
            if sec == "header_info" then
                P.source = R.read_string(s_sizet)
                if not P.source and parent_src then P.source = parent_src end
                P.linedefined = R.read_int()
                P.lastlinedefined = R.read_int()
                P.nups = R.read_byte()
                P.numparams = R.read_byte()
                P.is_vararg = R.read_byte()
                P.maxstacksize = R.read_byte()
            elseif sec == "code" then
                local n_code = R.read_int()
                P.code = {{}}
                for i = 1, n_code do
                    local b1, b2, b3, b4 = string.byte(R.read_bytes(4), 1, 4)
                    local raw = b1 + b2*256 + b3*65536 + b4*16777216
                    raw = bxor(raw, INS_XOR_MASK)

                    local prop_op = band(rshift(raw, POS_OP), MASK_OP)
                    local std_op = PROP_TO_STD_OPCODE[prop_op] or prop_op
                    local a = band(rshift(raw, POS_A), MASK_A)

                    local mode = OP_MODES[std_op] or 0
                    local std_ins = 0
                    if mode == 0 then -- iABC
                        local b = band(rshift(raw, POS_B), MASK_B)
                        local c = band(rshift(raw, POS_C), MASK_C)
                        std_ins = std_op + lshift(a, 6) + lshift(c, 14) + lshift(b, 23)
                    else -- iABx / iAsBx
                        local bx = band(rshift(raw, POS_BX), MASK_BX)
                        std_ins = std_op + lshift(a, 6) + lshift(bx, 14)
                    end
                    P.code[i] = std_ins
                end
            elseif sec == "constants" then
                local n_k = R.read_int()
                P.constants = {{}}
                for i = 1, n_k do
                    local prop_tag = R.read_byte()
                    local std_tag = PROP_TO_STD_TAG[prop_tag] or prop_tag
                    local item = {{ tag = std_tag }}
                    if std_tag == 0 then -- nil
                    elseif std_tag == 1 then -- bool
                        item.val = R.read_byte()
                    elseif std_tag == 3 then -- number
                        item.raw = R.read_raw_number()
                    elseif std_tag == 4 then -- string
                        item.val = R.read_string(s_sizet)
                    end
                    P.constants[i] = item
                end
            elseif sec == "subprotos" then
                local n_p = R.read_int()
                P.subprotos = {{}}
                for i = 1, n_p do
                    P.subprotos[i] = read_proto(P.source)
                end
            elseif sec == "debug" then
                local n_line = R.read_int()
                P.lineinfo = {{}}
                for i = 1, n_line do P.lineinfo[i] = R.read_int() end

                local n_loc = R.read_int()
                P.locvars = {{}}
                for i = 1, n_loc do
                    P.locvars[i] = {{
                        varname = R.read_string(s_sizet),
                        startpc = R.read_int(),
                        endpc = R.read_int()
                    }}
                end

                local n_upv = R.read_int()
                P.upvalues = {{}}
                for i = 1, n_upv do
                    P.upvalues[i] = R.read_string(s_sizet)
                end
            end
        end
        return P
    end

    local main_proto = read_proto()

    local W = create_std_writer(host_size_t)
    -- Write standard header
    W.w_bytes("\\027Lua")
    W.w_byte(0x51)
    W.w_byte(0)
    W.w_byte(1)
    W.w_byte(4)
    W.w_byte(host_size_t)
    W.w_byte(4)
    W.w_byte(8)
    W.w_byte(0)

    local function emit_proto(P, parent_src)
        local src_to_write = (P.source == parent_src) and nil or P.source
        W.w_string(src_to_write)
        W.w_int(P.linedefined)
        W.w_int(P.lastlinedefined)
        W.w_byte(P.nups)
        W.w_byte(P.numparams)
        W.w_byte(P.is_vararg)
        W.w_byte(P.maxstacksize)

        -- Code
        W.w_int(#P.code)
        for _, ins in ipairs(P.code) do W.w_int(ins) end

        -- Constants
        W.w_int(#P.constants)
        for _, k in ipairs(P.constants) do
            W.w_byte(k.tag)
            if k.tag == 0 then
            elseif k.tag == 1 then
                W.w_byte(k.val)
            elseif k.tag == 3 then
                W.w_bytes(k.raw)
            elseif k.tag == 4 then
                W.w_string(k.val)
            end
        end

        -- Subprotos
        W.w_int(#(P.subprotos or {{}}))
        for _, sub in ipairs(P.subprotos or {{}}) do
            emit_proto(sub, P.source)
        end

        -- Debug
        W.w_int(#(P.lineinfo or {{}}))
        for _, l in ipairs(P.lineinfo or {{}}) do W.w_int(l) end

        W.w_int(#(P.locvars or {{}}))
        for _, lv in ipairs(P.locvars or {{}}) do
            W.w_string(lv.varname)
            W.w_int(lv.startpc)
            W.w_int(lv.endpc)
        end

        W.w_int(#(P.upvalues or {{}}))
        for _, uv in ipairs(P.upvalues or {{}}) do
            W.w_string(uv)
        end
    end

    emit_proto(main_proto)
    return W.get_data()
end

function Loader.loadfile(filepath)
    local f = io.open(filepath, "rb")
    if not f then error("Cannot open file: " .. tostring(filepath)) end
    local content = f:read("*all")
    f:close()

    local host_size_t = string.len(string.dump(function() end)) == 52 and 4 or 8
    local std_bytecode = Loader.transpile_to_standard(content, host_size_t)
    return loadstring(std_bytecode, "@" .. filepath)
end

-- CLI Runner mode
if arg and arg[1] and not package.loaded["loader"] then
    local chunk, err = Loader.loadfile(arg[1])
    if not chunk then
        io.stderr:write("Loader Error: " .. tostring(err) .. "\\n")
        os.exit(1)
    end
    -- Shift arguments
    local args = {{}}
    for i = 2, #arg do table.insert(args, arg[i]) end
    chunk(unpack(args))
end

return Loader
"""
        return lua_code
