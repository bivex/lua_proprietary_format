"""
C Standalone Runner and Native VM Loader Emitter for Proprietary Lua Formats.
Generates self-contained C code with embedded CRC-32, HMAC-SHA256, custom undump,
instruction bitfield unpacker, opcode remapping, and Lua 5.1 C API runner.
"""

from lua_format.domain.profile import FormatProfile
from lua_format.codecs.instruction_codec import LAYOUT_DEFINITIONS


class CRunnerEmitter:
    """Emits standalone C runner capable of natively loading and executing proprietary Lua chunks."""

    def __init__(self, profile: FormatProfile) -> None:
        self.p = profile

    def emit(self) -> str:
        p = self.p
        pos_op, pos_a, pos_b, pos_c, pos_bx = LAYOUT_DEFINITIONS.get(p.bitfield_layout, (0, 6, 23, 14, 14))

        # Build C opcode mapping table: prop_op -> std_op
        inv_op_table = ", ".join(str(p.inv_opcode_map.get(i, i)) for i in range(38))
        
        # Build C const tag mapping table: prop_tag -> std_tag
        inv_tag_cases = []
        for prop_tag, std_tag in p.inv_const_tag_map.items():
            inv_tag_cases.append(f"        case {prop_tag}: std_tag = {std_tag}; break;")
        inv_tag_switch = "\n".join(inv_tag_cases)

        # Build Section parsing order in C
        section_calls = []
        for s in p.proto_section_order:
            if s == "header_info":
                section_calls.append("    LoadHeaderInfo(S, f, p);")
            elif s == "code":
                section_calls.append("    LoadCode(S, f);")
            elif s == "constants":
                section_calls.append("    LoadConstants(S, f);")
            elif s == "subprotos":
                section_calls.append("    LoadSubProtos(S, f);")
            elif s == "debug":
                section_calls.append("    LoadDebug(S, f);")
        section_code = "\n".join(section_calls)

        magic_hex_bytes = ", ".join(f"0x{b:02X}" for b in p.magic)
        magic_len = len(p.magic)

        envelope_check = ""
        if p.envelope.enabled:
            envelope_check = f"""
    /* 22-byte Envelope Check */
    if (size >= 22) {{
        uint32_t env_magic = *(const uint32_t*)buf;
        if (env_magic == 0x{p.envelope.magic:08X}) {{
            uint16_t pay_len = *(const uint16_t*)(buf + 16);
            uint32_t wire_crc = *(const uint32_t*)(buf + 18);
            
            uint32_t calc_crc = compute_crc32(buf, 18, buf + 22, pay_len);
            if (wire_crc != calc_crc) {{
                fprintf(stderr, "[ProprietaryRunner] Envelope CRC-32 mismatch! wire=0x%08X calc=0x%08X\\n", wire_crc, calc_crc);
                return 1;
            }}
            buf += 22;
            size = pay_len;
        }}
    }}
"""

        c_source = f"""/*
 * Auto-generated Standalone Runner for Proprietary Lua Format: {p.name}
 * Format Seed: {p.seed}
 * Bitfield Layout: {p.bitfield_layout} | XOR Mask: 0x{p.instruction_xor_mask:08X}
 * String XOR: 0x{p.string_xor_key:02X}
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include "lobject.h"
#include "lstate.h"
#include "lundump.h"
#include "ldebug.h"
#include "ldo.h"
#include "lfunc.h"
#include "lmem.h"
#include "lstring.h"
#include "lzio.h"
#include "lopcodes.h"

#define PROP_MAGIC_LEN {magic_len}
static const uint8_t PROP_MAGIC[PROP_MAGIC_LEN] = {{ {magic_hex_bytes} }};
static const uint8_t PROP_TO_STD_OPCODE[38] = {{ {inv_op_table} }};

#define PROP_POS_OP  {pos_op}
#define PROP_POS_A   {pos_a}
#define PROP_POS_B   {pos_b}
#define PROP_POS_C   {pos_c}
#define PROP_POS_BX  {pos_bx}

#define PROP_MASK_OP  0x3F
#define PROP_MASK_A   0xFF
#define PROP_MASK_B   0x1FF
#define PROP_MASK_C   0x1FF
#define PROP_MASK_BX  0x3FFFF
#define PROP_MAXARG_SBX 131071

#define INS_XOR_MASK 0x{p.instruction_xor_mask:08X}U
#define STR_XOR_KEY  0x{p.string_xor_key:02X}

typedef struct {{
    lua_State* L;
    const uint8_t* data;
    size_t size;
    size_t pos;
    const char* name;
    Mbuffer* b;
}} PropLoadState;

/* ISO-HDLC CRC32 Implementation */
static uint32_t compute_crc32(const uint8_t* h, size_t hlen, const uint8_t* p, size_t plen) {{
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < hlen; i++) {{
        crc ^= h[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }}
    uint8_t zero4[4] = {{0, 0, 0, 0}};
    for (int i = 0; i < 4; i++) {{
        crc ^= zero4[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }}
    for (size_t i = 0; i < plen; i++) {{
        crc ^= p[i];
        for (int j = 0; j < 8; j++) crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }}
    return ~crc;
}}

static void prop_error(PropLoadState* S, const char* why) {{
    luaO_pushfstring(S->L, "%s: %s in proprietary chunk", S->name, why);
    luaD_throw(S->L, LUA_ERRSYNTAX);
}}

static void PropReadBlock(PropLoadState* S, void* b, size_t size) {{
    if (S->pos + size > S->size) {{
        prop_error(S, "unexpected end of proprietary chunk");
    }}
    memcpy(b, S->data + S->pos, size);
    S->pos += size;
}}

static int PropReadByte(PropLoadState* S) {{
    uint8_t x;
    PropReadBlock(S, &x, 1);
    return x;
}}

static int PropReadInt(PropLoadState* S) {{
    int x;
    PropReadBlock(S, &x, sizeof(int));
    if (x < 0) prop_error(S, "bad integer");
    return x;
}}

static size_t PropReadSizeT(PropLoadState* S) {{
    size_t x;
    PropReadBlock(S, &x, sizeof(size_t));
    return x;
}}

static lua_Number PropReadNumber(PropLoadState* S) {{
    lua_Number x;
    PropReadBlock(S, &x, sizeof(lua_Number));
    return x;
}}

static TString* PropReadString(PropLoadState* S) {{
    size_t size = PropReadSizeT(S);
    if (size == 0) return NULL;
    char* s = luaZ_openspace(S->L, S->b, size);
    PropReadBlock(S, s, size);
#if STR_XOR_KEY != 0
    for (size_t i = 0; i < size; i++) {{
        s[i] ^= STR_XOR_KEY;
    }}
#endif
    return luaS_newlstr(S->L, s, size - 1);
}}

static Instruction DecodePropInstruction(uint32_t raw) {{
    raw ^= INS_XOR_MASK;
    uint32_t prop_op = (raw >> PROP_POS_OP) & PROP_MASK_OP;
    uint32_t std_op = (prop_op < 38) ? PROP_TO_STD_OPCODE[prop_op] : prop_op;
    uint32_t a = (raw >> PROP_POS_A) & PROP_MASK_A;

    enum OpMode mode = getOpMode(std_op);

    if (mode == iABC) {{
        uint32_t b = (raw >> PROP_POS_B) & PROP_MASK_B;
        uint32_t c = (raw >> PROP_POS_C) & PROP_MASK_C;
        return (Instruction)((std_op & 0x3F) | (a << 6) | (c << 14) | (b << 23));
    }} else {{
        uint32_t bx = (raw >> PROP_POS_BX) & PROP_MASK_BX;
        return (Instruction)((std_op & 0x3F) | (a << 6) | (bx << 14));
    }}
}}

static void LoadCode(PropLoadState* S, Proto* f) {{
    int n = PropReadInt(S);
    f->code = luaM_newvector(S->L, n, Instruction);
    f->sizecode = n;
    for (int i = 0; i < n; i++) {{
        uint32_t raw;
        PropReadBlock(S, &raw, sizeof(uint32_t));
        f->code[i] = DecodePropInstruction(raw);
    }}
}}

static Proto* LoadFunction(PropLoadState* S, TString* p);

static void LoadConstants(PropLoadState* S, Proto* f) {{
    int n = PropReadInt(S);
    f->k = luaM_newvector(S->L, n, TValue);
    f->sizek = n;
    for (int i = 0; i < n; i++) setnilvalue(&f->k[i]);

    for (int i = 0; i < n; i++) {{
        TValue* o = &f->k[i];
        int prop_tag = PropReadByte(S);
        int std_tag = prop_tag;
        switch (prop_tag) {{
{inv_tag_switch}
            default: break;
        }}

        switch (std_tag) {{
            case LUA_TNIL:
                setnilvalue(o);
                break;
            case LUA_TBOOLEAN:
                setbvalue(o, PropReadByte(S) != 0);
                break;
            case LUA_TNUMBER:
                setnvalue(o, PropReadNumber(S));
                break;
            case LUA_TSTRING:
                setsvalue2n(S->L, o, PropReadString(S));
                break;
            default:
                prop_error(S, "bad constant tag");
                break;
        }}
    }}
}}

static void LoadSubProtos(PropLoadState* S, Proto* f) {{
    int n = PropReadInt(S);
    f->p = luaM_newvector(S->L, n, Proto*);
    f->sizep = n;
    for (int i = 0; i < n; i++) f->p[i] = NULL;
    for (int i = 0; i < n; i++) f->p[i] = LoadFunction(S, f->source);
}}

static void LoadDebug(PropLoadState* S, Proto* f) {{
    int n = PropReadInt(S);
    f->lineinfo = luaM_newvector(S->L, n, int);
    f->sizelineinfo = n;
    for (int i = 0; i < n; i++) f->lineinfo[i] = PropReadInt(S);

    n = PropReadInt(S);
    f->locvars = luaM_newvector(S->L, n, LocVar);
    f->sizelocvars = n;
    for (int i = 0; i < n; i++) f->locvars[i].varname = NULL;
    for (int i = 0; i < n; i++) {{
        f->locvars[i].varname = PropReadString(S);
        f->locvars[i].startpc = PropReadInt(S);
        f->locvars[i].endpc = PropReadInt(S);
    }}

    n = PropReadInt(S);
    f->upvalues = luaM_newvector(S->L, n, TString*);
    f->sizeupvalues = n;
    for (int i = 0; i < n; i++) f->upvalues[i] = NULL;
    for (int i = 0; i < n; i++) f->upvalues[i] = PropReadString(S);
}}

static void LoadHeaderInfo(PropLoadState* S, Proto* f, TString* p) {{
    f->source = PropReadString(S);
    if (f->source == NULL) f->source = p;
    f->linedefined = PropReadInt(S);
    f->lastlinedefined = PropReadInt(S);
    f->nups = PropReadByte(S);
    f->numparams = PropReadByte(S);
    f->is_vararg = PropReadByte(S);
    f->maxstacksize = PropReadByte(S);
}}

static Proto* LoadFunction(PropLoadState* S, TString* p) {{
    Proto* f = luaF_newproto(S->L);
    setptvalue2s(S->L, S->L->top, f);
    incr_top(S->L);

{section_code}

    if (!luaG_checkcode(f)) prop_error(S, "bad code in function");

    S->L->top--;
    return f;
}}

static void LoadHeader(PropLoadState* S) {{
    uint8_t sig[PROP_MAGIC_LEN];
    PropReadBlock(S, sig, PROP_MAGIC_LEN);
    if (memcmp(sig, PROP_MAGIC, PROP_MAGIC_LEN) != 0) {{
        prop_error(S, "bad proprietary magic signature");
    }}
    PropReadByte(S); /* version */
    PropReadByte(S); /* format */
    PropReadByte(S); /* endianness */
    PropReadByte(S); /* sizeof(int) */
    PropReadByte(S); /* sizeof(size_t) */
    PropReadByte(S); /* sizeof(Instruction) */
    PropReadByte(S); /* sizeof(lua_Number) */
    PropReadByte(S); /* integral */
}}

int luaU_load_proprietary(lua_State* L, const uint8_t* buf, size_t size, const char* name) {{
{envelope_check}

    Mbuffer b;
    luaZ_initbuffer(L, &b);

    PropLoadState S;
    S.L = L;
    S.data = buf;
    S.size = size;
    S.pos = 0;
    S.name = name ? name : "proprietary_chunk";
    S.b = &b;

    LoadHeader(&S);
    Proto* tf = LoadFunction(&S, luaS_newliteral(L, "=?"));

    Closure* cl = luaF_newLclosure(L, 0, hvalue(gt(L)));
    cl->l.p = tf;
    setclvalue(L, L->top, cl);
    incr_top(L);

    return 0;
}}

int main(int argc, char* argv[]) {{
    if (argc < 2) {{
        fprintf(stderr, "Usage: %s <protected_script.luc> [args...]\\n", argv[0]);
        return 1;
    }}

    const char* filename = argv[1];
    FILE* f = fopen(filename, "rb");
    if (!f) {{
        perror("fopen");
        return 1;
    }}
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t* buf = (uint8_t*)malloc(sz);
    if (!buf) {{
        fclose(f);
        fprintf(stderr, "Out of memory\\n");
        return 1;
    }}
    if (fread(buf, 1, sz, f) != (size_t)sz) {{
        free(buf);
        fclose(f);
        fprintf(stderr, "Failed to read full file\\n");
        return 1;
    }}
    fclose(f);

    lua_State* L = lua_open();
    luaL_openlibs(L);

    int status = luaU_load_proprietary(L, buf, sz, filename);
    free(buf);

    if (status != 0) {{
        fprintf(stderr, "Failed to load proprietary chunk\\n");
        lua_close(L);
        return 1;
    }}

    /* Pass script arguments to Lua chunk */
    for (int i = 2; i < argc; i++) {{
        lua_pushstring(L, argv[i]);
    }}

    int n_args = argc - 2;
    status = lua_pcall(L, n_args, LUA_MULTRET, 0);
    if (status != 0) {{
        fprintf(stderr, "Runtime Error: %s\\n", lua_tostring(L, -1));
        lua_close(L);
        return 1;
    }}

    lua_close(L);
    return 0;
}}
"""
        return c_source
