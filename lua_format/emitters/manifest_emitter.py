"""
JSON and YAML Profile Manifest Emitters for Proprietary Lua Formats.
"""

import json
from lua_format.domain.profile import FormatProfile


class ManifestEmitter:
    """Emits machine-readable JSON and YAML representations of a format profile."""

    def __init__(self, profile: FormatProfile) -> None:
        self.p = profile

    def emit_json(self) -> str:
        return json.dumps(self.p.to_dict(), indent=2)

    def emit_yaml(self) -> str:
        d = self.p.to_dict()
        lines = [
            f"format_profile:",
            f"  name: {d['name']}",
            f"  seed: {d['seed']}",
            f"  magic_hex: \"{d['magic_hex']}\"",
            f"  version: {d['version']}",
            f"  format_version: {d['format_version']}",
            f"  endianness: {d['endianness']}",
            f"  size_int: {d['size_int']}",
            f"  size_size_t: {d['size_size_t']}",
            f"  size_instruction: {d['size_instruction']}",
            f"  size_lua_number: {d['size_lua_number']}",
            f"  bitfield_layout: {d['bitfield_layout']}",
            f"  instruction_xor_mask: \"{d['instruction_xor_mask']}\"",
            f"  string_encoding: {d['string_encoding']}",
            f"  string_xor_key: \"{d['string_xor_key']}\"",
            f"  strip_debug: {str(d['strip_debug']).lower()}",
            f"  proto_section_order:",
        ]
        for s in d['proto_section_order']:
            lines.append(f"    - {s}")

        lines.append("  const_tag_map:")
        for k, v in d['const_tag_map'].items():
            lines.append(f"    {k}: {v}")

        lines.append("  opcode_map:")
        for k, v in d['opcode_map'].items():
            lines.append(f"    {k}: {v}")

        lines.append("  envelope:")
        lines.append(f"    enabled: {str(d['envelope']['enabled']).lower()}")
        lines.append(f"    magic: \"{d['envelope']['magic']}\"")
        lines.append(f"    version: \"{d['envelope']['version']}\"")
        lines.append(f"    session_id: \"{d['envelope']['session_id']}\"")
        if d['envelope']['auth']:
            lines.append(f"    auth: {d['envelope']['auth']}")
            lines.append(f"    auth_key_hex: \"{d['envelope']['auth_key_hex']}\"")

        return "\n".join(lines) + "\n"
