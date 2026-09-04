"""
Multi-layer 22-byte Framing Envelope and HMAC Authentication Codec.
Inherited from gen_random_protocol wire framing specifications.
"""

import hmac
import hashlib
import struct
import zlib
from typing import Tuple
from lua_format.domain.profile import EnvelopeConfig


HEADER_22B_SIZE = 22
OPCODE_LUA_CHUNK = 0x00A1


def compute_crc32(header_without_crc: bytes, payload: bytes) -> int:
    """
    Compute ISO-HDLC CRC-32 over header(crc=0) || payload.
    """
    crc_init = struct.pack("<I", 0)
    data = header_without_crc + crc_init + payload
    return zlib.crc32(data) & 0xFFFFFFFF


def wrap_envelope(payload: bytes, config: EnvelopeConfig) -> bytes:
    """
    Wrap raw proprietary chunk payload into 22-byte canonical wire header
    with CRC-32 integrity and optional HMAC-SHA256 authentication.
    """
    if not config.enabled:
        return payload

    payload_len = len(payload)
    if payload_len > 0xFFFF:
        raise ValueError(f"Payload size {payload_len} exceeds 16-bit envelope capacity (65535)")

    hdr_prefix = struct.pack(
        "<IHHIIH",
        config.magic,
        config.version,
        OPCODE_LUA_CHUNK,
        config.session_id,
        config.sequence,
        payload_len
    )

    crc = compute_crc32(hdr_prefix, payload)
    header = hdr_prefix + struct.pack("<I", crc)

    frame = bytearray(header + payload)

    if config.auth == "hmac-sha256":
        mac = hmac.new(config.auth_key, bytes(frame), hashlib.sha256).digest()
        frame.extend(mac)

    return bytes(frame)


def unwrap_envelope(data: bytes, config: EnvelopeConfig) -> Tuple[bytes, bool]:
    """
    Unwrap 22-byte canonical wire header, verifying CRC-32 and HMAC-SHA256.
    Returns (unwrapped_payload, is_enveloped).
    """
    if len(data) < HEADER_22B_SIZE:
        return data, False

    magic, version, opcode, session_id, sequence, payload_len, wire_crc = struct.unpack(
        "<IHHIIHI", data[:HEADER_22B_SIZE]
    )

    # If magic doesn't match configured envelope magic, treat as non-enveloped
    if magic != config.magic:
        return data, False

    hdr_prefix = data[:18]
    expected_crc = compute_crc32(hdr_prefix, data[HEADER_22B_SIZE:HEADER_22B_SIZE + payload_len])

    if wire_crc != expected_crc:
        raise ValueError(f"Envelope CRC-32 mismatch: wire 0x{wire_crc:08X} != computed 0x{expected_crc:08X}")

    payload = data[HEADER_22B_SIZE:HEADER_22B_SIZE + payload_len]

    if config.auth == "hmac-sha256":
        expected_total = HEADER_22B_SIZE + payload_len + 32
        if len(data) < expected_total:
            raise ValueError("Missing HMAC-SHA256 authentication tag")
        wire_mac = data[HEADER_22B_SIZE + payload_len:expected_total]
        computed_mac = hmac.new(config.auth_key, data[:HEADER_22B_SIZE + payload_len], hashlib.sha256).digest()
        if not hmac.compare_digest(wire_mac, computed_mac):
            raise ValueError("Envelope HMAC-SHA256 authentication verification failed!")

    return payload, True
