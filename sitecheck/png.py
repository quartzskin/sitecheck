import struct
import zlib


def _chunk(tag, body):
    return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body))


def encode_rgb(width, height, rgb):
    """rgb: top-down bytes, 3 per pixel."""
    if len(rgb) != width * height * 3:
        raise ValueError("pixel buffer does not match size")
    stride = width * 3
    raw = b"".join(b"\0" + rgb[y * stride:(y + 1) * stride] for y in range(height))
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)) + _chunk(b"IDAT", zlib.compress(raw, 6)) + _chunk(b"IEND", b"")
