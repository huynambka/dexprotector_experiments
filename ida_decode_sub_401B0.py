import struct
import ida_bytes
import ida_kernwin

# ===== EDIT HERE =====
BLOB_EA = 0x2DCF
LENGTH  = 21
# =====================
TABLE = bytes.fromhex(
    "61d5ccc1cc0659b29b30e842f6fab3bd15edef6db465bf039775912d6e499aa"
    "20942d5d627bcafb8382f0055894fc3797529cb2ce6ec025423c8c33f6fd8b"
    "88065f72dca2a77a28a86a432549aab97cfa325cea8c96bbe3c0430df004b"
    "234a70dde895c6bd53d420909ae98a"
)
def u32(b, off):
    return struct.unpack_from("<I", b, off)[0]
def p32(x):
    return struct.pack("<I", x & 0xffffffff)
def ror32(x, n):
    x &= 0xffffffff
    return ((x >> n) | ((x << (32 - n)) & 0xffffffff)) & 0xffffffff
def decode_401B0(ea, length):
    blob = ida_bytes.get_bytes(ea, 8 + length)
    if blob is None:
        raise Exception("Cannot read blob at 0x%x" % ea)
    w9 = u32(blob, 0)  # a1[0]
    w8 = u32(blob, 4)  # a1[1]
    out = bytearray()
    ks = b"\x00" * 8
    for i in range(length):
        if (i & 7) == 0:
            for j in range(0, 0x6c, 4):
                t = u32(TABLE, j)
                w8 = (t ^ ((ror32(w8, 8) + w9) & 0xffffffff)) & 0xffffffff
                w9 = (w8 ^ ror32(w9, 29)) & 0xffffffff
            # sub_401B0 stores W9 first, then W8
            ks = p32(w9) + p32(w8)
        out.append(blob[8 + i] ^ ks[i & 7])
    return bytes(out)
res = decode_401B0(BLOB_EA, LENGTH)
try:
    s = res.rstrip(b"\x00").decode("utf-8")
except:
    s = repr(res)
ida_kernwin.msg("[sub_401B0] 0x%x len=%d -> %s\n" % (BLOB_EA, LENGTH, s))
ida_kernwin.msg("[hex] %s\n" % res.hex())