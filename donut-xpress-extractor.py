# Minimal Donut XPRESS extractor (Windows only).
# Extracts XPRESS-compressed payload assuming inline header: [comp_size decomp_size] (little endian).

import argparse, ctypes, os, sys

COMPRESSION_FORMAT_XPRESS = 0x0003
STATUS_SUCCESS = 0x00000000
STATUS_BUFFER_TOO_SMALL = 0xC0000023

def rtl_decompress_xpress(comp_bytes: bytes, want_uncompressed: int) -> bytes:
    ntdll = ctypes.WinDLL("ntdll")
    fn = ntdll.RtlDecompressBuffer
    fn.argtypes = [
        ctypes.c_ushort, ctypes.c_void_p, ctypes.c_uint32,
        ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)
    ]
    fn.restype = ctypes.c_uint32

    src = ctypes.create_string_buffer(comp_bytes)
    out_sz = max(want_uncompressed, 0x10000)
    MAX_OUT = 512 * 1024 * 1024

    while True:
        dst = ctypes.create_string_buffer(out_sz)
        final = ctypes.c_uint32(0)
        st = fn(COMPRESSION_FORMAT_XPRESS,
                dst, ctypes.c_uint32(out_sz),
                src, ctypes.c_uint32(len(comp_bytes)),
                ctypes.byref(final))
        if st == STATUS_SUCCESS:
            return dst.raw[:final.value]
        if st == STATUS_BUFFER_TOO_SMALL:
            out_sz *= 2
            if out_sz > MAX_OUT:
                raise RuntimeError("Uncompressed buffer exceeded cap")
            continue
        raise RuntimeError(f"RtlDecompressBuffer failed NTSTATUS=0x{st:X}")

def plausible(comp_sz: int, decomp_sz: int, remain: int) -> bool:
    if comp_sz <= 64 or decomp_sz < comp_sz: return False
    if comp_sz > remain: return False
    if decomp_sz > (512 * 1024 * 1024): return False
    if (decomp_sz / max(comp_sz, 1)) > 64.0: return False
    return True

def main():
    if os.name != "nt":
        print("Windows only")
        sys.exit(1)
        
    ap = argparse.ArgumentParser(description="Quick Donut XPRESS extractor")
    ap.add_argument("-i", "--input", required=True)
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--max-start", type=lambda x:int(x,0), default=0x2000,
                    help="Max header start offset to scan (default 0x2000)")
    args = ap.parse_args()



    data = open(args.input, "rb").read()
    limit = min(len(data) - 8, args.max_start)

    for off in range(0, limit + 1):
        comp = int.from_bytes(data[off:off+4], "little", signed=False)
        decomp = int.from_bytes(data[off+4:off+8], "little", signed=False)

        if not plausible(comp, decomp, len(data) - (off + 8)):
            continue

        comp_start = off + 8
        comp_end = comp_start + comp
        comp_bytes = data[comp_start:comp_end]

        try:
            dec = rtl_decompress_xpress(comp_bytes, decomp)
        except Exception:
            continue

        print(f"[+] Header @          0x{off:X}")
        print(f"[+] Compressed data @ 0x{comp_start:X}")
        print(f"    Comp size       : 0x{comp:X}")
        print(f"    Decomp size     : 0x{decomp:X}")
        print(f"    Decomp result   : 0x{len(dec):X} -> {'OK' if len(dec)==decomp else 'mismatch'}")

        with open(args.output, "wb") as f:
            f.write(dec)

        print(f"[+] Wrote to: {args.output}")
        return

    print("[-] No matching XPRESS stream found in the scanned range.")
    sys.exit(2)

if __name__ == "__main__":
    main()
