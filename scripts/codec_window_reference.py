#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 the http contributors
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Regenerate small RFC 9842 window fixtures with independent native codecs.

No library-under-test code is imported. Run in the retained Linux reference
image with --network none --cpus 2 --memory 2g --memory-swap 2g, using --check
or --write. The normal EUnit tests need neither Python nor these libraries.
The shared-library bytes and versions are verified before and after use.
Synthetic input/sequence recipes are ours; no upstream implementation is copied.
API references: google/brotli v1.1.0 c/include/brotli/{encode,decode}.h;
facebook/zstd v1.5.5 lib/zstd.h (ZSTD_compressSequences and usingDict).
"""

import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "test/fixtures/codec-window"
LIBRARIES = {
    "libbrotlicommon.so.1.1.0": "a91ead095d2c80520c55a89057bbe10b031a075340442e63f44b310f93883a1b",
    "libbrotlidec.so.1.1.0": "64d8a5019d4c294b89fde1193343ea324bbd8603652554e5545f0a01595fa2c5",
    "libbrotlienc.so.1.1.0": "6e59301f6c3a05815ecc6cd8c56714280367da1f6737e9f077f5847d86c509f2",
    "libzstd.so.1.5.5": "0a2128bc10841fb29e76d08d945864dfb0b6a66da5df6df5d8299197439e54bb",
}
LIB_ROOT = Path("/usr/lib/x86_64-linux-gnu")
PREFIX = b"".join(hashlib.sha256(b"RFC9842 independent window prefix" + bytes([i])).digest() for i in range(4))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check(condition):
    if not condition:
        raise ValueError("independent reference contract failed")


def libraries():
    observed = {name: sha((LIB_ROOT / name).read_bytes()) for name in LIBRARIES}
    if observed != LIBRARIES:
        raise ValueError("reference library identity mismatch")
    return observed


def api(lib, name, result, *args):
    function = getattr(lib, name)
    function.restype, function.argtypes = result, args
    return function


class Sequence(C.Structure):
    _fields_ = [(name, C.c_uint) for name in ("offset", "litLength", "matchLength", "rep")]


def zstandard():
    z = C.CDLL(str(LIB_ROOT / "libzstd.so.1.5.5"))
    size, ptr = C.c_size_t, C.c_void_p
    api(z, "ZSTD_versionNumber", C.c_uint)
    check(z.ZSTD_versionNumber() == 10505)
    api(z, "ZSTD_isError", C.c_uint, size)
    api(z, "ZSTD_createCCtx", ptr)
    api(z, "ZSTD_freeCCtx", size, ptr)
    api(z, "ZSTD_CCtx_setParameter", size, ptr, C.c_int, C.c_int)
    api(z, "ZSTD_CCtx_loadDictionary", size, ptr, ptr, size)
    api(z, "ZSTD_compressBound", size, size)
    api(z, "ZSTD_compressSequences", size, ptr, ptr, size, C.POINTER(Sequence), size, ptr, size)
    api(z, "ZSTD_createDCtx", ptr)
    api(z, "ZSTD_freeDCtx", size, ptr)
    api(z, "ZSTD_decompress_usingDict", size, ptr, ptr, size, ptr, size, ptr, size)
    return z


def zstd_fixture(z, log):
    def checked(value):
        if z.ZSTD_isError(value):
            raise ValueError("reference Zstandard failure")
        return value

    window = 1 << log
    # The last sequence reaches the FIRST dictionary byte across the entire intervening output.
    # A header-only/small-distance test cannot satisfy it.
    dictionary = PREFIX + b"d" * (window * 4 // 5 + 1 - len(PREFIX))
    literals = window - len(dictionary)
    data = b"x" * literals + PREFIX
    sequences = (Sequence * 2)(Sequence(1, 1, literals - 1, 0), Sequence(window, 0, 128, 0))
    src, out = C.create_string_buffer(data), C.create_string_buffer(z.ZSTD_compressBound(len(data)))
    ctx = z.ZSTD_createCCtx()
    check(ctx)
    try:
        checked(z.ZSTD_CCtx_setParameter(ctx, 101, log))  # ZSTD_c_windowLog
        checked(z.ZSTD_CCtx_setParameter(ctx, 200, 0))    # ZSTD_c_contentSizeFlag
        checked(z.ZSTD_CCtx_loadDictionary(ctx, dictionary, len(dictionary)))
        count = checked(z.ZSTD_compressSequences(ctx, out, len(out), sequences, 2, src, len(data)))
    finally:
        checked(z.ZSTD_freeCCtx(ctx))
    encoded = out.raw[:count]
    check(encoded[:4] == bytes.fromhex("28b52ffd") and encoded[4] & 32 == 0)
    wd = encoded[5]
    base = 1 << ((wd >> 3) + 10)
    check(base + (base >> 3) * (wd & 7) == window)
    dst, dec = C.create_string_buffer(len(data)), z.ZSTD_createDCtx()
    check(dec)
    try:
        count = checked(z.ZSTD_decompress_usingDict(dec, dst, len(dst), encoded, len(encoded), dictionary, len(dictionary)))
        check(count == len(data) and sha(dst.raw) == sha(data))
        # Remove only the referenced prefix without changing dictionary size.
        # The independent decoder must then produce a different result (or fail).
        wrong = b"?" * 128 + dictionary[128:]
        wrong_count = z.ZSTD_decompress_usingDict(dec, dst, len(dst), encoded, len(encoded), wrong, len(wrong))
        check(z.ZSTD_isError(wrong_count) or sha(dst.raw) != sha(data))
        missing = z.ZSTD_decompress_usingDict(dec, dst, len(dst), encoded, len(encoded), None, 0)
        check(z.ZSTD_isError(missing))
    finally:
        checked(z.ZSTD_freeDCtx(dec))
    return encoded, {
        "coding": "dcz", "file": f"zstd-window-{log}.zst", "window_log": log,
        "window_bytes": window, "backward_distance": window,
        "dictionary_bytes": len(dictionary), "dictionary_sha256": sha(dictionary),
        "output_bytes": len(data), "output_sha256": sha(data),
        "reference_decoder_verified": True, "missing_dictionary_rejected": True,
        "modified_prefix_changes_result": True,
        "decoder_cap_boundary": log == 27,
        "sequences": [[s.offset, s.litLength, s.matchLength] for s in sequences],
    }


def brotli_fixture():
    enc = C.CDLL(str(LIB_ROOT / "libbrotlienc.so.1.1.0"))
    dec = C.CDLL(str(LIB_ROOT / "libbrotlidec.so.1.1.0"))
    size, ptr = C.c_size_t, C.c_void_p
    api(enc, "BrotliEncoderVersion", C.c_uint)
    check(enc.BrotliEncoderVersion() == 0x1001000)
    api(enc, "BrotliEncoderMaxCompressedSize", size, size)
    api(enc, "BrotliEncoderCompress", C.c_int, C.c_int, C.c_int, C.c_int, size, ptr, C.POINTER(size), ptr)
    api(dec, "BrotliDecoderDecompress", C.c_int, size, ptr, C.POINTER(size), ptr)
    window = (1 << 24) - 16  # RFC 7932 WBITS 24 maximum backward distance.
    data = PREFIX + b"x" * (window - len(PREFIX)) + PREFIX
    src, out = C.create_string_buffer(data), C.create_string_buffer(enc.BrotliEncoderMaxCompressedSize(len(data)))
    count = size(len(out))
    check(enc.BrotliEncoderCompress(11, 24, 0, len(data), src, C.byref(count), out) == 1)
    encoded = out.raw[:count.value]
    dst, count = C.create_string_buffer(len(data)), size(len(data))
    check(dec.BrotliDecoderDecompress(len(encoded), encoded, C.byref(count), dst) == 1)
    check(count.value == len(data) and sha(dst.raw) == sha(data))
    return encoded, {
        "coding": "dcb", "file": "brotli-window-24.br", "window_log": 24,
        "window_bytes": 1 << 24, "backward_distance": window,
        "dictionary_hex": b"RFC9842 independent raw prefix dictionary".hex(),
        "output_bytes": len(data), "output_sha256": sha(data),
        "reference_decoder_verified": True,
        "backward_reference_proof": "ordinary EUnit scalar production copy-distance trace",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--write", action="store_true")
    args = parser.parse_args()
    before = libraries()
    z = zstandard()
    artifacts, rows = {}, []
    for encoded, row in [brotli_fixture()] + [zstd_fixture(z, log) for log in range(23, 28)]:
        row.update(encoded_bytes=len(encoded), encoded_sha256=sha(encoded))
        artifacts[row["file"]] = encoded
        rows.append(row)
    check(before == libraries())
    manifest = {"schema": 1, "reference_libraries": before, "prefix_hex": PREFIX.hex(),
                "dictionary_recipe": "prefix + d padding to floor(4 * window / 5) + 1 bytes",
                "rows": rows}
    artifacts["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    FIXTURES.mkdir(parents=True, exist_ok=True)
    for name, data in artifacts.items():
        path = FIXTURES / name
        if args.write:
            path.write_bytes(data)
        elif path.read_bytes() != data:
            raise ValueError("retained fixture mismatch: " + name)
    print(json.dumps({"status": "Passed", "fixtures": len(rows), "reference_libraries_unchanged": True}))


if __name__ == "__main__":
    main()
