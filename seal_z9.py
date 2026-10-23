#!/usr/bin/env python3
"""Seal a Z9 firmware: decrypt stock -> apply file-driven patches -> reseal ->
re-encrypt -> verify -> atomic write. (CLI hex can't carry a 1.5MB patch.)

  --body-patch PATH    replace the bird-model body inside the eg module;
                       auto-located by searching stock plaintext for the
                       original resource744 body bytes (must match uniquely)
  --eg-patches JSON    {eg_offset_hex: bytes_hex} windows (z9_patches.json)
  --selftest           no patches; output must be byte-identical to stock

  python -u seal_z9.py --out Z9_A.bin --body-patch new_body.bin
  python -u seal_z9.py --out Z9_B.bin --body-patch new_body.bin --eg-patches z9_patches.json
  python -u seal_z9.py --out NUL.bin --selftest --force
"""
import argparse, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# Paths of the toolkit that owns the container format and the signing key.
# Set NFP_TOOLKIT / Z9_KEY / Z9_SIG, or edit the defaults below.
FWT = os.environ.get("NFP_TOOLKIT", os.path.join(HERE, "nikon-fw-key-tool-main"))
sys.path.insert(0, FWT)
import decrypt_firmware as fw                       # noqa: E402
from repack_firmware import load_sig, sign, reseal  # noqa: E402

STOCK = os.environ.get("Z9_STOCK", os.path.join(HERE, "Z_9_0532.bin"))
KEY = os.environ.get("Z9_KEY", os.path.join(HERE, "nikon_key.json"))
SIG = os.environ.get("Z9_SIG", os.path.join(HERE, "sig_z9.json"))
ORIG_BODY = os.environ.get("Z9_ORIG_BODY", os.path.join(HERE, "resource744.body.bin"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stock", default=STOCK)
    ap.add_argument("--out", required=True)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--body-patch")
    ap.add_argument("--eg-patches")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    fw.refuse_clobber(a.out, a.force)
    if os.path.realpath(a.out) == os.path.realpath(a.stock):
        fw.die(fw.EX_USAGE, "output is the same file as the input")
    if a.selftest and (a.body_patch or a.eg_patches):
        fw.die(fw.EX_USAGE, "--selftest makes no edits")

    key = fw.load_key(KEY)
    k8 = load_sig(SIG)
    raw = open(a.stock, "rb").read()
    fw.check_scheme(raw, a.stock)
    plain = fw.decrypt(raw, *key)
    try:
        mods = fw.validate_firmware(memoryview(plain)[fw.HDR:])
    except ValueError as exc:
        fw.die(fw.EX_SANITY, "%s: %s" % (a.stock, exc))
    if sign(plain[fw.HDR:], k8) != plain[:20]:
        fw.die(fw.EX_KEY, "K8 does not verify %s" % a.stock)
    print("stock decrypted, container valid, signature verified")

    hits = [m for m in mods if m[0].startswith("eg")]
    if len(hits) != 1:
        fw.die(fw.EX_SANITY, "eg prefix not unique: %s" % [m[0] for m in hits])
    mod_name, mstart, mlen = hits[0]
    print("eg module: %s at body 0x%x, 0x%x bytes" % (mod_name, mstart, mlen))

    body = bytearray(plain[fw.HDR:])
    edits = []

    if a.body_patch:
        orig = open(ORIG_BODY, "rb").read()
        new = open(a.body_patch, "rb").read()
        if len(new) != len(orig):
            fw.die(fw.EX_USAGE, "body patch is %d bytes, original body is %d"
                   % (len(new), len(orig)))
        eg = bytes(body[mstart:mstart + mlen - 2])
        off = eg.find(orig)
        if off < 0 or eg.find(orig, off + 1) >= 0:
            fw.die(fw.EX_SANITY, "original body not found uniquely in eg (off=%d)" % off)
        del eg
        body[mstart + off:mstart + off + len(new)] = new
        edits.append(("model body", off, len(new)))

    if a.eg_patches:
        P = json.load(open(a.eg_patches))
        for offhex, hexbytes in sorted(P.items(), key=lambda kv: int(kv[0], 16)):
            off = int(offhex, 16)
            data = bytes.fromhex(hexbytes)
            if off + len(data) > mlen - 2:
                fw.die(fw.EX_USAGE, "patch at eg+0x%x leaves the module payload" % off)
            body[mstart + off:mstart + off + len(data)] = data
            edits.append(("eg window", off, len(data)))

    digest = reseal(body, mods, k8)
    out_plain = digest + plain[20:fw.HDR] + bytes(body)
    del plain, body
    cipher = fw.decrypt(out_plain, *key)

    if fw.decrypt(cipher, *key) != out_plain:
        fw.die(8, "re-encryption did not round-trip; nothing written")
    try:
        fw.validate_firmware(memoryview(out_plain)[fw.HDR:])
    except ValueError as exc:
        fw.die(8, "our own output fails validation (%s); nothing written" % exc)
    if sign(out_plain[fw.HDR:], k8) != out_plain[:20]:
        fw.die(8, "our own output fails its signature; nothing written")
    if a.selftest and cipher != raw:
        fw.die(8, "selftest: output differs from the input in %d byte(s)"
               % sum(x != y for x, y in zip(cipher, raw)))

    tmp = a.out + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(cipher)
        os.replace(tmp, a.out)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        fw.die(fw.EX_USAGE, "cannot write %s: %s" % (a.out, exc))

    back = fw.decrypt(open(a.out, "rb").read(), *key)
    if back != out_plain:
        fw.die(8, "written file does not decrypt to the expected plaintext")

    print("\nwrote %s (%d bytes)" % (a.out, len(cipher)))
    for what, off, n in edits:
        print("  patched  %-10s eg+0x%x, %d byte(s)" % (what, off, n))
    print("  header SHA-1  %s" % digest.hex())
    print("  checksums     %d module CRCs + package CRC recomputed" % len(mods))
    print("  cipher bytes  %d differ from stock" % sum(x != y for x, y in zip(cipher, raw)))
    if a.selftest:
        print("  selftest      output is bit-identical to the input")


if __name__ == "__main__":
    main()
