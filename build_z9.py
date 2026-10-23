#!/usr/bin/env python3
"""Build the Z9 RAW pre-capture patch (dry-run by default).

Compile firmware_z9.c with zig cc -> link at CAVE=0x408c2570 -> produce the
Z9 patch table (hook sites / callback slots / loader / data words / blob) ->
verify every window against the unpatched Z9 EG image.

Usage: build_z9.py [--write OUTBIN]   (default: dry-run, writes nothing)
"""
import json, os, struct, subprocess, sys

TMP = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
# Decrypted (plain) Z9 firmware image; override with the Z9_DEC environment variable.
Z9_DEC = os.environ.get('Z9_DEC', os.path.join(TMP, 'Z_9_0532.dec'))
VA9 = 0x40160000
CAVE = 0x408C2570
CAVE_EGOFF = 0x762570
LOADER9 = 0x1029CA0
LOADER_END_PAD = 0x1000

sys.path.insert(0, TMP)
from linker_z9 import link

sm = json.load(open(TMP + r'\z9_sitemap.json'))
sites = {int(k, 16): int(v, 16) for k, v in sm['sites'].items()}
slots = {int(k): int(v, 16) for k, v in sm['slots'].items()}

z9 = open(Z9_DEC, 'rb').read()
EG_OFF, EG_END = 0x8E0F4 + 0x20, 0x8E0F4 + 0x04E0878F
eg9 = bytearray(z9[EG_OFF:EG_END])

# ---------- compile ----------
FLAGS = ['-target', 'aarch64-freestanding-none', '-O2', '-ffreestanding', '-fno-builtin',
         '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
         '-mgeneral-regs-only', '-mstrict-align', '-Wall', '-Wextra', '-Werror',
         '-I', os.path.join(TMP, 'nfp', 'NikonFirmwarePatch-main', 'z8precapture')]
obj = os.path.join(TMP, 'patch_z9.o')
cmd = [PY, '-m', 'ziglang', 'cc', *FLAGS, '-c', os.path.join(TMP, 'firmware_z9.c'), '-o', obj]
print('+', ' '.join(cmd[2:6]), '... (zig cc)')
r = subprocess.run(cmd, capture_output=True, text=True)
if r.returncode != 0:
    print(r.stderr[-6000:])
    raise SystemExit('compile failed')
code, sections, symbols, relocs = link(open(obj, 'rb').read())
print(f'linked blob: {len(code)} bytes at {CAVE:#x}')
E = {k: int(v['va'], 16) for k, v in symbols.items()}
NEED = ['precapture_history_entry', 'precapture_tdec_release', 'precapture_write_file',
        'precapture_main_rc', 'precapture_current_entry', 'precapture_y_size_entry',
        'precapture_y_alloc_entry', 'precapture_main_step', 'precapture_tenc_config',
        'precapture_e_alloc', 'precapture_e_size', 'precapture_tdec_sel_entry',
        'precapture_gui_mode', 'precapture_ui_mode', 'precapture_cap_update',
        'precapture_ready_margin', 'precapture_quality_code', 'precapture_quality_star',
        'precapture_ordinary_code', 'precapture_ordinary_star', 'precapture_display_mode']
missing = [n for n in NEED if n not in E]
if missing:
    raise SystemExit('missing entry symbols: ' + ', '.join(missing))
assert E['precapture_history_entry'] == CAVE

loader_end = CAVE + ((len(code) + LOADER_END_PAD - 1) // LOADER_END_PAD) * LOADER_END_PAD
print(f'loader copy end: {loader_end:#x}')


def bl(at_va, to_va, tail=False):
    d = to_va - at_va
    assert d % 4 == 0 and -(1 << 27) <= d < (1 << 27), f'branch range {at:#x}->{to_va:#x}'
    return struct.pack('<I', (0x14000000 if tail else 0x94000000) | ((d // 4) & 0x3FFFFFF))


def movpair_x8(val):
    movz = 0xD2800000 | ((val & 0xFFFF) << 5) | 8
    movk = 0xF2A00000 | (((val >> 16) & 0xFFFF) << 5) | 8
    return struct.pack('<II', movz, movk)


# ---------- patch table (keyed by z8 eg offset so it mirrors patcher.py) ----------
P = {}   # z9 eg offset -> (bytes, purpose)


def put8(z8eg, raw, purpose):
    P[sites[z8eg]] = (raw, purpose)


def BL8(z8eg, entry, purpose, delta=0):
    at9 = sites[z8eg]
    put8(z8eg, bl(VA9 + at9 + delta, E[entry]), purpose)


BL8(0xe0fe90, 'precapture_history_entry', 'P8 submit history')
put8(0xd4915c, bytes.fromhex('e00317aa') + bl(VA9 + sites[0xd4915c] + 4, E['precapture_tdec_release']) + bytes.fromhex('1f2003d5'), 'tdec release')
BL8(0xd43638, 'precapture_write_file', 'write file')
BL8(0xd4eb60, 'precapture_main_rc', 'P7 main rc')
BL8(0xe0ff38, 'precapture_current_entry', 'submit current')
BL8(0xee8e1c, 'precapture_y_size_entry', 'B y_size')
BL8(0xd49fac, 'precapture_y_alloc_entry', 'A y_alloc')
BL8(0xd4eeec, 'precapture_main_step', 'J main step')
BL8(0xd4ef10, 'precapture_main_step', 'J main step')
put8(0x4d2ffc0, struct.pack('<I', 0x1082600), 'E alloc HE')
put8(0x4d2ffcc, struct.pack('<I', 0x1082600), 'E alloc HE*')

for z8eg, entry in ((0xd39798, 'precapture_tenc_config'), (0xeedf14, 'precapture_e_alloc'),
                    (0xd397c8, 'precapture_e_size'), (0xe38c4c, 'precapture_e_size'),
                    (0xe3a0b4, 'precapture_e_size'), (0xd49048, 'precapture_tdec_sel_entry'),
                    (0x24cce8, 'precapture_gui_mode'), (0xe36c90, 'precapture_ready_margin'),
                    (0xbe9044, 'precapture_ui_mode'), (0xbe24f0, 'precapture_ui_mode')):
    BL8(z8eg, entry, entry)
for z8eg in (0xd64640, 0xd66a8c, 0xdc4e08, 0xeb4b1c, 0xf871f8):
    at9 = sites[z8eg]
    put8(z8eg, bl(VA9 + at9, E['precapture_cap_update'], tail=z8eg == 0xd64640), 'cap_update')

CB = {93: 'precapture_display_mode', 112: 'precapture_quality_code', 113: 'precapture_quality_code',
      114: 'precapture_ordinary_code', 115: 'precapture_ordinary_code', 116: 'precapture_quality_star',
      117: 'precapture_ordinary_star', 129: 'precapture_display_mode', 130: 'precapture_display_mode'}
for idx, entry in CB.items():
    P[slots[idx]] = (struct.pack('<Q', E[entry]), f'callback {idx}')

P[LOADER9] = (movpair_x8(loader_end), 'loader extend')
P[CAVE_EGOFF] = (code, 'blob')

# ---------- verify against unpatched eg9 ----------
fails = 0
for off, (raw, why) in sorted(P.items()):
    cur = bytes(eg9[off:off + len(raw)])
    if off == CAVE_EGOFF:
        ok = cur == bytes(len(cur))  # cave must be zero
    elif off == LOADER9:
        w0, w1 = struct.unpack('<II', cur)
        ok = ((w0 >> 23) & 0x3F) == 0x25 and ((w1 >> 23) & 0x3F) == 0x25
    elif why.startswith('callback'):
        q = struct.unpack('<Q', cur)[0]
        ok = 0x40160000 < q < 0x40160000 + len(eg9)  # original callback VA in range
    elif why.startswith('E alloc'):
        ok = struct.unpack('<I', cur)[0] == 0x01082400
    elif why == 'precapture_tdec_sel_entry':
        ok = cur == bytes(eg9[off:off + 4])  # original is `mov w9,#2`, any word accepted
    elif len(raw) == 4:
        w = struct.unpack('<I', cur)[0]
        ok = (w & 0x7C000000) == 0x14000000  # original is B/BL
    else:
        ok = True
    if not ok:
        fails += 1
        print(f'  !! {off:#08x} {why}: original bytes unexpected: {cur[:16].hex()}')
print(f'patch windows: {len(P)}, verify failures: {fails}')

json.dump({hex(k): v[0].hex() for k, v in P.items()}, open(TMP + r'\z9_patches.json', 'w'), indent=1)
json.dump({k: hex(v) for k, v in E.items() if k in NEED}, open(TMP + r'\z9_entries.json', 'w'), indent=1)
print('wrote z9_patches.json + z9_entries.json (dry run, firmware untouched)')
