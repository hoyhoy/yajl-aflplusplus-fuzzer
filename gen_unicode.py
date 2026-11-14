#!/usr/bin/env python3
# gen_unicode_dict.py > unicode.dict
seen, out = set(), []

def add(name, b):
    if not (0 < len(b) <= 128) or b in seen:   # AFL++ tokens max out at 128 bytes
        return
    seen.add(b)
    out.append('%s="%s"' % (name, ''.join('\\x%02x' % c for c in b)))

def enc(cp):
    """Generalized UTF-8 encoder: also emits surrogates and values > U+10FFFF."""
    if cp < 0x80:    return bytes([cp])
    if cp < 0x800:   return bytes([0xC0 | cp >> 6, 0x80 | cp & 0x3F])
    if cp < 0x10000: return bytes([0xE0 | cp >> 12, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])
    return bytes([0xF0 | cp >> 18, 0x80 | cp >> 12 & 0x3F, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])

def overlong(cp, n):
    if n == 2: return bytes([0xC0 | cp >> 6, 0x80 | cp & 0x3F])
    if n == 3: return bytes([0xE0 | cp >> 12, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])
    return bytes([0xF0 | cp >> 18, 0x80 | cp >> 12 & 0x3F, 0x80 | cp >> 6 & 0x3F, 0x80 | cp & 0x3F])

# 1. Boundary and special code points: raw UTF-8 and JSON \u escapes
cps = [0x7F, 0x80, 0x85, 0xA0, 0xFF, 0x7FF, 0x800, 0x2028, 0x2029, 0xFEFF,
       0xFFFD, 0xFFFE, 0xFFFF, 0x10000, 0x1F600, 0x1FFFE, 0x10FFFE, 0x10FFFF,
       0x200B, 0x200C, 0x200D, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E,
       0x2066, 0x2067, 0x2068, 0x2069, 0x0300, 0x0301, 0x034F, 0xFDD0, 0xFDEF,
       0xE000, 0xF8FF, 0xE0001, 0xE007F]
for cp in cps:
    add("u_%X" % cp, enc(cp))
    if cp <= 0xFFFF:
        add("esc_%X" % cp, b"\\u%04x" % cp)
        add("escU_%X" % cp, b"\\u%04X" % cp)

# 2. Beyond Unicode range (invalid, but encoders produce them)
for cp in (0x110000, 0x1FFFFF, 0x200000, 0x3FFFFFF):
    add("beyond_%X" % cp, enc(cp) if cp < 0x200000 else bytes([0xF8, 0x88, 0x80, 0x80, 0x80]))

# 3. Raw surrogates (CESU-8 style) and JSON surrogate escapes
for cp in (0xD800, 0xDBFF, 0xDC00, 0xDFFF):
    add("rawsur_%X" % cp, enc(cp))
    add("escsur_%X" % cp, b"\\u%04x" % cp)
add("sur_pair_ok",       b"\\ud83d\\ude00")
add("sur_pair_rev",      b"\\ude00\\ud83d")
add("sur_hi_hi",         b"\\ud83d\\ud83d")
add("sur_lo_lo",         b"\\ude00\\ude00")
add("sur_hi_then_text",  b"\\ud83dx")
add("sur_hi_then_esc",   b"\\ud83d\\u0041")
add("sur_cesu_pair",     enc(0xD83D) + enc(0xDE00))

# 4. Overlong encodings of sensitive characters
for cp, nm in ((0x00, "nul"), (0x22, "quote"), (0x2F, "slash"), (0x5C, "bslash"),
               (0x41, "A"), (0x7F, "del"), (0x0A, "lf"), (0x20, "sp")):
    for n in (2, 3, 4):
        add("overlong%d_%s" % (n, nm), overlong(cp, n))
add("c0_80", b"\xc0\x80")
add("e0_80_80", b"\xe0\x80\x80")
add("f0_80_80_80", b"\xf0\x80\x80\x80")
add("e0_9f_bf", b"\xe0\x9f\xbf")        # overlong, just under U+0800
add("f0_8f_bf_bf", b"\xf0\x8f\xbf\xbf") # overlong, just under U+10000

# 5. Invalid bytes, stray continuations, truncated sequences
for b in (0x80, 0xBF, 0xC0, 0xC1, 0xF5, 0xF8, 0xFC, 0xFE, 0xFF):
    add("byte_%02x" % b, bytes([b]))
for lead in (0xC2, 0xDF, 0xE0, 0xE1, 0xED, 0xEF, 0xF0, 0xF1, 0xF4):
    add("lead_%02x" % lead, bytes([lead]))
add("trunc_e2_82", b"\xe2\x82")
add("trunc_f0_9f_98", b"\xf0\x9f\x98")
add("trunc_f4_8f_bf", b"\xf4\x8f\xbf")
add("f4_90_80_80", b"\xf4\x90\x80\x80")   # just above U+10FFFF
add("ed_a0_80", b"\xed\xa0\x80")
add("e2_28_a1", b"\xe2\x28\xa1")          # bad continuation
add("f0_28_8c_bc", b"\xf0\x28\x8c\xbc")
add("cont_run", b"\x80\x80\x80\x80")
add("lead_then_quote", b"\xc3\x22")        # swallowed closing quote
add("lead_then_bslash", b"\xc3\x5c")       # swallowed backslash
add("lead_then_nul", b"\xe2\x00")

# 6. BOMs and wide-encoding artifacts (UTF-16/32 text parsed as bytes)
add("bom_utf8",    b"\xef\xbb\xbf")
add("bom_utf16le", b"\xff\xfe")
add("bom_utf16be", b"\xfe\xff")
add("bom_utf32le", b"\xff\xfe\x00\x00")
add("bom_utf32be", b"\x00\x00\xfe\xff")
add("utf16le_obj", b'{\x00"\x00a\x00"\x00:\x001\x00}\x00')
add("utf16be_obj", b'\x00{\x00"\x00a\x00"\x00:\x001\x00}')

# 7. Composed sequences
add("zwj_family", enc(0x1F468) + enc(0x200D) + enc(0x1F469) + enc(0x200D) + enc(0x1F467))
add("flag_us",    enc(0x1F1FA) + enc(0x1F1F8))
add("skin_tone",  enc(0x1F44D) + enc(0x1F3FD))
add("combining_stack", b"a" + b"".join(enc(0x300 + i) for i in range(8)))
add("rlo_text",   enc(0x202E) + b"abc" + enc(0x202C))
add("tag_seq",    enc(0x1F3F4) + b"".join(enc(0xE0000 + c) for c in b"gbeng") + enc(0xE007F))
add("nul_in_str", b'"a\\u0000b"')
add("nul_raw_str", b'"a\x00b"')

print("\n".join(out))
