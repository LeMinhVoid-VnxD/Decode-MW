import struct, re

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libSandBoxEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

pe_offset = struct.unpack('<I', dll[0x3C:0x40])[0]
num_sections = struct.unpack('<H', dll[pe_offset+6:pe_offset+8])[0]
opt_hdr_size = struct.unpack('<H', dll[pe_offset+20:pe_offset+22])[0]
section_start = pe_offset + 24 + opt_hdr_size

sections = []
for i in range(num_sections):
    sec = dll[section_start + i*40 : section_start + (i+1)*40]
    name = sec[:8].rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack('<I', sec[8:12])[0]
    virt_addr = struct.unpack('<I', sec[12:16])[0]
    raw_size = struct.unpack('<I', sec[16:20])[0]
    raw_off = struct.unpack('<I', sec[20:24])[0]
    sections.append((name, virt_addr, virt_size, raw_off, raw_size))

def off2rva(off):
    for name, va, vs, ro, rs in sections:
        if ro <= off < ro + rs:
            return off - ro + va
    return None

# Search for exactly 16-byte printable ASCII strings in .rdata section
print("=== 16-byte printable ASCII strings in .rdata ===")
rdata_raw_off = None
rdata_raw_end = None
for name, va, vs, ro, rs in sections:
    if name == '.rdata':
        rdata_raw_off = ro
        rdata_raw_end = ro + rs
        break

if rdata_raw_off:
    rdata = dll[rdata_raw_off:rdata_raw_end]
    # Find all 16-byte sequences of printable ASCII
    i = 0
    while i < len(rdata) - 15:
        chunk = rdata[i:i+16]
        if all(32 <= b <= 126 for b in chunk):
            # Check that byte before is not printable (start of string) or at boundary
            prev_ok = (i == 0 or not (32 <= rdata[i-1] <= 126))
            # Check that byte after is not printable (end of string) or at boundary
            next_ok = (i+16 >= len(rdata) or not (32 <= rdata[i+16] <= 126))
            if prev_ok and next_ok:
                s = chunk.decode('ascii')
                rva = off2rva(rdata_raw_off + i)
                # Skip if it looks like a C++ mangled name
                if not any(c in s for c in '?@.<>'):
                    print(f'  0x{rva:08X}: "{s}"')
            i += 1
        else:
            i += 1

print()
print("=== 16-byte lowercase alpha-only strings in .rdata ===")
i = 0
while i < len(rdata) - 15:
    chunk = rdata[i:i+16]
    if all(97 <= b <= 122 for b in chunk):
        prev_ok = (i == 0 or not (97 <= rdata[i-1] <= 122))
        next_ok = (i+16 >= len(rdata) or not (97 <= rdata[i+16] <= 122))
        if prev_ok and next_ok:
            s = chunk.decode('ascii')
            rva = off2rva(rdata_raw_off + i)
            print(f'  0x{rva:08X}: "{s}"')
        i += 1
    else:
        i += 1

# Also search for any 16-byte string in .text section that could be an inline key
print()
print("=== Potential inline 16-byte keys in .text ===")
text_raw_off = None
text_raw_end = None
for name, va, vs, ro, rs in sections:
    if name == '.text':
        text_raw_off = ro
        text_raw_end = ro + rs
        break

if text_raw_off:
    text = dll[text_raw_off:text_raw_end]
    i = 0
    count = 0
    while i < len(text) - 15 and count < 30:
        chunk = text[i:i+16]
        if all(32 <= b <= 126 for b in chunk):
            s = chunk.decode('ascii')
            # Skip common noise
            if not any(c in s for c in '?@.<>{}[]()!$%^&#'):
                prev_ok = (i == 0 or not (32 <= text[i-1] <= 126))
                next_ok = (i+16 >= len(text) or not (32 <= text[i+16] <= 126))
                if prev_ok and next_ok and len(s.strip()) == 16:
                    rva = off2rva(text_raw_off + i)
                    print(f'  0x{rva:08X}: "{s}"')
                    count += 1
            i += 1
        else:
            i += 1
