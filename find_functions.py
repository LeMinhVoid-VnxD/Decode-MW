import struct

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

def rva2off(rva):
    for name, va, vs, ro, rs in sections:
        if va <= rva < va + vs:
            return rva - va + ro
    return None

def off2rva(off):
    for name, va, vs, ro, rs in sections:
        if ro <= off < ro + rs:
            return off - ro + va
    return None

# Search for all function names as strings in the DLL
targets = [b'getXXTeaKey', b'xxtea_decrypt', b'xxtea_encrypt', b'xxtea_need_size', b'b64_encode']
for t in targets:
    print(f'\n=== "{t.decode()}" ===')
    pos = 0
    while True:
        pos = dll.find(t, pos)
        if pos == -1:
            break
        rva = off2rva(pos)
        # Show 64 bytes before and after
        start = max(0, pos - 32)
        end = min(len(dll), pos + len(t) + 64)
        context = dll[start:end]
        print(f'  File offset: 0x{pos:X}, RVA: 0x{rva:X} (section: ', end='')
        for name, va, vs, ro, rs in sections:
            if ro <= pos < ro + rs:
                print(name, end='')
                break
        print(')')
        
        # Show context as hex and ASCII
        print(f'  Hex: {context.hex()}')
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in context)
        print(f'  ASCII: {ascii_str}')
        
        # Try to find the function code that references this string
        # Search for xrefs (RVA of this string in .text section)
        if rva:
            rva_bytes = struct.pack('<I', rva)
            for xref_pos in range(0, len(dll) - 4):
                if dll[xref_pos:xref_pos+4] == rva_bytes:
                    xref_rva = off2rva(xref_pos)
                    if xref_rva:
                        for name, va, vs, ro, rs in sections:
                            if ro <= xref_pos < ro + rs:
                                print(f'  XREF at file 0x{xref_pos:X} RVA=0x{xref_rva:X} (section {name})')
                                break
        pos += 1
