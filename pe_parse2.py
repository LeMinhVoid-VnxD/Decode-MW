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

# Read exports
opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
num_rva_and_sizes = struct.unpack('<I', opt_hdr[92:96])[0]
export_rva = struct.unpack('<I', opt_hdr[96:100])[0]
export_off = rva2off(export_rva)

e_flags = struct.unpack('<I', dll[export_off:export_off+4])[0]
base = struct.unpack('<I', dll[export_off+16:export_off+20])[0]
num_fns = struct.unpack('<I', dll[export_off+20:export_off+24])[0]
num_nms = struct.unpack('<I', dll[export_off+24:export_off+28])[0]
addr_fns = struct.unpack('<I', dll[export_off+28:export_off+32])[0]
addr_nms = struct.unpack('<I', dll[export_off+32:export_off+36])[0]
ordinals = struct.unpack('<I', dll[export_off+36:export_off+40])[0]

fn_off = rva2off(addr_fns)
nm_off = rva2off(addr_nms)
ord_off = rva2off(ordinals)

# Search for xxtea-related exports
print("=== XXTEA-related exports ===")
for j in range(num_nms):
    nr = struct.unpack('<I', dll[nm_off + j*4 : nm_off + j*4 + 4])[0]
    no = rva2off(nr)
    ord_ = struct.unpack('<H', dll[ord_off + j*2 : ord_off + j*2 + 2])[0]
    fr = struct.unpack('<I', dll[fn_off + ord_*4 : fn_off + ord_*4 + 4])[0]
    end = dll.index(b'\x00', no)
    s = dll[no:end].decode('ascii', errors='replace')
    if 'xxtea' in s.lower() or 'getXXTeaKey' in s or 'setXXTEAKey' in s or 'DevEncrypt' in s:
        fo = rva2off(fr)
        print(f'  {s}')
        print(f'    RVA=0x{fr:X}, file=0x{fo:X}')
        # Read first 64 bytes of function
        if fo:
            code = dll[fo:fo+64]
            print(f'    First 64 bytes: {code.hex()}')
            print()

# Also search for getXXTeaKey string in the file and find xrefs
print("=== getXXTeaKey occurrences ===")
search = b'getXXTeaKey'
pos = 0
while True:
    pos = dll.find(search, pos)
    if pos == -1:
        break
    rva = off2rva(pos)
    print(f'  Found at file offset 0x{pos:X}, RVA=0x{rva:X}')
    context = dll[max(0,pos-16):pos+len(search)+16]
    print(f'  Context: {context.hex()}')
    pos += 1

# Search for setXXTEAKeyAndSign
print()
print("=== setXXTEAKeyAndSign occurrences ===")
search = b'setXXTEAKeyAndSign'
pos = 0
while True:
    pos = dll.find(search, pos)
    if pos == -1:
        break
    rva = off2rva(pos)
    print(f'  Found at file offset 0x{pos:X}, RVA=0x{rva:X}')
    context = dll[max(0,pos-16):pos+len(search)+16]
    print(f'  Context: {context.hex()}')
    pos += 1

# Search for a0817i
print()
print("=== a0817i/sign occurrences ===")
for s in [b'a0817i', b'XXTEA']:
    search = s
    pos = 0
    while True:
        pos = dll.find(search, pos)
        if pos == -1:
            break
        rva = off2rva(pos)
        print(f'  \"{s.decode()}\" at file 0x{pos:X}, RVA=0x{rva:X}')
        context = dll[max(0,pos-8):pos+len(search)+8]
        print(f'    Context: {context}')
        pos += 1
