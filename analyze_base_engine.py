import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libMiniBaseEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

pe_offset = struct.unpack('<I', dll[0x3C:0x40])[0]
num_sections = struct.unpack('<H', dll[pe_offset+6:pe_offset+8])[0]
opt_hdr_size = struct.unpack('<H', dll[pe_offset+20:pe_offset+22])[0]

opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
magic = struct.unpack('<H', opt_hdr[0:2])[0]
if magic == 0x10B:
    image_base = struct.unpack('<I', opt_hdr[28:32])[0]
    export_rva = struct.unpack('<I', opt_hdr[96:100])[0]
    print(f"PE32 ImageBase: 0x{image_base:08X}")
    print(f"Export RVA: 0x{export_rva:08X}")
elif magic == 0x20B:
    image_base = struct.unpack('<Q', opt_hdr[24:32])[0]
    export_rva = struct.unpack('<I', opt_hdr[112:116])[0]
    print(f"PE32+ ImageBase: 0x{image_base:016X}")

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
    print(f"  {name}: VA=0x{virt_addr:08X} VSz=0x{virt_size:X} RawOff=0x{raw_off:X} RawSz=0x{raw_size:X}")

def rva2off(rva):
    for name, va, vs, ro, rs in sections:
        if va <= rva < va + vs:
            return rva - va + ro
    return None

# Search for getXXTeaKey string and function
print()
print("=== Searching for getXXTeaKey ===")
for s in [b'getXXTeaKey', b'xxtea_decrypt', b'xxtea_encrypt', b'xxtea_need_size', b'b64_encode']:
    pos = 0
    while True:
        pos = dll.find(s, pos)
        if pos == -1:
            break
        for name, va, vs, ro, rs in sections:
            if ro <= pos < ro + rs:
                print(f'  "{s.decode()}" @ file 0x{pos:X} section {name}')
                rva = pos - ro + va
                # Show context
                start = max(ro, pos - 32)
                end = min(len(dll), pos + len(s) + 32)
                ctx = dll[start:end]
                print(f'    RVA=0x{rva:08X} context: {ctx.hex()}')
                break
        pos += 1

# Find exports related to xxtea
print()
print("=== Exports ===")
export_off = rva2off(export_rva)
if export_off:
    base = struct.unpack('<I', dll[export_off+16:export_off+20])[0]
    num_fns = struct.unpack('<I', dll[export_off+20:export_off+24])[0]
    num_nms = struct.unpack('<I', dll[export_off+24:export_off+28])[0]
    addr_fns = struct.unpack('<I', dll[export_off+28:export_off+32])[0]
    addr_nms = struct.unpack('<I', dll[export_off+32:export_off+36])[0]
    ordinals = struct.unpack('<I', dll[export_off+36:export_off+40])[0]
    
    fn_off = rva2off(addr_fns)
    nm_off = rva2off(addr_nms)
    ord_off = rva2off(ordinals)
    
    print(f"  Functions: {num_fns}, Names: {num_nms}, Base: {base}")
    
    for j in range(num_nms):
        nr = struct.unpack('<I', dll[nm_off + j*4 : nm_off + j*4 + 4])[0]
        no = rva2off(nr)
        ord_ = struct.unpack('<H', dll[ord_off + j*2 : ord_off + j*2 + 2])[0]
        fr = struct.unpack('<I', dll[fn_off + ord_*4 : fn_off + ord_*4 + 4])[0]
        end = dll.index(b'\x00', no)
        s = dll[no:end].decode('ascii', errors='replace')
        
        if any(k in s for k in ['xxtea', 'XXTea', 'Key', 'b64']):
            fo = rva2off(fr)
            print(f"  {s}")
            print(f"    ord={ord_}, RVA=0x{fr:08X}, file=0x{fo:X}")
