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

opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
export_rva = struct.unpack('<I', opt_hdr[96:100])[0]
export_off = rva2off(export_rva)

base = struct.unpack('<I', dll[export_off+16:export_off+20])[0]
num_fns = struct.unpack('<I', dll[export_off+20:export_off+24])[0]
num_nms = struct.unpack('<I', dll[export_off+24:export_off+28])[0]
addr_fns = struct.unpack('<I', dll[export_off+28:export_off+32])[0]
addr_nms = struct.unpack('<I', dll[export_off+32:export_off+36])[0]
ordinals = struct.unpack('<I', dll[export_off+36:export_off+40])[0]

fn_off = rva2off(addr_fns)
nm_off = rva2off(addr_nms)
ord_off = rva2off(ordinals)

# List ALL export names and find getXXTeaKey and xxtea_decrypt by name
targets = ['getXXTeaKey', 'xxtea_decrypt', 'xxtea_encrypt', 'b64_encode', 'xxtea_need_size']
found_targets = {t: None for t in targets}

print(f'Searching {num_nms} export names...')
for j in range(num_nms):
    nr = struct.unpack('<I', dll[nm_off + j*4 : nm_off + j*4 + 4])[0]
    no = rva2off(nr)
    ord_ = struct.unpack('<H', dll[ord_off + j*2 : ord_off + j*2 + 2])[0]
    fr = struct.unpack('<I', dll[fn_off + ord_*4 : fn_off + ord_*4 + 4])[0]
    
    end = dll.index(b'\x00', no)
    s = dll[no:end].decode('ascii', errors='replace')
    
    for t in targets:
        if t in s:
            fo = rva2off(fr)
            found_targets[t] = (s, fr, fo, ord_)
            print(f'  Found "{t}" -> "{s}" @ RVA=0x{fr:X} file=0x{fo:X} ord={ord_}')
            
            if fo:
                code = dll[fo:fo+128]
                print(f'    Code hex: {code.hex()}')
                # Disassemble manually? Let's just show the bytes
                # Check if it's a simple function (small)
                print()

print()
for t, v in found_targets.items():
    if v is None:
        print(f'  NOT FOUND: {t}')

# Also look for the string "getXXTeaKey" in context to find what section format it uses
print()
print('Export name table entries around getXXTeaKey:')
target_rva = 0x231423A  # RVA of getXXTeaKey string
for j in range(num_nms):
    nr = struct.unpack('<I', dll[nm_off + j*4 : nm_off + j*4 + 4])[0]
    if nr == target_rva:
        print(f'  Found getXXTeaKey at export name index {j}')
        ord_ = struct.unpack('<H', dll[ord_off + j*2 : ord_off + j*2 + 2])[0]
        fr = struct.unpack('<I', dll[fn_off + ord_*4 : fn_off + ord_*4 + 4])[0]
        fo = rva2off(fr)
        print(f'  Ordinal: {ord_}, RVA=0x{fr:X}, file=0x{fo:X}')
        if fo:
            code = dll[fo:fo+256]
            print(f'  Code ({len(code)} bytes): {code.hex()}')
        # Print neighbors
        for idx in range(max(0,j-2), min(num_nms, j+3)):
            nr2 = struct.unpack('<I', dll[nm_off + idx*4 : nm_off + idx*4 + 4])[0]
            no2 = rva2off(nr2)
            ord2 = struct.unpack('<H', dll[ord_off + idx*2 : ord_off + idx*2 + 2])[0]
            fr2 = struct.unpack('<I', dll[fn_off + ord2*4 : fn_off + ord2*4 + 4])[0]
            end2 = dll.index(b'\x00', no2)
            s2 = dll[no2:end2].decode('ascii', errors='replace')
            print(f'    [{idx}] ord={ord2} name="{s2}" RVA=0x{fr2:X}')
        break
