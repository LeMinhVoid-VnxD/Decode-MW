import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libSandBoxEngine.dll'
with open(dll_path, 'rb') as f:
    dll = f.read()

pe_offset = struct.unpack('<I', dll[0x3C:0x40])[0]
print(f'PE signature at 0x{pe_offset:X}: {dll[pe_offset:pe_offset+4]}')

file_hdr = dll[pe_offset+4:pe_offset+24]
num_sections = struct.unpack('<H', file_hdr[2:4])[0]
opt_hdr_size = struct.unpack('<H', file_hdr[16:18])[0]
print(f'Sections: {num_sections}, OptHdrSize: {opt_hdr_size}')

opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
magic = struct.unpack('<H', opt_hdr[0:2])[0]
print(f'Optional Magic: 0x{magic:X}')

section_start = pe_offset + 24 + opt_hdr_size
print(f'Section headers at: 0x{section_start:X}')

for i in range(num_sections):
    sec = dll[section_start + i*40 : section_start + (i+1)*40]
    name_raw = sec[:8]
    name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack('<I', sec[8:12])[0]
    virt_addr = struct.unpack('<I', sec[12:16])[0]
    raw_size = struct.unpack('<I', sec[16:20])[0]
    raw_off = struct.unpack('<I', sec[20:24])[0]
    char = struct.unpack('<I', sec[36:40])[0]
    print(f'  [{i}] \"{name}\": VA=0x{virt_addr:08X} VSz=0x{virt_size:X} RawOff=0x{raw_off:X} RawSz=0x{raw_size:X} Char=0x{char:08X}')

# Export directory for PE32
num_rva_and_sizes = struct.unpack('<I', opt_hdr[92:96])[0]
export_rva = struct.unpack('<I', opt_hdr[96:100])[0]
export_size = struct.unpack('<I', opt_hdr[100:104])[0]
print(f'\nExport: RVA=0x{export_rva:X} Size=0x{export_size:X}')

# Check which section contains export
for i in range(num_sections):
    sec = dll[section_start + i*40 : section_start + (i+1)*40]
    name_raw = sec[:8]
    name = name_raw.rstrip(b'\x00').decode('ascii', errors='replace')
    virt_size = struct.unpack('<I', sec[8:12])[0]
    virt_addr = struct.unpack('<I', sec[12:16])[0]
    raw_size = struct.unpack('<I', sec[16:20])[0]
    raw_off = struct.unpack('<I', sec[20:24])[0]
    if virt_addr <= export_rva < virt_addr + virt_size:
        export_off = export_rva - virt_addr + raw_off
        print(f'Export in section [{i}] \"{name}\", file offset=0x{export_off:X}')
        # Parse export directory
        e_flags = struct.unpack('<I', dll[export_off:export_off+4])[0]
        e_ts = struct.unpack('<I', dll[export_off+4:export_off+8])[0]
        e_maj = struct.unpack('<H', dll[export_off+8:export_off+10])[0]
        e_min = struct.unpack('<H', dll[export_off+10:export_off+12])[0]
        name_rva = struct.unpack('<I', dll[export_off+12:export_off+16])[0]
        base = struct.unpack('<I', dll[export_off+16:export_off+20])[0]
        num_fns = struct.unpack('<I', dll[export_off+20:export_off+24])[0]
        num_nms = struct.unpack('<I', dll[export_off+24:export_off+28])[0]
        addr_fns = struct.unpack('<I', dll[export_off+28:export_off+32])[0]
        addr_nms = struct.unpack('<I', dll[export_off+32:export_off+36])[0]
        ordinals = struct.unpack('<I', dll[export_off+36:export_off+40])[0]
        print(f'  Functions: {num_fns}, Names: {num_nms}, Base: {base}')
        
        def rva2off(rva):
            for j in range(num_sections):
                s = dll[section_start + j*40 : section_start + (j+1)*40]
                sv = struct.unpack('<I', s[12:16])[0]
                ss = struct.unpack('<I', s[8:12])[0]
                so = struct.unpack('<I', s[20:24])[0]
                if sv <= rva < sv + ss:
                    return rva - sv + so
            return None
        
        fn_off = rva2off(addr_fns)
        nm_off = rva2off(addr_nms)
        ord_off = rva2off(ordinals)
        
        for j in range(num_nms):
            nr = struct.unpack('<I', dll[nm_off + j*4 : nm_off + j*4 + 4])[0]
            no = rva2off(nr)
            ord_ = struct.unpack('<H', dll[ord_off + j*2 : ord_off + j*2 + 2])[0]
            fr = struct.unpack('<I', dll[fn_off + ord_*4 : fn_off + ord_*4 + 4])[0]
            end = dll.index(b'\x00', no)
            s = dll[no:end].decode('ascii', errors='replace')
            if 'xxtea' in s.lower() or 'key' in s.lower():
                fo = rva2off(fr)
                print(f'    {s} @ RVA=0x{fr:X} (file=0x{fo:X}) ord={ord_}')
    else:
        print(f'Export NOT in [{i}] \"{name}\" [{virt_addr:X}, {virt_addr+virt_size:X})')
