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
addr_fns_rva = struct.unpack('<I', dll[export_off+28:export_off+32])[0]
addr_nms_rva = struct.unpack('<I', dll[export_off+32:export_off+36])[0]
ordinals_rva = struct.unpack('<I', dll[export_off+36:export_off+40])[0]

addr_fns_off = rva2off(addr_fns_rva)
addr_nms_off = rva2off(addr_nms_rva)
ordinals_off = rva2off(ordinals_rva)

# The ordinals for the XXTEA functions (based on hint bytes in the name table)
# \xec\x26 = 0x26EC = getXXTeaKey
# \xed\x26 = 0x26ED = xxtea_decrypt
# \xee\x26 = 0x26EE = xxtea_encrypt
# \xef\x26 = 0x26EF = xxtea_need_size
# \xeb\x26 = 0x26EB = b64_encode

# But wait - the hint ordinals in the PE export name table are indexes into AddressOfFunctions,
# not the actual ordinal. The actual function ordinal = base + hint_ordinal.
# However, in this strange format where the hint is stored BEFORE the name string,
# we need to figure out what these values mean.

# Let me first check: are the AddressOfNameOrdinals entries 0x26EB-0x26EF?
# Let me look at the actual AddressOfNames entries and find which entries point to the XXTEA names.

# Actually, let's first check if the hint bytes at the string locations match
# the ordinals in AddressOfNameOrdinals for names pointing to those RVAs

names_checked = 0
for j in range(num_nms):
    nr = struct.unpack('<I', dll[addr_nms_off + j*4 : addr_nms_off + j*4 + 4])[0]
    hint = struct.unpack('<H', dll[ordinals_off + j*2 : ordinals_off + j*2 + 2])[0]
    
    # Check if the name RVA points to locations we know
    if nr in [0x231423A, 0x2314248, 0x2314258, 0x2314268, 0x231427A]:
        no = rva2off(nr)
        end = dll.index(b'\x00', no)
        s = dll[no:end].decode('ascii', errors='replace')
        fr = struct.unpack('<I', dll[addr_fns_off + hint*4 : addr_fns_off + hint*4 + 4])[0]
        fo = rva2off(fr)
        print(f'Found! Index {j}: name="{s}" hint={hint} (0x{hint:04X}) fn_RVA=0x{fr:X} fn_off=0x{fo:X}')
        names_checked += 1

if names_checked == 0:
    print('Names NOT found through standard export lookup!')
    print()
    # The hint bytes before the names might be the ordinal_index directly
    # Let's try them as indices into AddressOfFunctions
    hints_to_try = [0x26EB, 0x26EC, 0x26ED, 0x26EE, 0x26EF]
    hint_names = {0x26EB: 'b64_encode', 0x26EC: 'getXXTeaKey', 0x26ED: 'xxtea_decrypt', 0x26EE: 'xxtea_encrypt', 0x26EF: 'xxtea_need_size'}
    
    for hint in hints_to_try:
        if hint < num_fns:
            fr = struct.unpack('<I', dll[addr_fns_off + hint*4 : addr_fns_off + hint*4 + 4])[0]
            fo = rva2off(fr)
            print(f'hint=0x{hint:04X} ({hint_names[hint]}): raw RVA=0x{fr:X} file_off=0x{fo}')
        else:
            print(f'hint=0x{hint:04X} ({hint_names[hint]}): BEYOND function table (num_fns={num_fns})')

# Also check the num_fns to understand bounds
print(f'\nnum_fns={num_fns}, base={base}')
print(f'addr_fns range: [0x{addr_fns_rva:X}, 0x{addr_fns_rva + num_fns*4:X})')
print(f'Last possible hint: {num_fns-1} (0x{num_fns-1:X})')

# Also check ALL entries around where the XXTEA name strings should be
# by searching the names RVAs array for anything near those RVAs
print()
print('Searching AddressOfNames for entries near XXTEA strings:')
for j in range(num_nms):
    nr = struct.unpack('<I', dll[addr_nms_off + j*4 : addr_nms_off + j*4 + 4])[0]
    no = rva2off(nr)
    if no:
        try:
            end = dll.index(b'\x00', no)
            s = dll[no:end].decode('ascii', errors='replace')
            if 'xxtea' in s.lower() or 'key' in s.lower():
                hint = struct.unpack('<H', dll[ordinals_off + j*2 : ordinals_off + j*2 + 2])[0]
                fr = struct.unpack('<I', dll[addr_fns_off + hint*4 : addr_fns_off + hint*4 + 4])[0]
                fo = rva2off(fr)
                print(f'  [{j}] hint={hint} name="{s}" fn_RVA=0x{fr:X} fn_off=0x{fo:X}')
        except:
            pass
