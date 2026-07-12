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

image_base = 0x10000000

# Read import directory
opt_hdr = dll[pe_offset+24:pe_offset+24+opt_hdr_size]
import_rva = struct.unpack('<I', opt_hdr[104:108])[0]
import_size = struct.unpack('<I', opt_hdr[108:112])[0]

print(f"Import directory: RVA=0x{import_rva:X}, Size=0x{import_size:X}")

import_off = rva2off(import_rva)
if import_off:
    # Parse import directory entries
    imp_idx = 0
    while True:
        iat = dll[import_off + imp_idx*20 : import_off + imp_idx*20 + 20]
        ilt_rva = struct.unpack('<I', iat[0:4])[0]  # Import Lookup Table RVA
        ts_rva = struct.unpack('<I', iat[4:8])[0]    # Timestamp
        fwd_chain = struct.unpack('<I', iat[8:12])[0]
        name_rva = struct.unpack('<I', iat[12:16])[0]  # DLL name RVA
        iat_rva = struct.unpack('<I', iat[16:20])[0]  # IAT RVA
        
        if ilt_rva == 0 and name_rva == 0:
            break  # End of import directory
            
        if name_rva:
            name_off = rva2off(name_rva)
            if name_off:
                end = dll.index(b'\x00', name_off)
                dll_name = dll[name_off:end].decode('ascii', errors='replace')
                
                # Parse the ILT
                ilt_off = rva2off(ilt_rva)
                if ilt_off:
                    thunk_idx = 0
                    while True:
                        thunk = struct.unpack('<Q' if False else '<I', dll[ilt_off + thunk_idx*4 : ilt_off + thunk_idx*4 + 4])
                        if isinstance(thunk, tuple):
                            thunk = thunk[0]
                        if thunk == 0:
                            break
                        
                        # Check if it's an ordinal (high bit set) or name import
                        if thunk & 0x80000000:
                            ordinal = thunk & 0xFFFF
                        else:
                            # Name import
                            hint_name_off = rva2off(thunk)
                            if hint_name_off:
                                end = dll.index(b'\x00', hint_name_off+2)
                                func_name = dll[hint_name_off+2:end].decode('ascii', errors='replace')
                                # Check if related to xxtea or key
                                if any(k in func_name.lower() for k in ['xxtea', 'tea', 'encrypt', 'decrypt', 'key', 'b64', 'base64']):
                                    print(f"  IMPORT: {dll_name}!{func_name}")
                                    
                        thunk_idx += 1
        imp_idx += 1

# Now let's look at the import address table entries used by decrypt_xxtea_b64
print()
print("=== IAT entries used by decrypt_xxtea_b64 ===")
# The IAT entries are at these RVAs:
iat_entries = [0x11CFAE10, 0x11CFB288, 0x11CFB284, 0x11CF8368, 0x11CF83F8, 0x11CF83FC]

# The IAT table is in .rdata section
rdata_va = None
for name, va, vs, ro, rs in sections:
    if name == '.rdata':
        rdata_va = va
        rdata_off = ro
        break

for iat_rva in iat_entries:
    iat_off = rva2off(iat_rva)
    if iat_off:
        func_rva = struct.unpack('<I', dll[iat_off:iat_off+4])[0]
        # Get the name from hint/name table
        # Search all import tables for this address
        print(f"  IAT[0x{iat_rva:08X}] -> 0x{func_rva:08X}")

# Let's search for xxtea-related code in the DLL directly
# Find the actual xxtea implementation (the delta constant appears 7 times)
print()
print("=== XXTEA delta constant locations (showing function context) ===")
delta = struct.pack('<I', 0x9E3779B9)
text_off = None
for name, va, vs, ro, rs in sections:
    if name == '.text':
        text_off = ro
        text_va = va
        break

delta_pos = 0
while True:
    delta_pos = dll.find(delta, delta_pos)
    if delta_pos == -1:
        break
    # Check if in .text section
    if text_off <= delta_pos < text_off + 0x1CF6600:
        rva = delta_pos - text_off + text_va
        # Read 64 bytes before and after
        start = max(text_off, delta_pos - 64)
        end = min(len(dll), delta_pos + 64)
        context = dll[start:end]
        print(f"\n  Delta at RVA=0x{rva:08X} (file=0x{dll.find(delta, delta_pos):X}):")
        for i in range(0, len(context), 16):
            addr = rva - (delta_pos - start) + i
            hex_str = ' '.join(f'{b:02x}' for b in context[i:i+16])
            print(f"    0x{addr:08X}: {hex_str}")
    delta_pos += 4
    if delta_pos > text_off + 0x1CF6600:
        break
