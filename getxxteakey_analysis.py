import struct

dll_path = r'C:\Users\Le Minh\AppData\Roaming\miniworldOverseasgame\libMiniBaseEngine.dll'
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

# Analyze getXXTeaKey function
fn_off = 0x218B70
fn_rva = 0x219770

print("=== getXXTeaKey function ===")
# Read up to 512 bytes
fn_size = 512
fn_code = dll[fn_off:fn_off+fn_size]

# Print hex dump
for i in range(0, len(fn_code), 16):
    addr = fn_rva + i
    hex_str = ' '.join(f'{b:02x}' for b in fn_code[i:i+16])
    # Try to show ASCII
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in fn_code[i:i+16])
    print(f"  0x{addr:08X}: {hex_str:48s} {ascii_str}")

# Analyze code flow
print()
print("=== Code Analysis ===")
# Track indirect and direct calls
for i in range(0, len(fn_code)-5, 1):
    # direct call E8 xx xx xx xx
    if fn_code[i] == 0xE8:
        rel = struct.unpack('<i', fn_code[i+1:i+5])[0]
        target = fn_rva + i + 5 + rel
        print(f"  @0x{fn_rva+i:08X}: CALL 0x{target:08X}")
    
    # indirect call FF 15 xx xx xx xx  
    if i+5 < len(fn_code) and fn_code[i:i+2] == b'\xff\x15':
        iat_abs = struct.unpack('<I', fn_code[i+2:i+6])[0]
        iat_rva = iat_abs - image_base
        iat_off = rva2off(iat_rva)
        if iat_off:
            func_abs = struct.unpack('<I', dll[iat_off:iat_off+4])[0]
            func_rva = func_abs - image_base
            print(f"  @0x{fn_rva+i:08X}: CALL [0x{iat_abs:08X}] -> 0x{func_rva:08X}")
    
    # mov reg, const (B0-BF for 8-bit, B8-BF for 32-bit)
    if (fn_code[i] & 0xF8) == 0xB8 and i+4 < len(fn_code):
        val = struct.unpack('<I', fn_code[i+1:i+5])[0]
        reg_idx = fn_code[i] & 0x07
        regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
        if 0x20 <= val <= 0x7E:
            print(f"  @0x{fn_rva+i:08X}: mov {regs[reg_idx]}, 0x{val:08X} ; '{chr(val)}'")
        elif val > 0x1000:
            # Could be an address reference
            off = rva2off(val)
            if off:
                # Read string at this location
                try:
                    end = dll.index(b'\x00', off)
                    s = dll[off:end].decode('ascii', errors='replace')
                    if len(s) > 3 and all(32 <= ord(c) <= 126 if c.isascii() else False for c in s):
                        print(f"  @0x{fn_rva+i:08X}: mov {regs[reg_idx]}, 0x{val:08X} ; -> \"{s}\"")
                except:
                    pass
    
    # push imm8
    if fn_code[i] == 0x6A:
        val = fn_code[i+1]
        if 0x20 <= val <= 0x7E:
            print(f"  @0x{fn_rva+i:08X}: push 0x{val:02X} ; '{chr(val)}'")
    
    # push imm32
    if fn_code[i] == 0x68 and i+4 < len(fn_code):
        val = struct.unpack('<I', fn_code[i+1:i+5])[0]
        off = rva2off(val)
        if off:
            try:
                end = dll.index(b'\x00', off)
                s = dll[off:end].decode('ascii', errors='replace')
                if len(s) > 3 and all(32 <= ord(c) <= 126 if c.isascii() else False for c in s):
                    print(f"  @0x{fn_rva+i:08X}: push 0x{val:08X} ; -> \"{s}\"")
            except:
                pass
        elif val > 0x20 and val < 0x1000:
            # Could be a size or constant
            print(f"  @0x{fn_rva+i:08X}: push 0x{val:X}")
    
    # lea reg, [reg+offset]  
    if fn_code[i] == 0x8D:
        modrm = fn_code[i+1]
        if (modrm & 0xC7) == 0x05 and i+5 < len(fn_code):  # lea reg, [addr]
            reg = (modrm >> 3) & 7
            addr_val = struct.unpack('<I', fn_code[i+2:i+6])[0]
            off = rva2off(addr_val)
            if off:
                try:
                    end = dll.index(b'\x00', off)
                    s = dll[off:end].decode('ascii', errors='replace')
                    regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                    if len(s) > 3 and all(32 <= ord(c) <= 126 if c.isascii() else False for c in s):
                        print(f"  @0x{fn_rva+i:08X}: lea {regs[reg]}, [0x{addr_val:08X}] ; -> \"{s}\"")
                except:
                    pass

# Also analyze the xxtea_decrypt function
print()
print("=== xxtea_decrypt function ===")
fn2_off = 0x218B80
fn2_rva = 0x219780
fn2_code = dll[fn2_off:fn2_off+512]

for i in range(0, len(fn2_code), 16):
    addr = fn2_rva + i
    hex_str = ' '.join(f'{b:02x}' for b in fn2_code[i:i+16])
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in fn2_code[i:i+16])
    print(f"  0x{addr:08X}: {hex_str:48s} {ascii_str}")

# Search for the actual XXTEA key in the DLL
print()
print("=== Searching for key constants in getXXTeaKey proximity ===")
# Read the whole function area around getXXTeaKey
fn_start = 0x218B70
fn_end = 0x218DA0  # end of xxtea_need_size
area = dll[fn_start:fn_end-fn_start]

# Look for any printable strings (potential keys)
print("Printable strings in function area:")
current = b''
for i, b in enumerate(area):
    if 32 <= b <= 126:
        current += bytes([b])
    else:
        if len(current) >= 4 and len(current) <= 32:
            s = current.decode('ascii')
            addr = fn_rva + i - len(current)
            print(f"  0x{addr:08X}: \"{s}\"")
        current = b''
if len(current) >= 4:
    print(f"  0x{fn_rva + len(area) - len(current):08X}: \"{current.decode('ascii')}\"")
