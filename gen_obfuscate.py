import random
random.seed(12345)
key = bytes.fromhex('b48e6ef44ed13eee606141750e729cf4')
hex_str = key.hex()  # 32 hex chars
hex_bytes = hex_str.encode('ascii')  # 32 ASCII bytes
mask = bytes([random.randint(0,255) for _ in range(32)])
masked = bytes(a ^ b for a, b in zip(hex_bytes, mask))

restored = bytes(a ^ b for a, b in zip(masked, mask)).decode('ascii')
print(f'Source hex: {hex_str}')
print(f'Match: {restored == hex_str}')

js_mask = ', '.join(f'0x{b:02x}' for b in mask)
js_masked = ', '.join(f'0x{b:02x}' for b in masked)
print(f'\nJS mask: [{js_mask}]')
print(f'JS masked: [{js_masked}]')

# C# format
cs_mask = ', '.join(f'0x{b:x2}' for b in mask)
cs_masked = ', '.join(f'0x{b:x2}' for b in masked)
print(f'\nC# mask: [{cs_mask}]')
print(f'C# masked: [{cs_masked}]')
