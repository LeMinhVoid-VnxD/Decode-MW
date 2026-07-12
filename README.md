# MiniWorld Lua Decoder 🛠️

Decode XXTEA-encrypted Lua files from **Mini World** (block game).

## Key 🔑

Extracted from `File .dll` → `getXXTeaKey` function:

```
b4*e6e****d13eee****41**0e72***4
```

## Encrypted Format

Two variants:
| Format | Prefix | Example |
|--------|--------|---------|
| 1 | `a0817i` + base64(ciphertext) | Official custom AI Lua files |
| 2 | raw base64 (no prefix) | In-game script files |

XXTEA ciphertext layout: **first 4 bytes = big-endian plaintext length**

## Tools

### 🖥️ MiniWorldDecoder (CLI)
.NET 8 console app. Drag-drop `.lua`/`.wsc` files or a folder onto the EXE, or use via command line.

**Usage:**
```
MiniWorldDecoder.exe <file-or-folder>
MiniWorldDecoder.exe -d <folder>   # decode entire folder
```

**Build:**
```bash
cd MiniWorldDecoder/MiniWorldDecoder
dotnet publish -c Release -r win-x64 --self-contained true
```

### 🌐 MiniWorldDecoder.html (Web UI)
Browser-based decoder — no install needed. Drag-drop files/folders, preview decrypted Lua, download as ZIP.

### 🪟 MiniWorldDecoderUI (WinForms)
Windows GUI application for batch decoding with folder tree view.

## Obfuscation

The XXTEA key is **never stored as plaintext** in the distributed source code. Instead, the hex-ASCII representation of the key is XOR-obfuscated with a 32-byte random mask. The code reconstructs the key at runtime by XOR-ing the masked bytes with the mask.

This is done to avoid automated scraping of the key from the repository while keeping the tools fully open-source.

## Project Structure

```
MiniWorldDecoder/
├── MiniWorldDecoder/          # CLI console app
│   ├── Program.cs             # Entry point with obfuscated key
│   ├── Modules/
│   │   ├── XXTEA.cs           # XXTEA implementation
│   │   ├── LuaProcessor.cs    # Lua detection & decoding
│   │   ├── PkgUnpacker.cs     # .pkg file extraction
│   │   └── ...
│   └── wwwroot/index.html     # HTML tool source
├── MiniWorldDecoderUI/        # WinForms GUI app
├── dist/                      # Pre-built binaries
│   ├── MiniWorldDecoder.exe   # Standalone CLI (self-contained)
│   └── MiniWorldDecoder.html  # Browser tool
└── *.py                       # Research/sidecar scripts
```

## Disclaimer

This project is for **educational and research purposes only**. Mini World is a trademark of its respective owner. Use at your own risk.
