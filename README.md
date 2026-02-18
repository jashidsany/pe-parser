# pe-parser
PE file parser written in C. Analyzes Windows executables by parsing DOS/NT headers and sections. Displays entry point, image base, section layout, and architecture info. Built with Windows API (CreateFileW, HeapAlloc, ReadFile). Great for learning Windows internals, reverse engineering, and malware analysis fundamentals.

# PE Parser

A Windows PE (Portable Executable) file parser written in C. This tool analyzes the structure of Windows executables (.exe) and DLLs (.dll) by parsing their headers and displaying detailed information.

## What is a PE File?

PE (Portable Executable) is the file format used by Windows for executables, DLLs, and other binary files. Understanding PE structure is fundamental for:

- Malware analysis
- Reverse engineering
- Windows internals
- Security research

## Features

- Parse DOS Header (MZ signature, offset to NT headers)
- Parse NT Headers (PE signature, File Header, Optional Header)
- Parse Section Headers (.text, .data, .rdata, etc.)
- Support for both 32-bit (PE32) and 64-bit (PE32+) executables
- Clean formatted output

## PE Structure Overview
```
┌─────────────────────────────────────┐
│ DOS Header                          │ ← Starts with "MZ"
├─────────────────────────────────────┤
│ DOS Stub                            │
├─────────────────────────────────────┤
│ NT Headers                          │ ← Starts with "PE"
│   ├── Signature                     │
│   ├── File Header                   │
│   └── Optional Header               │
├─────────────────────────────────────┤
│ Section Headers                     │
├─────────────────────────────────────┤
│ Sections (.text, .data, etc.)       │
└─────────────────────────────────────┘
```

## Usage
```
PEParser.exe <path to PE file>
```

### Example
```
PEParser.exe C:\Windows\System32\notepad.exe
```

### Example Output
```
[+] Parsing: C:\Windows\System32\notepad.exe

[+] File size: 201216 bytes

[+] DOS Header:
    e_magic:    0x5A4D (MZ)
    e_lfanew:   0xF0 (Offset to NT Headers)

[+] NT Headers:
    Signature:  0x4550 (PE)
[+] File Header:
    Machine:              0x8664
    NumberOfSections:     7
    TimeDateStamp:        0x5E2C4A4B
    SizeOfOptionalHeader: 0xF0
    Characteristics:      0x22
[+] Optional Header:
    Magic:                0x20B (64-bit)
    AddressOfEntryPoint:  0x1A4B0
    ImageBase:            0x140000000
    SectionAlignment:     0x1000
    FileAlignment:        0x200
    SizeOfImage:          0x39000
    SizeOfHeaders:        0x400
    NumberOfRvaAndSizes:  16

[+] Sections (7):
    Name     VirtAddr   VirtSize   RawAddr    RawSize   
    ----     --------   --------   -------    -------   
    .text    0x1000     0x1A3E4    0x400      0x1A400   
    .rdata   0x1C000    0xCE2C     0x1A800    0xD000    
    .data    0x29000    0x1690     0x27800    0x600     
    .pdata   0x2B000    0x1B54     0x27E00    0x1C00    
    .didat   0x2D000    0x130      0x29A00    0x200     
    .rsrc    0x2E000    0x9CE8     0x29C00    0x9E00    
    .reloc   0x38000    0x298      0x33A00    0x400     
```

## Field Explanations

### DOS Header

| Field | Description |
|-------|-------------|
| `e_magic` | DOS signature, must be "MZ" (0x5A4D) |
| `e_lfanew` | File offset to NT headers |

### File Header

| Field | Description |
|-------|-------------|
| `Machine` | Target CPU (0x8664 = x64, 0x14C = x86) |
| `NumberOfSections` | Count of sections in the PE |
| `TimeDateStamp` | Compilation timestamp (Unix format) |
| `SizeOfOptionalHeader` | Size of Optional Header in bytes |
| `Characteristics` | Flags (executable, DLL, etc.) |

### Optional Header

| Field | Description |
|-------|-------------|
| `Magic` | PE32 (0x10B) or PE32+ (0x20B) |
| `AddressOfEntryPoint` | RVA where execution begins |
| `ImageBase` | Preferred load address |
| `SectionAlignment` | Alignment in memory (usually 0x1000) |
| `FileAlignment` | Alignment on disk (usually 0x200) |
| `SizeOfImage` | Total size when loaded in memory |
| `SizeOfHeaders` | Size of all headers combined |

### Section Headers

| Field | Description |
|-------|-------------|
| `Name` | Section name (e.g., .text, .data) |
| `VirtualAddress` | RVA when loaded in memory |
| `VirtualSize` | Size in memory |
| `PointerToRawData` | File offset of section data |
| `SizeOfRawData` | Size on disk |

### Common Sections

| Section | Purpose |
|---------|---------|
| `.text` | Executable code |
| `.data` | Initialized global data |
| `.rdata` | Read-only data (strings, constants) |
| `.bss` | Uninitialized data |
| `.rsrc` | Resources (icons, dialogs) |
| `.reloc` | Relocation information |
| `.pdata` | Exception handling (x64) |

## Build

### Requirements

- Windows 10/11
- Visual Studio 2019 or later

### Steps

1. Open `PEParser.sln` in Visual Studio
2. Select `Release` and `x64`
3. Build → Build Solution
4. Output: `x64\Release\PEParser.exe`

### Manual Compilation
```
cl.exe /W4 /O2 PEParser.c /Fe:PEParser.exe
```

## Project Structure
```
PEParser/
├── PEParser.c       # Main source code
├── PEParser.sln     # Visual Studio solution
├── PEParser.vcxproj # Visual Studio project
└── README.md        # This file
```

## What I Learned

- PE file structure and layout
- DOS and NT header parsing
- Pointer arithmetic and memory offsets
- Windows API functions (CreateFileW, ReadFile, HeapAlloc)
- Error handling patterns in C
- File I/O operations

## Future Improvements

- [ ] Parse Import Table (show imported DLLs and functions)
- [ ] Parse Export Table (show exported functions)
- [ ] Parse Data Directories
- [ ] Decode Characteristics flags to readable text
- [ ] Add hex dump of headers
- [ ] Support for packed/obfuscated PEs

## References

- [Microsoft PE Format Documentation](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [PE Format - Wikipedia](https://en.wikipedia.org/wiki/Portable_Executable)
- Windows Internals Book by Mark Russinovich

## Disclaimer

This tool is for educational purposes only. Use responsibly and only on files you have permission to analyze.

## License

MIT License
```

---

## Files to Include in Your GitHub Repo
```
PEParser/
├── PEParser.c           # Your source code
├── PEParser.sln         # Visual Studio solution (optional)
├── PEParser.vcxproj     # Visual Studio project (optional)
├── README.md            # The readme above
├── screenshot.png       # Screenshot of output (recommended)
└── LICENSE              # MIT License file (optional)
