## Import the library (PE) and load notepad.exe binary
```
import pefile
pe = pefile.PE('notepad.exe')
pe
```
- Print the structure of the file
`dir(pe)`

- Print the PE header
`pe.DOS_HEADER`
Sample:
```
<Structure: [IMAGE_DOS_HEADER] 0x0 0x0 e_magic: 0x5A4D 0x2 0x2 e_cblp: 0x90 0x4 0x4 e_cp: 0x3 0x6 0x6 e_crlc: 0x0 0x8 0x8 e_cparhdr: 0x4 0xA 0xA e_minalloc: 0x0 0xC 0xC e_maxalloc: 0xFFFF 0xE 0xE e_ss: 0x0 0x10 0x10 e_sp: 0xB8 0x12 0x12 e_csum: 0x0 0x14 0x14 e_ip: 0x0 0x16 0x16 e_cs: 0x0 0x18 0x18 e_lfarlc: 0x40 0x1A 0x1A e_ovno: 0x0 0x1C 0x1C e_res: 0x24 0x24 e_oemid: 0x0 0x26 0x26 e_oeminfo: 0x0 0x28 0x28 e_res2: 0x3C 0x3C e_lfanew: 0xE8>
```
- Import pprint and print the PE header
`import pprint`
`pprint.pprint(dir(pe.DOS_HEADER))`
Sample:
```
['__all_zeroes__',
 '__class__',
 '__delattr__',
 '__dict__',
 '__doc__',
 '__field_offsets__',
 '__file_offset__',
 '__format__',
 '__format_length__',
 '__get_format__',
 '__getattribute__',
 '__hash__',
 '__init__',
 '__keys__',
 '__long__',
 '__module__',
 '__native__',
 '__new__',
 '__nonzero__',
 '__pack__',
 '__reduce__',
 '__reduce_ex__',
 '__repr__',
 '__set_format__',
 '__setattr__',
 '__sizeof__',
 '__str__',
 '__subclasshook__',
 '__unicode__',
 '__unpack__',
 '__unpacked_data_elms__',
 '__weakref__',
 'all_zeroes',
 'dump',
 'dump_dict',
 'e_cblp',
 'e_cp',
 'e_cparhdr',
 'e_crlc',
 'e_cs',
 'e_csum',
 'e_ip',
 'e_lfanew',
 'e_lfarlc',
 'e_magic',
 'e_maxalloc',
 'e_minalloc',
 'e_oemid',
 'e_oeminfo',
 'e_ovno',
 'e_res',
 'e_res2',
 'e_sp',
 'e_ss',
 'get_field_absolute_offset',
 'get_field_relative_offset',
 'get_file_offset',
 'name',
 'next',
 'set_file_offset',
 'sizeof',
 'sizeof_type']
```

- Print the magic number of the PE file in decimal, hex and ASCII
> Decimal
`print pe.DOS_HEADER.e_magic`
> Hex
`print hex(pe.DOS_HEADER.e_magic)`
> ASCII Char string
```
a = hex(pe.DOS_HEADER.e_magic)
a =  a[2:]
print a.decode("hex")
```
Sample:
```
23117
0x5a4d
ZM
```

- Print number of sections in the PE file
`print pe.FILE_HEADER.NumberOfSections`
- Print sections of the PE file
`print pe.sections`
- sample:
```
[<Structure: [IMAGE_SECTION_HEADER] 0x1F0 0x0 Name: .text 0x1F8 0x8 Misc: 0x18D6E 0x1F8 0x8 Misc_PhysicalAddress: 0x18D6E 0x1F8 0x8 Misc_VirtualSize: 0x18D6E 0x1FC 0xC VirtualAddress: 0x1000 0x200 0x10 SizeOfRawData: 0x18E00 0x204 0x14 PointerToRawData: 0x400 0x208 0x18 PointerToRelocations: 0x0 0x20C 0x1C PointerToLinenumbers: 0x0 0x210 0x20 NumberOfRelocations: 0x0 0x212 0x22 NumberOfLinenumbers: 0x0 0x214 0x24 Characteristics: 0x60000020>, <Structure: [IMAGE_SECTION_HEADER] 0x218 0x0 Name: .rdata 0x220 0x8 Misc: 0x7560 0x220 0x8 Misc_PhysicalAddress: 0x7560 0x220 0x8 Misc_VirtualSize: 0x7560 0x224 0xC VirtualAddress: 0x1A000 0x228 0x10 SizeOfRawData: 0x7600 0x22C 0x14 PointerToRawData: 0x19200 0x230 0x18 PointerToRelocations: 0x0 0x234 0x1C PointerToLinenumbers: 0x0 0x238 0x20 NumberOfRelocations: 0x0 0x23A 0x22 NumberOfLinenumbers: 0x0 0x23C 0x24 Characteristics: 0x40000040>, <Structure: [IMAGE_SECTION_HEADER] 0x240 0x0 Name: .data 0x248 0x8 Misc: 0x2D14 0x248 0x8 Misc_PhysicalAddress: 0x2D14 0x248 0x8 Misc_VirtualSize: 0x2D14 0x24C 0xC VirtualAddress: 0x22000 0x250 0x10 SizeOfRawData: 0xC00 0x254 0x14 PointerToRawData: 0x20800 0x258 0x18 PointerToRelocations: 0x0 0x25C 0x1C PointerToLinenumbers: 0x0 0x260 0x20 NumberOfRelocations: 0x0 0x262 0x22 NumberOfLinenumbers: 0x0 0x264 0x24 Characteristics: 0xC0000040>, <Structure: [IMAGE_SECTION_HEADER] 0x268 0x0 Name: .pdata 0x270 0x8 Misc: 0x8B8 0x270 0x8 Misc_PhysicalAddress: 0x8B8 0x270 0x8 Misc_VirtualSize: 0x8B8 0x274 0xC VirtualAddress: 0x25000 0x278 0x10 SizeOfRawData: 0xA00 0x27C 0x14 PointerToRawData: 0x21400 0x280 0x18 PointerToRelocations: 0x0 0x284 0x1C PointerToLinenumbers: 0x0 0x288 0x20 NumberOfRelocations: 0x0 0x28A 0x22 NumberOfLinenumbers: 0x0 0x28C 0x24 Characteristics: 0x40000040>, <Structure: [IMAGE_SECTION_HEADER] 0x290 0x0 Name: .rsrc 0x298 0x8 Misc: 0x19CE0 0x298 0x8 Misc_PhysicalAddress: 0x19CE0 0x298 0x8 Misc_VirtualSize: 0x19CE0 0x29C 0xC VirtualAddress: 0x26000 0x2A0 0x10 SizeOfRawData: 0x19E00 0x2A4 0x14 PointerToRawData: 0x21E00 0x2A8 0x18 PointerToRelocations: 0x0 0x2AC 0x1C PointerToLinenumbers: 0x0 0x2B0 0x20 NumberOfRelocations: 0x0 0x2B2 0x22 NumberOfLinenumbers: 0x0 0x2B4 0x24 Characteristics: 0x40000040>, <Structure: [IMAGE_SECTION_HEADER] 0x2B8 0x0 Name: .reloc 0x2C0 0x8 Misc: 0x218 0x2C0 0x8 Misc_PhysicalAddress: 0x218 0x2C0 0x8 Misc_VirtualSize: 0x218 0x2C4 0xC VirtualAddress: 0x40000 0x2C8 0x10 SizeOfRawData: 0x400 0x2CC 0x14 PointerToRawData: 0x3BC00 0x2D0 0x18 PointerToRelocations: 0x0 0x2D4 0x1C PointerToLinenumbers: 0x0 0x2D8 0x20 NumberOfRelocations: 0x0 0x2DA 0x22 NumberOfLinenumbers: 0x0 0x2DC 0x24 Characteristics: 0x42000040>]
```
- Print the first section of the PE file
`pprint.pprint(dir(pe.sections[0]))`

Sample:
```
 ['Characteristics',
 'IMAGE_SCN_ALIGN_1024BYTES',
 'IMAGE_SCN_ALIGN_128BYTES',
 'IMAGE_SCN_ALIGN_16BYTES',
 'IMAGE_SCN_ALIGN_1BYTES',
 'IMAGE_SCN_ALIGN_2048BYTES',
 'IMAGE_SCN_ALIGN_256BYTES',
 'IMAGE_SCN_ALIGN_2BYTES',
 'IMAGE_SCN_ALIGN_32BYTES',
 'IMAGE_SCN_ALIGN_4096BYTES',
```
- Print the name and size of raw data for each section
```
for section in pe.sections:
    print section.Name
    print section.SizeOfRawData
    print '\n'
```
- Load notepad_upx.exe file and list the sections