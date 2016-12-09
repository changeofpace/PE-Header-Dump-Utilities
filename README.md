# PE Header Dump Utilities

## added commands

- **pedumpHeader** *[base address]*
- **pedumpNTHeaders** *[base address]*
- **pedumpDataDirectories** *[base address]*
- **pedumpSections** *[base address]*

## syntax

base address is an optional arg.  if no base address is specified, the command will use the base address of the valid module containing the selected address.  if the selected address is not in a valid module, the command will use the base address of the active memory region.

## command summary

- **pedumpHeader:** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;print File Header, Optional Header, Data Directories, and Section Headers to log tab.
- **pedumpNTHeaders:** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;print File Header, Optional Header to log tab.
- **pedumpDataDirectories:** &nbsp;&nbsp;print Data Directories to log tab.
- **pedumpSections:** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;print Section Headers to log tab.

## features

- characteristics members (flags) converted to strings 
- RVA to VA translations
- readable time stamp date

## example output
<pre>
[PE Header Dump Utilities]  dumping NT headers at 00000000772D0000.
===============================================================================
FILE HEADER
===============================================================================
  Machine:                                8664  AMD64
  NumberOfSections:                          7
  TimeDateStamp:                      57F7C06E  Fri Oct 07 11:34:06 2016
  PointerToSymbolTable:       0000000000000000
  NumberOfSymbols:                           0
  SizeOfOptionalHeader:                     F0
  Characteristics:                        2022  EXECUTABLE_IMAGE  LARGE_ADDRESS_AWARE  DLL
===============================================================================
OPTIONAL HEADER
===============================================================================
  Magic:                                   20B  HDR64
  MajorLinkerVersion:                        9
  MinorLinkerVersion:                        0
  SizeOfCode:                            FB800
  SizeOfInitializedData:                 A9600
  SizeOfUninitializedData:                   0
  AddressOfEntryPoint:                       0
  BaseOfCode:                             1000
  ImageBase:                  00000000772D0000
  SectionAlignment:                       1000
  FileAlignment:                           200
  MajorOperatingSystemVersion:               6
  MinorOperatingSystemVersion:               1
  MajorImageVersion:                         6
  MinorImageVersion:                         1
  MajorSubsystemVersion:                     6
  MinorSubsystemVersion:                     1
  Win32VersionValue:                         0
  SizeOfImage:                          1AA000
  SizeOfHeaders:                           400
  CheckSum:                             1B0CE1
  Subsystem:                                 3  WINDOWS_CUI
  DllCharacteristics:                      140  DYNAMIC_BASE  NX_COMPAT
  SizeOfStackReserve:                    40000
  SizeOfStackCommit:                      1000
  SizeOfHeapReserve:                    100000
  SizeOfHeapCommit:                       1000
  LoaderFlags:                               0
  NumberOfRvaAndSizes:                      10
</pre>

## misc
- currently supports x64 only.
