# PE Header Dump Utilities

## Added commands

- **pedumpPEHeader**
- **pedumpDOSHeader**
- **pedumpNTHeaders**
- **pedumpFileHeader**
- **pedumpOptionalHeader**
- **pedumpDataDirectories**
- **pedumpSections**

## Summary

Each command has the following syntax:

<pre>command [Base Address]</pre>

If a base address is not specified, then the command will calculate a base address using the selected address in the disassembly view.  If the selected address is in a module, then the module's base address is used.  If the selected address is not in a module, then the memory region's base address is used.

e.g. if you are viewing kernel32.dll's .text section in the disassembly view, then executing the **pedumpPEHeader** command will dump the entire pe header for kernel32. 

## Features

- Magic numbers, signatures, flags, and misc. constants converted to strings.
- RVA-to-VA translations.
- Page-aligned size values.
- Readable time date stamp

## Building

A post-build event requires two environment variables, **"X64DBG_PATH"** and **"X32DBG_PATH"**, to be defined to their respective install directories.

## Sample output

See sample_output.txt