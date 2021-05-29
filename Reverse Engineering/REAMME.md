
## Some great disassemblers

- Ghidr
  - Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. Windows, Mac OS, and Linux.
- radare2
  - Radare2 is an open source tool to disassemble, debug, analyze and manipulate binary files. It actually supports many architectures (x86{16,32,64}, Dalvik, avr, ARM, java, PowerPC, Sparc, MIPS) and several binary formats (pe{32,64}, [fat]mach0{32,64}, ELF{32,64}, dex and Java classes)
- Binary Ninja
  - Binary Ninja is a reverse engineering platform. It focuses on a clean and easy to use interface with a powerful multithreaded analysis built on a custom IL to quickly adapt to a variety of architectures, platforms, and compilers. Runs on macOS, Windows, and Linux.
- Hopper
  - Hopper is a reverse engineering tool for macOS and Linux, that lets you disassemble, decompile and debug (OS X only) your 32/64bits Intel Mac, Windows and iOS (ARM) executables.
- x64dbg
  - An open-source x64/x32 debugger for windows.
- ImmunityDbg
  - Immunity Debugger is a branch of OllyDbg v1.10, with built-in support for Python scripting and much more.
- OllyDbg
  - OllyDbg is an assembler level analysing debugger for Microsoft® Windows®. Emphasis on binary code analysis makes it particularly useful in cases where source is unavailable.

# Change OllyDbg layout fonts to become readable:
Add the following lines to the *.ini file of OllyDbg v2.x to make it more readable or suitable for working with it:

`[Colour schemes]
Scheme name[4]=KuNgBiM's Scheme
Foreground_1[4]=*,*,808000,0,FFFF,80,*,FF00,*,FF0000,*,*,*,*,*,*
Foreground_2[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*
Background_1[4]=C0DCC0,C0DCC0,C0DCC0,FF00,*,FFFF00,*,*,C0DCC0,FFFF,*,*,*,*,*,*
Background_2[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,*,*,*
Operands[4]=0
Modified commands[4]=0

[Highlighting schemes]
Scheme name[4]=KuNgBiM's Code
Foreground_1[4]=*,*,*,*,*,*,*,*,*,*,*,*,FF0000,FF,FF,FF0000
Foreground_2[4]=0,0,0,FF00,FF,FF,*,*,800000,0,0,800080,FF00FF,80,FF00FF,*
Background_1[4]=*,*,*,*,*,*,*,*,*,*,*,*,*,FFFF,FFFF,*
Background_2[4]=FFFF00,FF00,*,FF,*,*,*,*,*,*,*,*,*,*,*,*
Operands[4]=1
Modified commands[4]=0

[Fonts]
Font name[5]=KuNgBiM's Fonts
Font data[5]=-12,0,400,0,0,0,134,1,49,0,0,0
Face name[5]=#65B0#5B8B#4F53`

Alternately you can go to the git repo of () to find the some of the theme's for debuggers.
