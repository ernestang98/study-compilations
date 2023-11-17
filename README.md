# Budget OSED Study Materials (WIP)

Compilation of OSED-related write-ups

# 1. WinDbg and x86 Architecture

[WinDBG quick start tutorial by CodeMachine Inc](https://codemachine.com/articles/windbg_quickstart.html)

[Wikipedia's x86 Calling Convention](https://en.wikipedia.org/wiki/X86_calling_conventions)

### Tips:

- Google/ChatGPT on familiarising yourself with using WinDbg

# 2. Exploiting Stack Overflows

[Exploiting Basic Buffer Overflow in VulnServer (TRUN Command) by Bryan Leong](https://bryanleong98.medium.com/exploiting-basic-buffer-overflow-in-vulnserver-trun-command-a8e642cf3211)

### Tips:

- Understand HOW stack buffer overflow occurs

- Understand HOW to exploit a stack buffer overflow condition

- Understand HOW to mitigate the exploitation of stack buffer overflows (e.g. stack cookies, DEP)

- Understand HOW to bypass mitigations of exploitation of stack buffer overflows (e.g. trigger SEH before stack cookie check, ROP)

- Download binaries from ExploitDB and attempt exploiting them, start from a simple crash

# 3. Exploiting SEH Overflows

[Vulnserver Exploiting GMON with SEH Overwrite by Anubis](https://anubissec.github.io/Vulnserver-Exploiting-GMON-SEH-Overwrite/)

[ired.team's explanation of SEH](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/seh-based-buffer-overflow)

### Tips:

- Understand SEH data structures

- Understand HOW SEH buffer overflow occurs

- Understand HOW to exploit a SEH overflow condition

- Understand HOW to mitigate the exploitation of SEH overflows (e.g. SafeSEH)

- Understand HOW to bypass mitigations of SEH overflows (e.g. usage of SafeSEH-disabled modules)

- Download binaries from ExploitDB and attempt exploiting them, start from a simple crash

# 4. Introduction to IDA Pro

[Reverse Engineering with IDA Pro Freeware by Sams Class](https://samsclass.info/126/proj/p2-126-IDA.html)

### Tips:

- Google/ChatGPT on familiarising yourself with using IDA Pro Free

- Practice IDA by reversing [crackmes](https://crackmes.one/)

# 10. Stack Overflows and ASLR Bypass

[Fun with Info Leaks by rh0dev](https://rh0dev.github.io/blog/2015/fun-with-info-leaks/)
