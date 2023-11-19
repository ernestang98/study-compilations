# Budget OSED (WIP)

Compilation of OSED-related write-ups which pretty much covers the OSED syllabus found [here](https://www.offsec.com/courses/exp-301/download/syllabus) as OffSec courses are getting more and more expensive. Hopefully this gives you the necessary knowledge and skills to prepare for your windows security research job interviews/internships or to just become an independent security researcher :)

# 1. WinDbg and x86 Architecture

[WinDBG quick start tutorial by CodeMachine Inc](https://codemachine.com/articles/windbg_quickstart.html)

[Wikipedia's x86 Calling Convention](https://en.wikipedia.org/wiki/X86_calling_conventions)

### Tips:

- Google/ChatGPT on familiarising yourself with using WinDbg

# 2. Exploiting Stack Overflows

[Exploiting Basic Buffer Overflow in VulnServer (TRUN Command) by Bryan Leong](https://bryanleong98.medium.com/exploiting-basic-buffer-overflow-in-vulnserver-trun-command-a8e642cf3211)

### Tldr:

Stack overflows occur when a copy function is executed unsafely on a buffer.

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

# 5. Overcoming Space Restrictions: Egghunters

[Windows Exploitation: Egg hunting by NotSoShant](https://medium.com/@notsoshant/windows-exploitation-egg-hunting-117828020595)

[Safely Searching Process Virtual Address Space by Skypher](https://www.hick.org/code/skape/papers/egghunt-shellcode.pdf)

### Tips:

- Understanding WHAT do egghunters in exploit development context achieve and HOW they work

- Understand HOW to debug egghunter shellcode (e.g. let's say your egghunter fails to find an egg which is clearly in memory, you should be able to analyse and troubleshoot the shellcode)

- Download binaries from ExploitDB and attempt exploiting them, start from a simple crash (binaries without space restrictions could work fine as well)

# 6. Creating Custom Shellcode

[Win32 Reverse Shellcode by h0mbre](https://h0mbre.github.io/Win32_Reverse_Shellcode/)

[Writing W32 shellcode by FuzzySecurity](https://fuzzysecurity.com/tutorials/expDev/6.html)

### Tips:

- Try writing shellcoding that works with other Windows APIs from different [DLLs](https://www.win7dll.info/), the sky's the limit (e.g. ADVAPI32.dll)

# 7. Reverse Engineering for Bugs (NOT fuzzing btw)

Can't really find a good one which shows the entire process of vulnerability discovery and exploitation via static and dynamic analysis using windbg and IDA. Maybe I will make one myself? ;)

# 8. Stack Overflows and DEP Bypass

[Bypassing DEP via ROP by vulndev.io (copy-esp method)](https://www.vulndev.io/2022/06/12/bypassing-dep-with-writeprocessmemory/)

[Bypassing DEP via ROP by FuzzySecurity (pushad method)](https://fuzzysecurity.com/tutorials/expDev/7.html)

### Tips:

- Understanding HOW DEP helps to mitigate binary exploitation

- Understanding WHAT is ROP and HOW to bypass DEP with ROP

- Understanding HOW to bypass DEP via ROP from a stack overflow condition

- Understanding HOW to bypass DEP via ROP from a SEH overflow condition

- Understanding HOW to ensure that your exploit is not OS-dependent (for instance via IATs if ASLR is not applied on the executable itself)

- There are other ways of bypassing DEP such as [COP](https://connormcgarr.github.io/ROP2/), or [JOP](https://www.exploit-db.com/exploits/49959)

- Apart from WriteProcessMemory, you can also use VirtualAlloc, VirtualProtect, HeapAlloc + HeapCreate/GetProcessHeap, SetProcessDEPPolicy, or NtSetInformationProcess, though I have not seen a DEP bypass via NtSetInformationProcess before :). I personally wrote a ROP chain exploit via HeapAlloc + HeapCreate/GetProcessHeap and will be releasing it soon via exploitdb. As for the rest of the methods, you can simply google/surf exploitdb to see proof-of-concepts of how ROP chains are used to call these functions to bypass DEP. 

# 9. Stack Overflows and ASLR Bypass

[Fun with Info Leaks by rh0dev](https://rh0dev.github.io/blog/2015/fun-with-info-leaks/)

### Tips:

- Understanding HOW ASLR helps to mitigate binary exploitation

- Understanding HOW to bypass ASLR 

# 10. Format String Specifier Attack Part I

Can't really find a good one which shows the ability of format string vulnerabilities to lead to an arbitrary read exploit. Maybe I will make one myself? ;)

# 11. Format String Specifier Attack Part II

Can't really find a good one which shows the ability of format string vulnerabilities to lead to an arbitrary write exploit. Maybe I will make one myself? ;)

