
#include "Wow64Hook.h"
#include "LinkedList.h"

HANDLE CurrentProcessHandle;
HANDLE ProcessHeapHandle;
LIST_ENTRY WoW64ListHead;
PVOID JmpSwitchBaseAddress;

PWOW64_SYSCALL_INFO AllocWow64Entry(
    _In_ PSTR FunctionName, 
    _In_ ULONG Index
    )
{
    PWOW64_SYSCALL_INFO Entry;
    SIZE_T FunctionNameLen;
    PSTR FunctionNameAlloc;

    FunctionNameLen = strlen(FunctionName);
    if (!(FunctionNameLen > 0))
    {
        return NULL;
    }

    Entry = (PWOW64_SYSCALL_INFO)HeapAlloc(ProcessHeapHandle, HEAP_ZERO_MEMORY, sizeof(WOW64_SYSCALL_INFO));
    FunctionNameAlloc = (PSTR)HeapAlloc(ProcessHeapHandle, HEAP_ZERO_MEMORY, FunctionNameLen + sizeof(CHAR));
    if (!(Entry && FunctionNameAlloc))
    {
        if (Entry)
        {
            HeapFree(ProcessHeapHandle, 0, Entry);
        }
        if (FunctionNameAlloc)
        {
            HeapFree(ProcessHeapHandle, 0, FunctionNameAlloc);
        }

        return NULL;
    }
        
    RtlCopyMemory(FunctionNameAlloc, FunctionName, FunctionNameLen);
    Entry->FunctionName = FunctionNameAlloc;
    Entry->Index = Index;

    return Entry;
}

BOOL AddWoW64FunctionEntry(
    _In_ PSTR FunctionName, 
    _In_ PVOID FunctionAddress
    )
{
    PBYTE BytesAddress;
    ULONG Index;
    PWOW64_SYSCALL_INFO NewWow64Entry;

    /*
    
    ZwCreateFile    B8 52000000     MOV EAX, <Index>
                    33C9            XOR ECX,ECX
                    8D5424 04       LEA EDX,DWORD PTR SS:[ESP+0x4]
                    64:FF15 C000000>CALL NEAR DWORD PTR FS:[0xC0]
                    83C4 04         ADD ESP,0x4
                    C2 2C00         RETN 0x2C

    Fast check, this can be improved by using a disassembler

    */
    BytesAddress = (PBYTE)FunctionAddress;
    
    if (BytesAddress[0] == 0xB8 &&      // MOV
        BytesAddress[7] == 0x8D &&      // LEA
        BytesAddress[0xB] == 0x64 &&    // CALL
        BytesAddress[0xC] == 0xFF &&    
        BytesAddress[0xD] == 0x15 &&    
        BytesAddress[0x12] == 0x83 &&   // ADD
        (BytesAddress[0x15] == 0xC2 || BytesAddress[0x15] == 0xC3)  // RET
        )
    {
        Index = *((PULONG)&BytesAddress[1]);
        NewWow64Entry = AllocWow64Entry(FunctionName, Index);
        if (NewWow64Entry)
        {
            INSERT_TAIL_LIST(&WoW64ListHead, &NewWow64Entry->ListEntry);
            return TRUE;
        }
    }

    return FALSE;
}

BOOL EnumWow64SystemFunctions()
{
    HMODULE NtdllBaseAddress;
    PIMAGE_DOS_HEADER DOSHeader;
    PIMAGE_NT_HEADERS NTHeaders;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PULONG NameTable;
    PUSHORT OrdinalTable;
    PULONG AddressTable;
    USHORT Ordinal;
    PSTR SymbolName;
    PVOID SymbolAddress;

    NtdllBaseAddress  = GetModuleHandle(_T("ntdll"));
    DOSHeader = (PIMAGE_DOS_HEADER)NtdllBaseAddress;
    NTHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)NtdllBaseAddress + DOSHeader->e_lfanew);

    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)NtdllBaseAddress + NTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    NameTable = (PULONG)((ULONG_PTR)NtdllBaseAddress + ExportDirectory->AddressOfNames);
    OrdinalTable = (PUSHORT)((ULONG_PTR)NtdllBaseAddress + ExportDirectory->AddressOfNameOrdinals);
    AddressTable = (PULONG)((ULONG_PTR)NtdllBaseAddress + ExportDirectory->AddressOfFunctions);

    for (DWORD n = 0; n < ExportDirectory->NumberOfNames; n++)
    {
        Ordinal = OrdinalTable[n];
        if (Ordinal &&
            (!(Ordinal >= ExportDirectory->NumberOfFunctions)))
        {
            SymbolName = (PSTR)((ULONG_PTR)NtdllBaseAddress + NameTable[n]);
            SymbolAddress = (PVOID)((ULONG_PTR)NtdllBaseAddress + AddressTable[Ordinal]);
            AddWoW64FunctionEntry(SymbolName, SymbolAddress);
        }
    }

    return TRUE;
}

PWSTR FormatCallString(
    _In_ _Printf_format_string_ PWSTR Format,
    ...
    )
{
    va_list argptr;
    va_start(argptr, Format);
    return FormatCallStringEx(Format, argptr);
}

PWSTR FormatCallStringEx(
    _In_ _Printf_format_string_ PWSTR Format,
    _In_ va_list ArgPtr
    )
{
    PWSTR String;
    ULONG Length;
    SIZE_T BufferSize;

    Length = _vscwprintf(Format, ArgPtr);
    if (Length == -1)
    {
        return NULL;
    }

    BufferSize = (Length * sizeof(WCHAR)) + sizeof(WCHAR);
    String = (PWSTR)HeapAlloc(ProcessHeapHandle, HEAP_ZERO_MEMORY, BufferSize);

    if (String)
    {
        _vsnwprintf(String, Length, Format, ArgPtr);
    }

    return String;
}

PWSTR fMultiCharToUnicode(_In_ PSTR Ansi)
{
    PWSTR Pointer;
    ULONG Length;

    Length = MultiByteToWideChar(CP_UTF8, 0, Ansi, -1, NULL, 0);
    Pointer = (PWSTR)HeapAlloc(ProcessHeapHandle, HEAP_ZERO_MEMORY, Length * sizeof(WCHAR));
    if (Pointer)
    {
        if (!MultiByteToWideChar(CP_UTF8, 0, Ansi, -1, Pointer, Length))
        {
            HeapFree(ProcessHeapHandle, 0, Pointer);
            Pointer = NULL;
        }
    }

    return Pointer;
}

VOID __stdcall IndexLookupPrint(_In_ DWORD Index)
{
    PLIST_ENTRY List;
    PWOW64_SYSCALL_INFO Entry;
    PWSTR UnicodeName;
    PWSTR DebugString;
    
    List = WoW64ListHead.Flink;

    // synchronization is unnecessary in this code
    while (List != &WoW64ListHead)
    {
        Entry = CONTAINING_RECORD(List, WOW64_SYSCALL_INFO, ListEntry);
        if (Entry->Index == Index)
        {
            UnicodeName = fMultiCharToUnicode(Entry->FunctionName);
            if (UnicodeName)
            {
                DebugString = FormatCallString(_T("Call:%s (0x%X)"), UnicodeName, Index);
                if (DebugString)
                {
                    OutputDebugStringW(DebugString);
                    HeapFree(ProcessHeapHandle, 0, DebugString);
                }

                HeapFree(ProcessHeapHandle, 0, UnicodeName);
            }

            break;
        }

        List = List->Flink;
    }
}

VOID __declspec(naked) X86SwitchTo64BitModeProxy()
{
    __asm
    {
        pushad
        mov edi, JmpSwitchBaseAddress
        mov esi, dword ptr fs:[0xC0]
        mov dword ptr fs:[0xC0], edi
        push eax
        call IndexLookupPrint
        mov dword ptr fs:[0xC0], esi
        popad
        jmp JmpSwitchBaseAddress;
    }
}

BOOL HookWow64Function(
    _In_ PVOID FunctionAddress,
    _In_ PVOID HookFunctionAddress
    )
{
    BOOL Status;
    PBYTE BytesAddress;
    BYTE HookCode[8];
    DWORD OldProtection;

    if (!FunctionAddress ||
        !HookFunctionAddress)
    {
        return FALSE;
    }

    JmpSwitchBaseAddress = VirtualAlloc(
        0, 
        16, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE);

    if (!JmpSwitchBaseAddress)
    {
        return FALSE;
    }

    BytesAddress = (PBYTE)FunctionAddress;
    if (!(BytesAddress[0] == 0xEA &&
          BytesAddress[5] == 0x33 && 
          BytesAddress[6] == 0x00))
    {
        return FALSE;
    }

    // Copy jump far
    RtlCopyMemory(JmpSwitchBaseAddress, FunctionAddress, 7);

    // Build hook code
    HookCode[0] = 0xE9;
    *((PDWORD)&HookCode[1]) = (DWORD)((ULONG_PTR)HookFunctionAddress - (ULONG_PTR)FunctionAddress - 5);

    Status = VirtualProtect(FunctionAddress, 7, PAGE_EXECUTE_READWRITE, &OldProtection);
    if (Status)
    {
        RtlCopyMemory(FunctionAddress, HookCode, 5);
        VirtualProtect(FunctionAddress, 7, OldProtection, &OldProtection);
    }

    return Status;
}

BOOL InterceptWoW64SystemCalls()
{
    BOOL bIsWoW64Process;

    CurrentProcessHandle = GetCurrentProcess();
    ProcessHeapHandle = GetProcessHeap();    
    INITIALIZE_LIST_HEAD(&WoW64ListHead);

    // Make sure we are running from WoW64 process
    if (!IsWow64Process(CurrentProcessHandle, &bIsWoW64Process))
    {
        return FALSE;
    }
    if (!bIsWoW64Process)
    {
        return FALSE;
    }

    // We list all system services 
    EnumWow64SystemFunctions();
    
    // Hook at wow64cpu!X86SwitchTo64BitMode
    return HookWow64Function((PVOID)__readfsdword(0xC0), X86SwitchTo64BitModeProxy);
}
