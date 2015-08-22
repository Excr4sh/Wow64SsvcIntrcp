
#include <Windows.h>
#include <tchar.h>

typedef struct _WOW64_SYSCALL_INFO
{
    PSTR FunctionName;
    ULONG Index;
    LIST_ENTRY ListEntry;

}WOW64_SYSCALL_INFO, *PWOW64_SYSCALL_INFO;

PWOW64_SYSCALL_INFO AllocWow64Entry(
    _In_ PSTR FunctionName,
    _In_ ULONG Index
    );

BOOL AddWoW64FunctionEntry(
    _In_ PSTR FunctionName,
    _In_ PVOID FunctionAddress
    );

BOOL EnumWow64SystemFunctions();

PWSTR FormatCallString(
    _In_ _Printf_format_string_ PWSTR Format,
    ...
    );

PWSTR FormatCallStringEx(
    _In_ _Printf_format_string_ PWSTR Format,
    _In_ va_list ArgPtr
    );

VOID __stdcall IndexLookupPrint(_In_ DWORD Index);

VOID __declspec() X86SwitchTo64BitModeProxy();

BOOL HookWow64Function(
    _In_ PVOID FunctionAddress,
    _In_ PVOID HookFunctionAddress
    );

BOOL InterceptWoW64SystemCalls();
