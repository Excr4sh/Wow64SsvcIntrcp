
#include <Windows.h>
#include <tchar.h>
#include "Wow64Hook.h"

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD     fdwReason,
    _In_ LPVOID    lpvReserved
    )
{
    BOOL Status;

    Status = TRUE;
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:

        // Disable notifications
        DisableThreadLibraryCalls(hinstDLL);

        OutputDebugStringW(L"Wow64HookDll Loading");

        Status = InterceptWoW64SystemCalls();

        if (Status)
            OutputDebugStringW(L"succeeded");
        else
            OutputDebugStringW(L"failed");

        break;
    case DLL_PROCESS_DETACH:
        // Here we can unhook and free resources
        OutputDebugStringW(L"Wow64HookDll Unloading");
        break;
    }

    return Status;
}
