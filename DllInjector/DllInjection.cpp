
#include "DllInjection.h"

BOOL EnableDebugPrivilege(_In_ HANDLE ProcessHandle)
{
    BOOL Status;
    HANDLE TokenHandle;
    TOKEN_PRIVILEGES TokenPriv;
    LUID Luid;

    if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &Luid))
    {
        return FALSE;
    }
    if (!OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES, &TokenHandle))
    {
        return FALSE;
    }

    TokenPriv.PrivilegeCount = 1;
    TokenPriv.Privileges[0].Luid = Luid;
    TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Status = AdjustTokenPrivileges(
        TokenHandle,
        FALSE,
        &TokenPriv,
        sizeof(TOKEN_PRIVILEGES),
        NULL,
        NULL);

    CloseHandle(TokenHandle);
    return Status;
}

BOOL InjectDll(
    _In_ DWORD ProcessId,
    _In_ PCSTR DllPath
    )
{
    BOOL Status;
    HANDLE ProcessHandle;
    SIZE_T DllPathLength;
    LPVOID RemoteBuffer;
    SIZE_T Written;
    HANDLE ThreadHandle;

    DllPathLength = lstrlenA(DllPath);
    if (!DllPathLength)
    {
        return FALSE;
    }

    if (!EnableDebugPrivilege(GetCurrentProcess()))
    {
        return FALSE;
    }

    ProcessHandle = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
        FALSE, 
        ProcessId);

    if (!ProcessHandle)
    {
        return FALSE;
    }

    Status = FALSE;
    RemoteBuffer = VirtualAllocEx(
        ProcessHandle, 
        NULL, 
        DllPathLength + 1, 
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE);

    if (RemoteBuffer)
    {
        if (WriteProcessMemory(
            ProcessHandle,
            RemoteBuffer,
            DllPath,
            DllPathLength + 1,
            &Written
            ))
        {
            ThreadHandle = CreateRemoteThread(
                ProcessHandle,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)LoadLibraryA,
                RemoteBuffer,
                0,
                NULL);

            if (ThreadHandle)
            {
                WaitForSingleObject(ProcessHandle, INFINITE);
                CloseHandle(ThreadHandle);
                Status = TRUE;
            }
        }
    }

    CloseHandle(ProcessHandle);
    return Status;
}



