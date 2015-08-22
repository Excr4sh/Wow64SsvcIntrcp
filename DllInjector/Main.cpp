
#include <tchar.h>
#include <Windows.h>
#include <iostream>
#include <string>
#include "DllInjection.h"

using namespace std;

int main(int argc, char* argv[])
{
    string ProcessId;
    char DllPath[MAX_PATH + 1];
    string StdDllPath;

    cout << "Wow64HookDll Injector\n";
    cout << "Process Identifier: \n";
    cin >> ProcessId;

    GetModuleFileNameA(NULL, DllPath, MAX_PATH);
    string::size_type Pos = string(DllPath).find_last_of("\\");
    StdDllPath = string(DllPath).substr(0, Pos) + "\\Wow64HookDll.dll";
    if (InjectDll(stoi(ProcessId, 0, 0), StdDllPath.c_str()))
    {
        cout << "injeccion succeeded\n";
    }
    else
    {
        cout << "Injection failed\n";
    }

    cin >> DllPath;
    return 0;
}

