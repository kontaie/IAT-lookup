#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <iostream>
#include <string>

HANDLE GetProcessHandle(const std::wstring& process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(snapshot, &process_entry)) {
        CloseHandle(snapshot);
        return NULL;
    }

    do {
        if (_wcsicmp(process_entry.szExeFile, process_name.c_str()) == 0) {
            HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_entry.th32ProcessID);
            if (process_handle != NULL) {
                CloseHandle(snapshot);
                return process_handle;
            }
        }
    } while (Process32Next(snapshot, &process_entry));

    CloseHandle(snapshot);
    return NULL;
}

void injector(HANDLE process, char* dllpath) {
    SIZE_T allocs = strlen(dllpath) + 1;  
    SIZE_T lpNumberOfBytesWritten = 0;

    LPVOID lploadlib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    LPVOID lpmem = VirtualAllocEx(process, NULL, allocs, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(process, lpmem, dllpath, allocs, &lpNumberOfBytesWritten);
    HANDLE hThread = CreateRemoteThread(process, NULL, NULL, (LPTHREAD_START_ROUTINE)lploadlib, lpmem, NULL, NULL);
}

int main() {
    std::string dllpath;
    std::wstring process_name;
    std::wcout << L"Enter DLL path: ";
    std::cin >> dllpath;
    std::wcout << L"\nEnter process name: ";
    std::wcin >> process_name;

    HANDLE process = GetProcessHandle(process_name);
    if (process) {
        std::wcout << L"Process handle obtained: " << process << std::endl;
    }
    else {
        std::wcout << L"Failed to get process handle." << std::endl;
    }

    injector(process, (char*)dllpath.c_str());

    return 0;
}