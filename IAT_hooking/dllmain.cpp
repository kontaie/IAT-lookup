#include "pch.h"
#include <iostream>
#include <fstream>
#include <Windows.h>
#include <winternl.h>
#include <vector>

using FTMessageBox = int (WINAPI*)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

FTMessageBox originalMsgBox = MessageBoxA;

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    return originalMsgBox(hWnd, "h00ked", lpCaption, uType);
}

void Log(const std::string& message) {
    std::ofstream logFile("C:\\Users\\levdk\\OneDrive\\Desktop\\logfile.txt", std::ios_base::app);
    logFile << message << std::endl;
}

DWORD FunctionsEnum() {
    LPVOID imageBase = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE) {
        return 1;
    }
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)imageBase + dosHeaders->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return 1;
    }

#ifdef _WIN64
    IMAGE_OPTIONAL_HEADER64 OptionalHeader = ntHeaders->OptionalHeader;
#else
    IMAGE_OPTIONAL_HEADER32 OptionalHeader = ntHeaders->OptionalHeader;
#endif

    IMAGE_DATA_DIRECTORY import_dir = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR import_des = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)imageBase + import_dir.VirtualAddress);
    SIZE_T dllnum = import_dir.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

    std::vector<HMODULE> dlls;

    for (int i = 0; i < dllnum - 1; i++) {
        LPCSTR dllname = (LPCSTR)((uintptr_t)imageBase + import_des[i].Name);
        Log("[i]Found Dll : " + std::string(dllname) + "\n############\n");
        HMODULE dll = LoadLibraryA(dllname);
        dlls.push_back(dll);
    }
    for (HMODULE dll : dlls) {
        if (dll) {
            PIMAGE_THUNK_DATA ogthunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + import_des->OriginalFirstThunk);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((uintptr_t)imageBase + import_des->FirstThunk);

            while (ogthunk->u1.AddressOfData != NULL)
            {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)imageBase + ogthunk->u1.AddressOfData);
                std::string(functionName->Name);
                Log("[i]imported function : " + std::string(functionName->Name));
                ogthunk++;
                thunk++;
            }
        }
        break;
    }
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        FunctionsEnum();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
