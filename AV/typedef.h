/*
	header file that contains the defintions of the WinAPIs used

*/

#pragma once

#include <Windows.h>
#include <tlhelp32.h>

/*
typedef struct tagTHREADENTRY32 {
    DWORD dwSize;
    DWORD cntUsage;
    DWORD th32ThreadID;
    DWORD th32OwnerProcessID;
    LONG  tpBasePri;
    LONG  tpDeltaPri;
    DWORD dwFlags;
} THREADENTRY32, * PTHREADENTRY32, * LPTHREADENTRY32;
*/

#ifndef TYPEDEF_H
#define TYPEDEF_H


// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
typedef ULONGLONG(WINAPI* fnGetTickCount64)();

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
typedef HANDLE(WINAPI* fnOpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex
typedef LRESULT(WINAPI* fnCallNextHookEx)(HHOOK hhk, int nCode, WPARAM wParam, LPARAM lParam);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw
typedef HHOOK(WINAPI* fnSetWindowsHookExW)(int idHook, HOOKPROC lpfn, HINSTANCE hmod, DWORD dwThreadId);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew
typedef BOOL(WINAPI* fnGetMessageW)(LPMSG lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowprocw
typedef LRESULT(WINAPI* fnDefWindowProcW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex
typedef BOOL(WINAPI* fnUnhookWindowsHookEx)(HHOOK hhk);

// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamew
typedef DWORD(WINAPI* fnGetModuleFileNameW)(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);

// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
typedef HANDLE(WINAPI* fnCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

// https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle
typedef BOOL(WINAPI* fnSetFileInformationByHandle)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize);

// https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
typedef BOOL(WINAPI* fnCloseHandle)(HANDLE hObject);

typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
    );

typedef BOOL(WINAPI* fnThread32First)(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
    );

typedef BOOL(WINAPI* fnThread32Next)(
    HANDLE hSnapshot,
    LPTHREADENTRY32 lpte
    );
//THREADENTRY32

#endif // !TYPEDEF_H
