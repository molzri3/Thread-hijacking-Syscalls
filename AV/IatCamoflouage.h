/*
    IatCamoflouage.h - IAT camouflage and benign API references
    ----------------------------------------------------------
    Purpose:
        - Implements harmless helper functions to populate the Import Address Table (IAT) with benign API references, camouflaging the binary.
    Main Contents:
        - Functions for runtime seeding, memory operations, and benign API calls.
    Role in Project:
        - Helps evade static analysis by making the IAT appear less suspicious and more like a typical application.
*/
#pragma once

#include <Windows.h>
#include <time.h>

// Generate a pseudo-random runtime seed using local time
int RuntimeSeed() {
    SYSTEMTIME st;
    GetSystemTime(&st);

    return (st.wHour * 3600 + st.wMinute * 60 + st.wSecond + st.wMilliseconds) ^ GetCurrentProcessId();
}

// Harmless helper function doing basic memory operation
PVOID CleanHelper(PVOID* ppAddress) {
    SIZE_T allocSize = (RuntimeSeed() % 0x100) + 1;  // small random buffer size
    PVOID pBuffer = VirtualAlloc(NULL, allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuffer)
        return NULL;

    memset(pBuffer, 'A', allocSize);  // fill with dummy data
    *ppAddress = pBuffer;
    return pBuffer;
}

// Harmless API reference to populate IAT without suspicious usage
VOID CleanIatCamouflage() {
    PVOID pAddress = NULL;
    BYTE* buf = (BYTE*)CleanHelper(&pAddress);

    // Unreachable condition (safe but weird logic)
    if (buf[0] > 250 && buf[0] < 1) {
        // benign common APIs to populate IAT
        HWND hwnd = GetForegroundWindow();
        RECT rect;
        GetClientRect(hwnd, &rect);
        POINT pt = { 0 };
        ClientToScreen(hwnd, &pt);
        int len = GetWindowTextLengthW(hwnd);
        WCHAR* tmp = (WCHAR*)HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(WCHAR));
        if (tmp) {
            GetWindowTextW(hwnd, tmp, len + 1);
            HeapFree(GetProcessHeap(), 0, tmp);
        }
        Sleep(10);  // Sleep is benign and often used
        GetTickCount(); // harmless timing
    }

    // Clean up
    if (pAddress)
        VirtualFree(pAddress, 0, MEM_RELEASE);
}
