/*
    Debug.h - CRT-free debug output macros and helpers
    -----------------------------------------------
    Purpose:
        - Provides macros and helper functions for debug output without relying on the C runtime (CRT).
    Main Contents:
        - Macros for formatted ASCII and wide-character console output (PRINTA, PRINTW).
        - CRT-free getchar replacement (GETCHARA).
    Role in Project:
        - Enables debug logging and console interaction in a portable, CRT-independent way.
*/

/*
    If you Encounter a problem with CRT func you can use this file to replace them 
    and make the builder happy 
*/

#pragma once

#include <Windows.h>

// uncomment to enable debug mode
#define DEBUG



#ifdef DEBUG

// wprintf replacement
#define PRINTW( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleW( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  


// printf replacement
#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

/// CRT‑free getchar replacement
#ifndef EOF
#define EOF    (-1)
#endif

/// CRT‑free getchar replacement
static __forceinline int GETCHARA(void) {
    CHAR  ch = 0;
    DWORD read = 0;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);

    // Read exactly 1 byte from the console
    if (hIn == INVALID_HANDLE_VALUE
        || !ReadConsoleA(hIn, &ch, 1, &read, NULL)
        || read == 0
        ) {
        return EOF;
    }

    return (unsigned char)ch;
}




#endif // DEBUG




