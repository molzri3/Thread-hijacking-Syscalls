/*
	ApiHashing.c - API and module hashing resolution
	-----------------------------------------------
	Purpose:
		- Implements custom API hashing to resolve function and module addresses without standard WinAPI calls.
	Main Functions:
		- Custom GetProcAddress and GetModuleHandle using hash lookups.
	Role in Project:
		- Supports stealthy API resolution, reducing reliance on standard imports and improving evasion.
*/

#include <Windows.h>

#include "Structs.h"
#include "Common.h"



FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER			pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS			pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER		ImgOptHdr = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY		pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD						FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD						FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD						FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// hashing every function name `pFunctionName`
		// if both hashes are equal, then we found the function we want 
		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}

//------------------------------------------------------------------------------------------------------------------------------------------------//
//------------------------------------------------------------------------------------------------------------------------------------------------//


HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {

			// converting `FullDllName.Buffer` to upper case string 
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)_toUpper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);

		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}