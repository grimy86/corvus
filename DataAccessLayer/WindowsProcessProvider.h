#ifndef WINDOWS_PROCESS_PROVIDER_H
#define WINDOWS_PROCESS_PROVIDER_H

#include "MuninnConfig.h"
#include <TlHelp32.h>
#include <ProcessSnapshot.h>

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

/// <summary>
/// Retrieves the buffer size required for NtQuerySystemInformation.
/// </summary>
/// <param name="infoClass"> System information class. </param>
/// <param name="pRequiredBufferSize"> Receives the required buffer size. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQSIBufferSize(
	_In_ const SYSTEM_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize);

/// <summary>
/// Retrieves the buffer size required for NtQueryObject.
/// </summary>
/// <param name="duplicatedHandle"> Handle to query. </param>
/// <param name="infoClass"> Object information class. </param>
/// <param name="pRequiredBufferSize"> Receives the required buffer size. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQOBufferSize(
	_In_ const HANDLE duplicatedHandle,
	_In_ const OBJECT_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize);

/// <summary>
/// Retrieves the name of a kernel object referenced by a handle.
/// </summary>
/// <param name="sourceHandle"> Handle in the source process. </param>
/// <param name="processId"> Process that owns the handle. </param>
/// <param name="pBuffer"> Destination string buffer. </param>
/// <param name="bufferLength"> Buffer length in characters. </param>
/// <param name="pCopiedLength"> Receives number of characters written. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetObjectName(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves the type name of a kernel object referenced by a handle.
/// </summary>
/// <param name="sourceHandle"> Handle in the source process. </param>
/// <param name="processId"> Process that owns the handle. </param>
/// <param name="pBuffer"> Destination string buffer. </param>
/// <param name="bufferLength"> Buffer length in characters. </param>
/// <param name="pCopiedLength"> Receives number of characters written. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetObjectType(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Reads a UNICODE_STRING structure from a remote process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pRemoteUnicodeString"> Address of the remote UNICODE_STRING. </param>
/// <param name="pBuffer"> Destination string buffer. </param>
/// <param name="bufferLength"> Buffer length in characters. </param>
/// <param name="pCopiedLength"> Receives number of characters written. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetRemoteUnicodeString(
	_In_ const HANDLE processHandle,
	_In_ const UNICODE_STRING* const pRemoteUnicodeString,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessId(
	_In_ const WCHAR* const processName,
	_Out_ DWORD* const pProcessId,
	_Out_ BOOL* const pIsRunning);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessInformation(
	_In_ const DWORD processId,
	_Out_ PROCESSENTRY32W* const pProcessEntry);

/// <summary>
/// Retrieves information about all processes in the system.
/// </summary>
/// <param name="ppBuffer">
/// Receives a pointer to a heap-allocated buffer containing the 
/// full SYSTEM_PROCESS_INFORMATION list. The caller is responsible
/// for freeing this buffer with free().
/// </param>
/// <param name="pSize"> Receives the size, in bytes, of the returned buffer. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetSystemProcessInformation(
	_Out_ BYTE** const ppBuffer,
	_Out_ DWORD* const pSize);

/// <summary>
/// Retrieves extended information about a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pProcessInfo"> Receives the process information structure. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessInformation(
	_In_ const HANDLE processHandle,
	_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves the image file name of a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer length. </param>
/// <param name="pCopiedLength"> Receives number of characters written. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves the Win32 image path of a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer length. </param>
/// <param name="pCopiedLength"> Receives number of characters written. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetWin32ImageFileName(
	_In_ const HANDLE processHandle,
	_Out_writes_(bufferLength)
	WCHAR* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetModuleBaseAddress(
	_In_ const DWORD processId,
	_In_ const wchar_t* const pModuleName,
	_Out_ uintptr_t* const pModuleBaseAddress);

/// <summary>
/// Retrieves the address of the Process Environment Block (PEB).
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPebBaseAddress"> Receives the PEB address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress);

/// <summary>
/// Retrieves the PEB address from process information.
/// </summary>
/// <param name="pProcessInfo"> Process information structure. </param>
/// <param name="pPebBaseAddress"> Receives the PEB address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddressFromProcessInfo(
	_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo,
	_Out_ uintptr_t* const pPebBaseAddress);

/// <summary>
/// Retrieves the PEB address and process information.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPebBaseAddress"> Receives the PEB address. </param>
/// <param name="pProcessInfo"> Receives process information. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebBaseAddressAndProcessInfo(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress,
	_Out_ PROCESS_EXTENDED_BASIC_INFORMATION* const pProcessInfo);

/// <summary>
/// Reads the PEB structure of a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPeb"> Receives the PEB structure. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPeb(
	_In_ const HANDLE processHandle,
	_Out_ PEB* const pPeb);

/// <summary>
/// Retrieves both the PEB address and PEB structure.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPebBaseAddress"> Receives the PEB address. </param>
/// <param name="pPeb"> Receives the PEB structure. </param>
/// <returns></returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetPebAndPebBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pPebBaseAddress,
	_Out_ PEB* const pPeb);

/// <summary>
/// Retrieves the base address of the main module of a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pModuleBaseAddress"> Receives the module base address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddress(
	_In_ const HANDLE processHandle,
	_Out_ uintptr_t* const pModuleBaseAddress);

/// <summary>
/// Retrieves the base address of the main module using process information.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="processInfo"> Process information containing the PEB address. </param>
/// <param name="pModuleBaseAddress"> Receives the module base address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromProcessInfo(
	_In_ const HANDLE processHandle,
	_In_ const PROCESS_EXTENDED_BASIC_INFORMATION* const processInfo,
	_Out_ uintptr_t* const pModuleBaseAddress);

/// <summary>
/// Retrieves the base address of the main module using a PEB address.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPebBaseAddress"> PEB address. </param>
/// <param name="pModuleBaseAddress"> Receives the module base address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromPebBaseAddress(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t* const pPebBaseAddress,
	_Out_ uintptr_t* const pModuleBaseAddress);

/// <summary>
/// Retrieves the base address of the main module using a PEB structure.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPeb"> PEB structure. </param>
/// <param name="pModuleBaseAddress"> Receives the module base address. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetModuleBaseAddressFromPeb(
	_In_ const HANDLE processHandle,
	_In_ const PEB* const pPeb,
	_Out_ uintptr_t* const pModuleBaseAddress);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetWindowVisibility(
	_In_ const DWORD processId,
	_Out_ BOOL* const pIsWindowVisible);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessArchitecture(
	_In_ const HANDLE processHandle,
	_Out_ USHORT* const pProcessMachine,
	_Out_ USHORT* const pNativeMachine,
	_Out_ BOOL* const pIsWow64);

/// <summary>
/// Retrieves the WOW64 information for a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pWow64Info"> Receives the WOW64 information pointer. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetWow64Info(
	_In_ const HANDLE processHandle,
	_Out_ ULONG_PTR* const pWow64Info);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessModules(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	MODULEENTRY32W* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves modules loaded in a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="pPeb"> PEB structure. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer capacity. </param>
/// <param name="pCopiedLength"> Receives module count. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessModules(
	_In_ const HANDLE processHandle,
	_In_ const PEB* const pPeb,
	_Out_writes_(bufferLength)
	LDR_DATA_TABLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessThreads(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	THREADENTRY32* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves threads belonging to a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="processId"> Process identifier. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer capacity. </param>
/// <param name="pCopiedLength"> Receives thread count. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessThreads(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	SYSTEM_THREAD_INFORMATION* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetProcessHandles(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	PSS_HANDLE_ENTRY* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves handles owned by a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="processId"> Process identifier. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer capacity. </param>
/// <param name="pCopiedLength"> Receives handle count. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessHandles(
	_In_ const HANDLE processHandle,
	_In_ const DWORD processId,
	_Out_writes_(bufferLength)
	SYSTEM_HANDLE_TABLE_ENTRY_INFO* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

#endif // !WINDOWS_PROCESS_PROVIDER_H