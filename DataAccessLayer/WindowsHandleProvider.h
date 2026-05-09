#ifndef WINDOWS_HANDLE_PROVIDER_H
#define WINDOWS_HANDLE_PROVIDER_H

#include "MuninnConfig.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_OpenProcessHandle(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle);

/// <summary>
/// Opens a handle to a process.
/// </summary>
/// <param name="processId"> Target process identifier. </param>
/// <param name="accessMask"> Desired access rights. </param>
/// <param name="pHandle"> Receives the process handle. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_OpenProcessHandle(
	_In_ const DWORD processId,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pHandle);

/// <summary>
/// Closes a handle.
/// </summary>
/// <param name="handle"> Handle to close. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_CloseHandle(_In_ const HANDLE handle);

/// <summary>
/// Duplicates a handle from another process into the current process.
/// </summary>
/// <param name="sourceHandle"> Handle in the source process. </param>
/// <param name="processId"> Identifier of the process that owns the handle. </param>
/// <param name="pDuplicatedHandle"> Receives the duplicated handle. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_DuplicateHandle(
	_In_ const HANDLE sourceHandle,
	_In_ const DWORD processId,
	_Out_ HANDLE* const pDuplicatedHandle);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_OpenTokenHandle(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle);

/// <summary>
/// Opens the access token associated with a process.
/// </summary>
/// <param name="processHandle"> Handle to the process. </param>
/// <param name="accessMask"> Desired token access rights. </param>
/// <param name="pTokenHandle"> Receives the token handle. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_OpenTokenHandle(
	_In_ const HANDLE processHandle,
	_In_ const ACCESS_MASK accessMask,
	_Out_ HANDLE* const pTokenHandle);

#endif // !WINDOWS_HANDLE_PROVIDER_H