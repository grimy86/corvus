#ifndef WINDOWS_PRIVILEGE_PROVIDER_H
#define WINDOWS_PRIVILEGE_PROVIDER_H

#include "MuninnConfig.h"

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif // !NTSTATUS

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetSeDebugPrivilege();

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetRemoteSeDebugPrivilege(
	_In_ const HANDLE tokenHandle);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetSeDebugPrivilege(
	_In_ const HANDLE tokenHandle,
	_Out_ BOOL* const pIsSeDebugPrivilegeEnabled);

/// <summary>
/// Combines the components of a LUID into a 64-bit value.
/// </summary>
/// <param name="luid"> Source LUID structure. </param>
/// <param name="pFullLuid"> Receives the combined value. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetFullLuid(
	_In_ const LUID luid,
	_Out_ uint64_t* const pFullLuid);

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetTokenInfoBufferSize(
	_In_ const HANDLE tokenHandle,
	_In_ const TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredSize);

/// <summary>
/// Retrieves the buffer size required for NtQueryInformationToken.
/// </summary>
/// <param name="tokenHandle"> Token handle. </param>
/// <param name="infoClass"> Token information class. </param>
/// <param name="pRequiredBufferSize"> Receives the required buffer size. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQITBufferSize(
	_In_ const HANDLE tokenHandle,
	_In_ const TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize);

/// <summary>
/// Retrieves statistics for a process token.
/// </summary>
/// <param name="tokenHandle"> Token handle. </param>
/// <param name="pTokenStatistics"> Receives token statistics. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetTokenStatistics(
	_In_ const HANDLE tokenHandle,
	_Out_ TOKEN_STATISTICS* const pTokenStatistics);

/// <summary>
/// Retrieves privileges associated with a token.
/// </summary>
/// <param name="tokenHandle"> Token handle. </param>
/// <param name="pBuffer"> Destination buffer. </param>
/// <param name="bufferLength"> Buffer capacity. </param>
/// <param name="pCopiedLength"> Receives privilege count. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetTokenPriviliges(
	_In_ const HANDLE tokenHandle,
	_Out_writes_(bufferLength)
	LUID_AND_ATTRIBUTES* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength);

/// <summary>
/// Retrieves the session identifier associated with a token.
/// </summary>
/// <param name="tokenHandle"> Token handle. </param>
/// <param name="pSessionId"> Receives the session identifier. </param>
/// <returns> NTSTATUS indicating the result of the operation. </returns>
MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetTokenSessionId(
	_In_ const HANDLE tokenHandle,
	_Out_ DWORD* const pSessionId);

#endif // !WINDOWS_PRIVILEGE_PROVIDER_H