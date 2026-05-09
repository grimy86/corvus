#include "WindowsPrivilegeProvider.h"
#include "WindowsUtilityProvider.h"

#ifndef SE_DEBUG_NAME_W
#define SE_DEBUG_NAME_W L"SeDebugPrivilege"
#endif // !SE_DEBUG_NAME_W

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetSeDebugPrivilege()
{
	HANDLE tokenHandle = NULL;
	NTSTATUS status = DAL_Win32_OpenTokenHandle(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&tokenHandle);

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_HANDLE;

	LUID luid = { 0ul, 0l };
	status = LookupPrivilegeValueW(
		NULL,
		SE_DEBUG_NAME_W,
		&luid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		DAL_CloseHandle32(tokenHandle);
		return status;
	}

	if (!DAL_IsValidLuid(luid))
	{
		DAL_CloseHandle32(tokenHandle);
		return STATUS_UNSUCCESSFUL;
	}

	TOKEN_PRIVILEGES privileges = { 0 };
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&privileges,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(status))
	{
		DAL_CloseHandle32(tokenHandle);
		return status;
	}

	// privilege missing
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		DAL_CloseHandle32(tokenHandle);
		return STATUS_UNSUCCESSFUL;
	}

	DAL_CloseHandle32(tokenHandle);
	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_SetRemoteSeDebugPrivilege(
	_In_ const HANDLE tokenHandle)
{
	// required: TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_HANDLE;

	LUID luid = { 0ul, 0l };
	NTSTATUS status = LookupPrivilegeValueW(
		NULL,
		SE_DEBUG_NAME_W,
		&luid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
		return status;

	if (!DAL_IsValidLuid(luid))
		return STATUS_UNSUCCESSFUL;

	TOKEN_PRIVILEGES privileges = { 0 };
	privileges.PrivilegeCount = 1;
	privileges.Privileges[0].Luid = luid;
	privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	status = AdjustTokenPrivileges(
		tokenHandle,
		FALSE,
		&privileges,
		sizeof(TOKEN_PRIVILEGES),
		NULL,
		NULL) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (NT_SUCCESS(status))
		return status;

	// privilege missing
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return STATUS_UNSUCCESSFUL;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetSeDebugPrivilege(
	_In_ const HANDLE tokenHandle,
	_Out_ BOOL* const pIsSeDebugPrivilegeEnabled)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pIsSeDebugPrivilegeEnabled == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pIsSeDebugPrivilegeEnabled = FALSE;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = DAL_Win32_GetTokenInfoBufferSize(
		tokenHandle,
		TokenPrivileges,
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
		return status;

	if (!requiredBufferSize)
		return STATUS_UNSUCCESSFUL;

	BYTE* privilegesBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (privilegesBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = GetTokenInformation(
		tokenHandle,
		TokenPrivileges,
		privilegesBuffer,
		requiredBufferSize,
		&requiredBufferSize) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	PTOKEN_PRIVILEGES pTokenPrivileges =
		(PTOKEN_PRIVILEGES)(privilegesBuffer);

	LUID debugLuid = { 0ul, 0l };
	status = LookupPrivilegeValueW(
		NULL,
		SE_DEBUG_NAME_W,
		&debugLuid) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		free(privilegesBuffer);
		return status;
	}

	if (!DAL_IsValidLuid(debugLuid))
	{
		free(privilegesBuffer);
		return STATUS_UNSUCCESSFUL;
	}

	status = STATUS_NOT_FOUND;
	for (DWORD i = 0ul; i < pTokenPrivileges->PrivilegeCount; ++i)
	{
		LUID_AND_ATTRIBUTES* pLaa =
			&pTokenPrivileges->Privileges[i];

		if (pLaa->Luid.LowPart == debugLuid.LowPart &&
			pLaa->Luid.HighPart == debugLuid.HighPart)
		{
			*pIsSeDebugPrivilegeEnabled =
				(pLaa->Attributes & SE_PRIVILEGE_ENABLED) != FALSE;

			status = STATUS_SUCCESS;
			break;
		}
	}

	free(privilegesBuffer);
	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetFullLuid(
	_In_ const LUID luid,
	_Out_ uint64_t* const pFullLuid)
{
	if (!DAL_IsValidLuid(luid))
		return STATUS_INVALID_PARAMETER_1;
	if (pFullLuid == NULL)
		return STATUS_INVALID_PARAMETER_2;

	// cast to uint32_t first to avoid sign extension of signed LONG
	*pFullLuid
		= ((uint64_t)(uint32_t)luid.HighPart << 32) |
		(uint64_t)luid.LowPart;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_GetTokenInfoBufferSize(
	_In_ const HANDLE tokenHandle,
	_In_ const TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredSize)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pRequiredSize == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pRequiredSize = 0ul;

	NTSTATUS status = GetTokenInformation(
		tokenHandle,
		infoClass,
		NULL,
		0,
		pRequiredSize) ?
		STATUS_SUCCESS :
		STATUS_UNSUCCESSFUL;

	if (!NT_SUCCESS(status))
	{
		if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			return STATUS_BUFFER_TOO_SMALL;
		else return status;
	}

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetQITBufferSize(
	_In_ const HANDLE tokenHandle,
	_In_ const TOKEN_INFORMATION_CLASS infoClass,
	_Out_ DWORD* const pRequiredBufferSize)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pRequiredBufferSize == NULL)
		return STATUS_INVALID_PARAMETER_3;

	*pRequiredBufferSize = 0ul;

	NTSTATUS status = NtQueryInformationToken(
		tokenHandle,
		infoClass,
		NULL,
		0,
		pRequiredBufferSize);

	if (status != STATUS_INFO_LENGTH_MISMATCH)
		*pRequiredBufferSize = 0ul;

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetProcessTokenStatistics(
	_In_ const HANDLE tokenHandle,
	_Out_ TOKEN_STATISTICS* const pTokenStatistics)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pTokenStatistics == NULL)
		return STATUS_INVALID_PARAMETER_2;

	memset(
		pTokenStatistics,
		0,
		sizeof(TOKEN_STATISTICS));

	// requiredBufferSize, the tarnished one
	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = NtQueryInformationToken(
		tokenHandle,
		(TOKEN_INFORMATION_CLASS)TokenStatistics, // phnt
		pTokenStatistics,
		sizeof(TOKEN_STATISTICS),
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
		memset(
			pTokenStatistics,
			0,
			sizeof(TOKEN_STATISTICS));

	return status;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetTokenPriviliges(
	_In_ const HANDLE tokenHandle,
	_Out_writes_(bufferLength)
	LUID_AND_ATTRIBUTES* const pBuffer,
	_In_ const DWORD bufferLength,
	_Out_ DWORD* const pCopiedLength)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pBuffer == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (pCopiedLength == NULL)
		return STATUS_INVALID_PARAMETER_4;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = DAL_Nt_GetQITBufferSize(
		tokenHandle,
		TokenPrivileges,
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
		return status;

	BYTE* privilegesBuffer =
		(BYTE*)malloc(requiredBufferSize);
	if (privilegesBuffer == NULL)
		return STATUS_NO_MEMORY;

	status = NtQueryInformationToken(
		tokenHandle,
		TokenPrivileges,
		privilegesBuffer,
		requiredBufferSize,
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
	{
		free(privilegesBuffer);
		return status;
	}

	PTOKEN_PRIVILEGES privileges =
		(PTOKEN_PRIVILEGES)privilegesBuffer;

	DWORD totalPrivileges = privileges->PrivilegeCount;

	DWORD copied = DAL_MinU32(
		bufferLength,
		totalPrivileges);

	for (DWORD i = 0ul; i < copied; ++i)
	{
		pBuffer[i] = privileges->Privileges[i];
	}

	*pCopiedLength = totalPrivileges;
	free(privilegesBuffer);
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_GetTokenSessionId(
	_In_ const HANDLE tokenHandle,
	_Out_ DWORD* const pSessionId)
{
	if (!DAL_IsValidHandle(tokenHandle))
		return STATUS_INVALID_PARAMETER_1;
	if (pSessionId == NULL)
		return STATUS_INVALID_PARAMETER_2;

	*pSessionId = 0ul;

	DWORD requiredBufferSize = 0ul;
	NTSTATUS status = NtQueryInformationToken(
		tokenHandle,
		TokenSessionId,
		pSessionId,
		sizeof(ULONG),
		&requiredBufferSize);

	if (!NT_SUCCESS(status))
		*pSessionId = 0ul;

	return status;
}

/*
BOOL GetProcessTokenPriviligeObjectsNt(const HANDLE tokenHandle, std::vector<Muninn::Object::PrivilegeEntry>& privileges)
{
	if (!IsValidHandle(tokenHandle)) return FALSE;

	std::vector<LUID_AND_ATTRIBUTES> priviligesBuffer
	{ DAL_Nt_GetTokenPriviliges(tokenHandle) };
	if (priviligesBuffer.empty()) return FALSE;

	for (LUID_AND_ATTRIBUTES privilege : priviligesBuffer)
	{
		Muninn::Object::PrivilegeEntry privilegeEntry{};
		privilegeEntry.TokenLuid = DAL_Nt_GetFullLuid(privilege.Luid);
		privilegeEntry.TokenAttributes = privilege.Attributes;
		privileges.push_back(privilegeEntry);
	}
	return TRUE;
}

BOOL GetProcessAccessTokenObjectNt(
	const HANDLE processHandle,
	const ACCESS_MASK accessMask,
	Muninn::Object::AccessTokenModel& accessToken)
{
	if (!IsValidHandle(processHandle)) return FALSE;

	HANDLE tokenHandle{ DAL_Nt_OpenTokenHandle(processHandle, accessMask) };
	if (!IsValidHandle(tokenHandle)) return FALSE;

	TOKEN_STATISTICS statistics{
		DAL_Nt_GetProcessTokenStatistics(tokenHandle) };
	if (!IsValidLuid(statistics.TokenId)) return FALSE;
	if (statistics.PrivilegeCount <= 0) return FALSE;

	DWORD sessionId{ DAL_Nt_GetTokenSessionId(tokenHandle) };
	if (!sessionId) return FALSE;

	std::vector<Muninn::Object::PrivilegeEntry> privileges{};
	if (!GetProcessTokenPriviligeObjectsNt(tokenHandle, privileges))
		return FALSE;

	accessToken.TokenPrivileges = privileges;
	accessToken.TokenId = DAL_Nt_GetFullLuid(statistics.TokenId);
	accessToken.AuthenticationId = DAL_Nt_GetFullLuid(statistics.AuthenticationId);
	accessToken.SessionId = sessionId;
	return TRUE;
}
*/