#include "WindowsUtilityProvider.h"

MUNINN_API bool MUNINN_CALL
DAL_IsValidProcessId(
	_In_ const DWORD processId)
{
	// Process Ids are typically multiples of 4
	return processId % 4ul == 0ul;
}

MUNINN_API
_Success_(return != FALSE)
bool MUNINN_CALL
DAL_IsValidHandle(
	_In_ const HANDLE handle)
{
	return (handle != NULL &&
		handle != INVALID_HANDLE_VALUE);
}

MUNINN_API bool MUNINN_CALL
DAL_IsValidAddress(
	_In_ const uintptr_t address)
{
	return address != 0ull;
}

MUNINN_API bool MUNINN_CALL
DAL_IsValidLuid(
	_In_ const LUID luid)
{
	return (luid.HighPart != 0ul && luid.LowPart != 0ul);
}

MUNINN_API size_t MUNINN_CALL
DAL_MinSizeT(
	_In_ const size_t a,
	_In_ const size_t b)
{
	return a < b ? a : b;
}

MUNINN_API uint32_t MUNINN_CALL
DAL_MinU32(
	_In_ const uint32_t a,
	_In_ const uint32_t b)
{
	return (a < b) ? a : b;
}