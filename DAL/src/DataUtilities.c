#include "DataUtilities.h"

bool MDAL_IsValidProcessId(const DWORD processId)
{
	return processId % 4ul == 0ul;
}

bool MDAL_IsValidHandle(const HANDLE handle)
{
	return (handle != NULL &&
		handle != INVALID_HANDLE_VALUE);
}

bool MDAL_IsValidAddress(const DWORD address)
{
	return address != ERROR_INVALID_ADDRESS;
}

bool MDAL_IsValidLuid(const LUID luid)
{
	return (luid.HighPart != 0ul && luid.LowPart != 0ul);
}