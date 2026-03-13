#ifndef MUNINN_DATA_UTILITIES
#define MUNINN_DATA_UTILITIES

#include "phnt/phnt_windows.h"
#include <stdbool.h>

bool MDAL_IsValidProcessId(const DWORD processId);
bool MDAL_IsValidHandle(const HANDLE processHandle);
bool MDAL_IsValidAddress(const DWORD moduleBaseAddress);
bool MDAL_IsValidLuid(const LUID luid);

#endif // !MUNINN_DATA_UTILITIES