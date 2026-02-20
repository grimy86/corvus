#include "MemoryService32.h"
#include "MemoryService.h"

namespace Corvus::Memory
{
	HANDLE OpenHandle32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		HANDLE hProcess{ OpenProcess(accessMask, FALSE, processId) };
		if (Corvus::Memory::IsValidHandle(hProcess)) return hProcess;
		else return nullptr;
	}

	BOOL CloseHandle32(HANDLE handle) { return CloseHandle(handle); }

	BOOL EnableSeDebugPrivilege32()
	{
		BOOL bRet{ FALSE };
		HANDLE hToken{ nullptr };
		LUID luid{};

		if (OpenProcessToken(
			GetCurrentProcess(),
			TOKEN_ADJUST_PRIVILEGES,
			&hToken))
		{
			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			{
				TOKEN_PRIVILEGES tPriv{};
				tPriv.PrivilegeCount = 1;
				tPriv.Privileges[0].Luid = luid;
				tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				bRet = AdjustTokenPrivileges(hToken,
					FALSE,
					&tPriv,
					sizeof(TOKEN_PRIVILEGES),
					nullptr,
					nullptr);
			}
		}

		return bRet;
	}

	BOOL EnableSeDebugPrivilege32(const DWORD processId)
	{
		HANDLE hProc{ OpenHandle32(processId, PROCESS_ALL_ACCESS) };
		if (!IsValidHandle(hProc)) return FALSE;

		BOOL bRet{ FALSE };
		HANDLE hToken{ nullptr };
		LUID luid{};

		if (OpenProcessToken(
			hProc,
			TOKEN_ADJUST_PRIVILEGES,
			&hToken))
		{
			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			{
				TOKEN_PRIVILEGES tPriv{};
				tPriv.PrivilegeCount = 1;
				tPriv.Privileges[0].Luid = luid;
				tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				bRet = AdjustTokenPrivileges(hToken,
					FALSE,
					&tPriv,
					sizeof(TOKEN_PRIVILEGES),
					nullptr,
					nullptr);
			}
		}

		CloseHandle32(hProc);
		return bRet;
	}

	BOOL SetThreadPriority32(int priorityMask)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityMask);
	}

	BOOL  SuspendThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseHandle32(hThread);
		return TRUE;
	}

	BOOL ResumeThread32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseHandle32(hThread);
		return TRUE;
	}

	void PatchExecutionExt32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void PatchExecutionInt32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	void NopExecutionExt32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionExt32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	void NopExecutionInt32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	DWORD FindDMAAddyExt32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	DWORD FindDMAAddyInt32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}
}