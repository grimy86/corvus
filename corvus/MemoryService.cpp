#include "MemoryService.h"
#include "MemoryService32.h"

namespace Corvus::Memory
{
	bool IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
	bool IsValidAddress(const DWORD address) noexcept { return address != ERROR_INVALID_ADDRESS; }
	bool IsValidHandle(const HANDLE handle) noexcept
	{
		return (handle != nullptr &&
			handle != reinterpret_cast<HANDLE>(-1) &&
			handle != INVALID_HANDLE_VALUE);
	}

	BOOL Inject(DWORD processId, const std::wstring& dllPath)
	{
		if (dllPath.empty()) return FALSE;

		// Open process
		HANDLE hProcess{
			OpenHandle32(
				processId,
				PROCESS_CREATE_THREAD |
				PROCESS_QUERY_INFORMATION |
				PROCESS_VM_OPERATION |
				PROCESS_VM_WRITE |
				PROCESS_VM_READ
			) };

		if (!IsValidHandle(hProcess))
			return FALSE;

		// Allocate memory in target process
		const size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);

		void* remotePath =
			VirtualAllocEx(
				hProcess,
				nullptr,
				bytes,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE);

		if (!remotePath)
		{
			CloseHandle32(hProcess);
			return FALSE;
		}

		// Write DLL path
		if (!WriteProcessMemory(
			hProcess,
			remotePath,
			dllPath.c_str(),
			bytes,
			nullptr))
		{
			VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
			CloseHandle32(hProcess);
			return FALSE;
		}

		// Get LoadLibraryW address
		auto loadLibraryW =
			reinterpret_cast<LPTHREAD_START_ROUTINE>(
				GetProcAddress(
					GetModuleHandleW(L"kernel32.dll"),
					"LoadLibraryW"));

		if (!loadLibraryW)
		{
			VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
			CloseHandle32(hProcess);
			return FALSE;
		}

		// Create remote thread
		HANDLE hThread =
			CreateRemoteThread(
				hProcess,
				nullptr,
				0,
				loadLibraryW,
				remotePath,
				0,
				nullptr);

		if (!IsValidHandle(hThread))
		{
			VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
			CloseHandle32(hProcess);
			return FALSE;
		}

		// Wait for completion
		WaitForSingleObject(hThread, INFINITE);

		// Cleanup
		VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
		CloseHandle32(hThread);
		CloseHandle32(hProcess);

		return TRUE;
	}

	bool InstallInlineHook(void* originalFunctionToHook, void* hookFunction, int opcodeLength, HookInfo& outHookInfo)
	{
		if (opcodeLength < 5) return false; // JMP rel32 = 5 bytes

		DWORD oldProtect;
		if (!VirtualProtect(originalFunctionToHook, opcodeLength, PAGE_EXECUTE_READWRITE, &oldProtect))
			return false;

		// NOP the region for safety in case we overwrite more than 5 bytes
		memset(originalFunctionToHook, 0x90, opcodeLength);

		// Calculate relative offset for JMP rel32 (target - source - 5), -5 OR - sizeof(opcodeLength)?
		DWORD relativeAddress = (DWORD)hookFunction - (DWORD)originalFunctionToHook - 5;

		// Write JMP instruction
		*(BYTE*)originalFunctionToHook = 0xE9;
		*(DWORD*)((DWORD)originalFunctionToHook + 1) = relativeAddress;

		// Restore memory protection
		DWORD temp;
		VirtualProtect(originalFunctionToHook, opcodeLength, oldProtect, &temp);

		// Fill out hook information
		outHookInfo.originalFunc = originalFunctionToHook;
		outHookInfo.hookFunc = hookFunction;
		outHookInfo.returnAddress = (void*)((DWORD)originalFunctionToHook + opcodeLength);
		outHookInfo.overwrittenBytes = opcodeLength;

		return true;
	}
}