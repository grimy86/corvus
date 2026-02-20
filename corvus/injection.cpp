#include "injection.hpp"

namespace corvus::injection
{
	BOOL Inject(const std::wstring& dllPath, const corvus::process::Win32Backend& proc)
	{
		/*
		// Guards
		if (dllPath.empty())
			return FALSE;

		const DWORD pid = proc.GetProcessId();
		if (!corvus::process::WindowsBackend::IsValidProcessId(pid))
			return FALSE;

		// Open process
		HANDLE hProcess =
			corvus::process::WindowsBackend::OpenProcessHandle32(
				pid,
				PROCESS_CREATE_THREAD |
				PROCESS_QUERY_INFORMATION |
				PROCESS_VM_OPERATION |
				PROCESS_VM_WRITE |
				PROCESS_VM_READ
			);

		if (!corvus::process::WindowsBackend::IsValidHandle(hProcess))
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
			CloseHandle(hProcess);
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
			CloseHandle(hProcess);
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
			CloseHandle(hProcess);
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

		if (!corvus::process::WindowsBackend::IsValidHandle(hThread))
		{
			VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
			CloseHandle(hProcess);
			return FALSE;
		}

		// Wait for completion
		WaitForSingleObject(hThread, INFINITE);

		// Cleanup
		VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
		CloseHandle(hThread);
		CloseHandle(hProcess);

		return TRUE;
		*/
	}
}