#include "MemoryService.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include "WindowsProvider32.h"

#ifndef SUSPEND_THREAD_ERROR
#define SUSPEND_THREAD_ERROR -1
#endif // !SUSPEND_THREAD_ERROR

#ifndef RESUME_THREAD_ERROR
#define RESUME_THREAD_ERROR -1
#endif // !RESUME_THREAD_ERROR

#ifndef PREALLOC_HANDLES
#define PREALLOC_HANDLES 1000
#endif // !PREALLOC_HANDLES

#ifndef MAX_PATH_LONG
#define MAX_PATH_LONG 32768
#endif // !MAX_PATH_LONG

namespace Muninn::Data
{
#pragma region WRITE
	HANDLE OpenProcessHandle32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	BOOL CloseHandle32(const HANDLE handle)
	{
		return CloseHandle(handle);
	}

	HANDLE OpenTokenHandle32(const HANDLE processHandle, const ACCESS_MASK accessMask)
	{
		if (!IsValidHandle(processHandle)) return {};

		HANDLE tokenHandle{};
		LUID luid{};
		BOOL status{ OpenProcessToken(
			processHandle,
			accessMask,
			&tokenHandle) };
		if (!status) return {};
		else return tokenHandle;
	}

	BOOL SetSeDebugPrivilege32()
	{
		HANDLE tokenHandle{
			OpenTokenHandle32(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY) };
		if (!IsValidHandle(tokenHandle)) return FALSE;

		LUID luid{};
		BOOL status{
			LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) };
		if (!status)
		{
			CloseHandle32(tokenHandle);
			return FALSE;
		}

		TOKEN_PRIVILEGES privileges{};
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		status = AdjustTokenPrivileges(
			tokenHandle,
			FALSE,
			&privileges,
			sizeof(TOKEN_PRIVILEGES),
			nullptr,
			nullptr);
		if (!status) return FALSE;
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			CloseHandle32(tokenHandle);
			return FALSE;
		}

		CloseHandle32(tokenHandle);
		return TRUE;
	}

	BOOL SetSeDebugPrivilege32(const HANDLE tokenHandle)
	{
		// required: TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
		if (!IsValidHandle(tokenHandle)) return FALSE;

		LUID luid{};
		BOOL status{
			LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid) };
		if (!status) return FALSE;

		TOKEN_PRIVILEGES privileges{};
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Luid = luid;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		status = AdjustTokenPrivileges(
			tokenHandle,
			FALSE,
			&privileges,
			sizeof(TOKEN_PRIVILEGES),
			nullptr,
			nullptr);
		if (!status) return FALSE;
		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
			return FALSE;

		return TRUE;
	}

	BOOL SetThreadPriority32(const DWORD priorityClass)
	{
		return SetPriorityClass(GetCurrentProcess(), priorityClass);
	}

	BOOL SetThreadSuspended32(const DWORD threadId)
	{
		HANDLE threadHandle{
			OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!threadHandle) return FALSE;

		DWORD suspendCount{ SuspendThread(threadHandle) };
		if (suspendCount == SUSPEND_THREAD_ERROR)
			return FALSE;

		CloseHandle32(threadHandle);
		return TRUE;
	}

	BOOL SetThreadResumed32(const DWORD threadId)
	{
		HANDLE threadHandle{
			OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!threadHandle) return FALSE;

		DWORD suspendCount{ ResumeThread(threadHandle) };
		if (suspendCount == RESUME_THREAD_ERROR)
			return FALSE;

		CloseHandle32(threadHandle);
		return TRUE;
	}
#pragma endregion

#pragma region READ
	int GetThreadPriority32(HANDLE threadHandle)
	{
		return GetThreadPriority(threadHandle);
	}

	DWORD GetTokenInfoBufferSize32(
		const HANDLE tokenHandle,
		const _TOKEN_INFORMATION_CLASS infoClass)
	{
		DWORD bufferSize{};
		if (!GetTokenInformation(
			tokenHandle,
			infoClass,
			nullptr, 0, &bufferSize))
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				return bufferSize;
			else return 0;
		}
		return bufferSize;
	}

	BOOL GetSeDebugPrivilege32(const HANDLE tokenHandle)
	{
		if (!IsValidHandle(tokenHandle)) return FALSE;

		DWORD bufferSize{
			GetTokenInfoBufferSize32(tokenHandle, TokenPrivileges) };
		if (!bufferSize) return FALSE;

		std::vector<BYTE> buffer(bufferSize);
		if (!GetTokenInformation(
			tokenHandle,
			TokenPrivileges,
			buffer.data(),
			bufferSize,
			&bufferSize))
			return FALSE;

		PTOKEN_PRIVILEGES pTokenPrivileges{
			reinterpret_cast<PTOKEN_PRIVILEGES>(buffer.data()) };

		LUID debugLuid{};
		if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugLuid))
			return FALSE;

		for (DWORD i{ 0 }; i < pTokenPrivileges->PrivilegeCount; ++i)
		{
			const LUID_AND_ATTRIBUTES& laa{ pTokenPrivileges->Privileges[i] };
			if (laa.Luid.LowPart == debugLuid.LowPart &&
				laa.Luid.HighPart == debugLuid.HighPart)
				return (laa.Attributes & SE_PRIVILEGE_ENABLED) != 0;
		}
		return FALSE;
	}

	PROCESSENTRY32W GetProcessInformation32(const DWORD processId)
	{
		if (!IsValidProcessId(processId)) return {};

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (!IsValidHandle(snapshotHandle)) return {};

		PROCESSENTRY32W processEntry{};
		processEntry.dwSize = sizeof(PROCESSENTRY32W);

		if (!Process32FirstW(snapshotHandle, &processEntry))
		{
			CloseHandle32(snapshotHandle);
			return {};
		}

		do
		{
			if (processEntry.th32ProcessID == processId)
			{
				CloseHandle32(snapshotHandle);
				return processEntry;
			}
		} while (Process32NextW(snapshotHandle, &processEntry));

		CloseHandle32(snapshotHandle);
		return {};
	}

	BOOL GetProcessInformationObject32(
		const DWORD processId,
		Muninn::Object::ProcessEntry& processEntry)
	{
		if (!IsValidProcessId(processId)) return FALSE;

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
		if (!IsValidHandle(snapshotHandle)) return FALSE;

		PROCESSENTRY32W processEntry32W{};
		processEntry32W.dwSize = sizeof(PROCESSENTRY32W);
		if (!Process32FirstW(snapshotHandle, &processEntry32W))
		{
			CloseHandle32(snapshotHandle);
			return FALSE;
		}

		do
		{
			if (processEntry32W.th32ProcessID != processId) continue;
			processEntry.processName = processEntry32W.szExeFile;
			processEntry.parentProcessId = processEntry32W.th32ParentProcessID;
			break;

		} while (Process32NextW(snapshotHandle, &processEntry32W));

		CloseHandle32(snapshotHandle);
		return TRUE;
	}

	std::wstring GetImageFileName32(const HANDLE hProcess)
	{
		std::wstring imageFileNameBuffer(MAX_PATH_LONG, L'\0');
		DWORD bufferSize{
			static_cast<DWORD>(imageFileNameBuffer.size()) };

		if (!QueryFullProcessImageNameW(
			hProcess,
			0,
			imageFileNameBuffer.data(),
			&bufferSize))
			return L"";

		// Resize string to the actual path length
		imageFileNameBuffer.resize(bufferSize);
		return imageFileNameBuffer;
	}

	uintptr_t GetModuleBaseAddress32(const DWORD processId, const std::wstring& processName)
	{
		if (!IsValidProcessId(processId)) return 0;

		MODULEENTRY32W mEntry{};
		mEntry.dwSize = sizeof(MODULEENTRY32W);
		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		if (!IsValidHandle(snapshotHandle)) return 0;

		if (!Module32FirstW(snapshotHandle, &mEntry))
		{
			CloseHandle32(snapshotHandle);
			return 0;
		}

		do
		{
			if (_wcsicmp(mEntry.szModule, processName.c_str()) == 0)
			{
				CloseHandle32(snapshotHandle);
				return reinterpret_cast<uintptr_t>(mEntry.modBaseAddr);
			}
		} while (Module32Next(snapshotHandle, &mEntry));

		CloseHandle32(snapshotHandle);
		return 0;
	}

	BOOL GetWindowVisibility32(const DWORD processId)
	{
		for (HWND hwnd{ GetTopWindow(nullptr) }; hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD windowThreadProcessId{};
			GetWindowThreadProcessId(hwnd, &windowThreadProcessId);

			if (windowThreadProcessId == processId && IsWindowVisible(hwnd))
				return TRUE;
		}
		return FALSE;
	}

	BOOL GetProcessArchitecture32(
		const HANDLE processHandle,
		Muninn::Object::ArchitectureType& architectureType,
		BOOL& isWow64)
	{
		if (!IsValidHandle(processHandle)) return FALSE;

		// processMachine is the type of WoW process
		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		// nativeMachine is the native architecture of host system
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		if (!IsWow64Process2(processHandle, &processMachine, &nativeMachine))
		{
			isWow64 = FALSE;
			architectureType = Muninn::Object::ArchitectureType::Unknown;
			return FALSE;
		}

		// emulation check
		isWow64 = (processMachine != IMAGE_FILE_MACHINE_UNKNOWN);
		const USHORT machine{ isWow64 ? processMachine : nativeMachine };
		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			architectureType = Muninn::Object::ArchitectureType::Unknown;
			break;
		case IMAGE_FILE_MACHINE_I386:
			architectureType = Muninn::Object::ArchitectureType::x86;
			break;
		case IMAGE_FILE_MACHINE_AMD64:
			architectureType = Muninn::Object::ArchitectureType::x64;
			break;
		default:
			architectureType = Muninn::Object::ArchitectureType::Unknown;
			break;
		}

		return TRUE;
	}

	std::vector<std::pair<MODULEENTRY32W, MODULEINFO>> GetProcessModules32(
		const HANDLE processHandle,
		const DWORD processId)
	{
		if (!IsValidHandle(processHandle)) return {};
		if (!IsValidProcessId(processId)) return {};

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		if (!IsValidHandle(snapshotHandle)) return {};

		MODULEENTRY32W moduleEntry32W{};
		moduleEntry32W.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32FirstW(snapshotHandle, &moduleEntry32W))
		{
			CloseHandle32(snapshotHandle);
			return {};
		}

		std::vector<std::pair<MODULEENTRY32W, MODULEINFO>> modules;
		do
		{
			MODULEINFO moduleInfoBuffer{};
			if (!K32GetModuleInformation(
				processHandle,
				reinterpret_cast<HMODULE>(moduleEntry32W.modBaseAddr),
				&moduleInfoBuffer,
				sizeof(moduleInfoBuffer)))
				continue;
			modules.emplace_back(moduleEntry32W, moduleInfoBuffer);

		} while (Module32NextW(snapshotHandle, &moduleEntry32W));
		CloseHandle32(snapshotHandle);
		return modules;
	}

	BOOL GetProcessModuleObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::ModuleEntry>& modules)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		if (!IsValidHandle(snapshotHandle)) return FALSE;

		MODULEENTRY32W moduleEntry32W{};
		moduleEntry32W.dwSize = sizeof(MODULEENTRY32W);
		if (!Module32FirstW(snapshotHandle, &moduleEntry32W))
		{
			CloseHandle32(snapshotHandle);
			return FALSE;
		}

		do
		{
			MODULEINFO moduleInfoBuffer{};
			if (!K32GetModuleInformation(
				processHandle,
				reinterpret_cast<HMODULE>(moduleEntry32W.modBaseAddr),
				&moduleInfoBuffer,
				sizeof(moduleInfoBuffer)))
				continue;

			Muninn::Object::ModuleEntry moduleEntry{};
			moduleEntry.moduleName = moduleEntry32W.szModule;
			moduleEntry.modulePath = moduleEntry32W.szExePath;
			moduleEntry.moduleLoadAddress =
				reinterpret_cast<uintptr_t>(moduleInfoBuffer.lpBaseOfDll);
			moduleEntry.moduleEntryPoint =
				reinterpret_cast<uintptr_t>(moduleInfoBuffer.EntryPoint);
			moduleEntry.moduleBaseAddress =
				reinterpret_cast<uintptr_t>(moduleEntry32W.modBaseAddr);
			moduleEntry.moduleImageSize = moduleEntry32W.modBaseSize;
			moduleEntry.processId = moduleEntry32W.th32ProcessID;
			modules.push_back(moduleEntry);

		} while (Module32NextW(snapshotHandle, &moduleEntry32W));
		CloseHandle32(snapshotHandle);
		return TRUE;
	}

	std::vector<THREADENTRY32> GetProcessThreads32(
		const HANDLE processHandle,
		const DWORD processId)
	{
		if (!IsValidHandle(processHandle)) return {};
		if (!IsValidProcessId(processId)) return {};

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId) };
		if (!IsValidHandle(snapshotHandle)) return {};

		THREADENTRY32 threadEntry32{};
		threadEntry32.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(snapshotHandle, &threadEntry32))
		{
			CloseHandle32(snapshotHandle);
			return {};
		}

		std::vector<THREADENTRY32> threads{};
		do
		{
			if (threadEntry32.th32OwnerProcessID != processId) continue;
			threads.push_back(threadEntry32);

		} while (Thread32Next(snapshotHandle, &threadEntry32));
		CloseHandle32(snapshotHandle);
		return threads;
	}

	BOOL GetProcessThreadObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::ThreadEntry>& threads)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		HANDLE snapshotHandle{
			CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId) };
		if (!IsValidHandle(snapshotHandle)) return FALSE;

		THREADENTRY32 threadEntry32{};
		threadEntry32.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(snapshotHandle, &threadEntry32))
		{
			CloseHandle32(snapshotHandle);
			return FALSE;
		}

		do
		{
			if (threadEntry32.th32OwnerProcessID != processId) continue;

			Muninn::Object::ThreadEntry threadEntry{};
			threadEntry.nativeThreadBasePriority =
				static_cast<KPRIORITY>(threadEntry32.tpBasePri);
			threadEntry.threadId = threadEntry32.th32ThreadID;
			threadEntry.threadOwnerProcessId = threadEntry32.th32OwnerProcessID;
			threads.push_back(threadEntry);

		} while (Thread32Next(snapshotHandle, &threadEntry32));
		CloseHandle32(snapshotHandle);
		return TRUE;
	}

	std::vector<PSS_HANDLE_ENTRY> GetProcessHandles32(
		const HANDLE processHandle,
		const DWORD processId)
	{
		if (!IsValidHandle(processHandle)) return {};
		if (!IsValidProcessId(processId)) return {};

		HPSS pssSnapshotHandle{};
		if (PssCaptureSnapshot(
			processHandle,
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE,
			0,
			&pssSnapshotHandle)
			!= ERROR_SUCCESS)
			return {};

		HPSSWALK walkMarkerHandle{};
		if (PssWalkMarkerCreate(nullptr, &walkMarkerHandle) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
			return {};
		}

		std::vector<PSS_HANDLE_ENTRY> handles{};
		handles.reserve(PREALLOC_HANDLES);
		while (true)
		{
			PSS_HANDLE_ENTRY pssHandleEntry{};
			DWORD walkStatus{ PssWalkSnapshot(
				pssSnapshotHandle,
				PSS_WALK_HANDLES,
				walkMarkerHandle,
				&pssHandleEntry,
				sizeof(pssHandleEntry)) };

			if (walkStatus == ERROR_NO_MORE_ITEMS) break;
			if (walkStatus != ERROR_SUCCESS) break;

			handles.push_back(pssHandleEntry);
		}

		PssWalkMarkerFree(walkMarkerHandle);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
		return handles;
	}

	BOOL GetProcessHandleObjects32(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Muninn::Object::HandleEntry>& handles)
	{
		if (!IsValidHandle(processHandle)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		HPSS pssSnapshotHandle{};
		if (PssCaptureSnapshot(
			processHandle,
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE,
			0,
			&pssSnapshotHandle)
			!= ERROR_SUCCESS)
			return FALSE;

		HPSSWALK walkMarkerHandle{};
		if (PssWalkMarkerCreate(nullptr, &walkMarkerHandle) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
			return FALSE;
		}

		while (true)
		{
			PSS_HANDLE_ENTRY pssHandleEntry{};
			DWORD walkStatus{ PssWalkSnapshot(
				pssSnapshotHandle,
				PSS_WALK_HANDLES,
				walkMarkerHandle,
				&pssHandleEntry,
				sizeof(pssHandleEntry)) };

			if (walkStatus == ERROR_NO_MORE_ITEMS) break;
			if (walkStatus != ERROR_SUCCESS) break;

			Muninn::Object::HandleEntry handleEntry{};
			handleEntry.typeName
				= pssHandleEntry.TypeName ? pssHandleEntry.TypeName : L"";
			handleEntry.objectName
				= pssHandleEntry.ObjectName ? pssHandleEntry.ObjectName : L"";
			handleEntry.handleValue = pssHandleEntry.Handle;
			handleEntry.grantedAccess = pssHandleEntry.GrantedAccess;

			switch (pssHandleEntry.ObjectType)
			{
			case PSS_OBJECT_TYPE_PROCESS:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Process;
				handleEntry.userTargetProcessId
					= pssHandleEntry.TypeSpecificInformation.Process.ProcessId;
				break;
			case PSS_OBJECT_TYPE_THREAD:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Thread;
				handleEntry.userTargetProcessId
					= pssHandleEntry.TypeSpecificInformation.Thread.ProcessId;
				break;
			case PSS_OBJECT_TYPE_MUTANT:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Mutant;
				handleEntry.userTargetProcessId
					= pssHandleEntry.TypeSpecificInformation.Mutant.OwnerProcessId;
				break;
			case PSS_OBJECT_TYPE_EVENT:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Event;
				// PSS_OBJECT_TYPE_EVENT, doesn't own a processId
				break;
			case PSS_OBJECT_TYPE_SECTION:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Section;
				// PSS_OBJECT_TYPE_SECTION, doesn't own a processId
				break;
			case PSS_OBJECT_TYPE_SEMAPHORE:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Semaphore;
				// PSS_OBJECT_TYPE_SEMAPHORE, doesn't own a processId
				break;
			default:
				handleEntry.userHandleObjectType
					= Muninn::Object::UserHandleObjectType::Unknown;
				handleEntry.userTargetProcessId = 0;
				break;
			}

			handles.push_back(handleEntry);
		}

		PssWalkMarkerFree(walkMarkerHandle);
		PssFreeSnapshot(GetCurrentProcess(), pssSnapshotHandle);
		return TRUE;
	}
#pragma endregion
}