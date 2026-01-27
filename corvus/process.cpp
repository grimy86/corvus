#include "process.hpp"
#include <TlHelp32.h>
#include <Psapi.h>
#include <ProcessSnapshot.h>
#pragma comment(lib, "ntdll.lib")

namespace corvus::process
{
	const std::wstring& WindowsProcessBase::GetName() const noexcept { return m_name; }
	const std::wstring& WindowsProcessBase::GetImageFilePath() const noexcept { return m_imageFilePath; }
	const std::wstring& WindowsProcessBase::GetPriorityClass() const noexcept { return m_priorityClass; }
	const std::vector<ModuleEntry>& WindowsProcessBase::GetModules() const noexcept { return m_modules; }
	const std::vector<ThreadEntry>& WindowsProcessBase::GetThreads() const noexcept { return m_threads; }
	const std::vector<HandleEntry>& WindowsProcessBase::GetHandles() const noexcept { return m_handles; }
	uintptr_t WindowsProcessBase::GetModuleBaseAddress() const noexcept { return m_moduleBaseAddress; }
	uintptr_t WindowsProcessBase::GetPEBAddress() const noexcept { return m_pebAddress; }
	DWORD WindowsProcessBase::GetProcessId() const noexcept { return m_processId; }
	LONG WindowsProcessBase::GetBasePriority() const noexcept { return m_basePriority; }
	BOOL WindowsProcessBase::IsWow64() const noexcept { return m_isWow64; }
	BOOL WindowsProcessBase::IsProtectedProcess() const noexcept { return m_isProtectedProcess; }
	BOOL WindowsProcessBase::IsBackgroundProcess() const noexcept { return m_isBackgroundProcess; }
	BOOL WindowsProcessBase::IsSecureProcess() const noexcept { return m_isSecureProcess; }
	BOOL WindowsProcessBase::IsSubsystemProcess() const noexcept { return m_isSubsystemProcess; }
	BOOL WindowsProcessBase::HasVisibleWindow() const noexcept { return m_hasVisibleWindow; }
	ArchitectureType WindowsProcessBase::GetArchitectureType() const noexcept { return m_architectureType; }
	const std::string WindowsProcessBase::GetNameUTF8() const noexcept { return ToString(m_name); }
	const std::string WindowsProcessBase::GetImageFilePathUTF8() const noexcept { return ToString(m_imageFilePath); }
	const std::string WindowsProcessBase::GetPriorityClassUTF8() const noexcept { return ToString(m_priorityClass); }
	const std::string WindowsProcessBase::GetArchitectureTypeUTF8() const noexcept { return ToString(m_architectureType); }

	bool WindowsProcessBase::IsValidProcessId(const DWORD processId) noexcept { return processId % 4 == 0; }
	bool WindowsProcessBase::IsValidModuleBaseAddress(const DWORD moduleBaseAddress) noexcept { return moduleBaseAddress != ERROR_INVALID_ADDRESS; }
	bool WindowsProcessBase::IsValidHandle(const HANDLE processHandle) noexcept
	{
		return (processHandle != nullptr &&
			processHandle != reinterpret_cast<HANDLE>(-1) &&
			processHandle != INVALID_HANDLE_VALUE);
	}

	std::string WindowsProcessBase::ToString(const std::wstring& w) noexcept
	{
		if (w.empty())
			return {};

		int size = WideCharToMultiByte(
			CP_UTF8, 0,
			w.data(), (int)w.size(),
			nullptr, 0,
			nullptr, nullptr
		);

		std::string result(size, '\0');

		WideCharToMultiByte(
			CP_UTF8, 0,
			w.data(), (int)w.size(),
			result.data(), size,
			nullptr, nullptr
		);

		return result.c_str();
	}

	const char* WindowsProcessBase::ToString(ArchitectureType arch) noexcept
	{
		switch (arch)
		{
		case ArchitectureType::Native: return "Native";
		case ArchitectureType::x86: return "x86";
		case ArchitectureType::x64: return "x64";
		case ArchitectureType::arm: return "ARM";
		case ArchitectureType::arm64: return "ARM64";
		default: return "Unknown";
		}
	}

	WindowsProcessBase::WindowsProcessBase(const DWORD processId)
		: m_processId(processId)
	{
		if (!IsValidProcessId(processId))
			throw std::invalid_argument("Invalid PID");
	}

	void WindowsProcessWin32::QueryNameW32()
	{
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return;

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Process32FirstW(snapshot, &entry))
		{
			do
			{
				if (entry.th32ProcessID == m_processId)
				{
					m_name = entry.szExeFile;
					break;
				}
			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WindowsProcessWin32::QueryModulesW32()
	{
		HANDLE hSnapshot{ CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			m_processId
		) };

		HANDLE hProcess{ OpenProcessHandleW32(
			m_processId,
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
		) };

		if (hSnapshot == INVALID_HANDLE_VALUE || hProcess == INVALID_HANDLE_VALUE)
			return;

		MODULEINFO moduleInfoBuffer{};
		MODULEENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Module32FirstW(hSnapshot, &entry))
		{
			do
			{
				K32GetModuleInformation(hProcess, reinterpret_cast<HMODULE>(entry.modBaseAddr),
					&moduleInfoBuffer, sizeof(moduleInfoBuffer));

				ModuleEntry module{};
				module.moduleName = entry.szModule;
				module.modulePath = entry.szExePath;
				module.size = entry.dwSize;
				module.baseAddress = reinterpret_cast<uintptr_t>(entry.modBaseAddr);
				module.moduleBaseSize = entry.modBaseSize;
				module.entryPoint = moduleInfoBuffer.EntryPoint;
				module.processId = entry.th32ProcessID;
				module.globalLoadCount = entry.GlblcntUsage;
				module.processLoadCount = entry.ProccntUsage;

				m_modules.push_back(module);
			} while (Module32NextW(hSnapshot, &entry));
		}

		CloseHandle(hSnapshot);
	}

	void WindowsProcessWin32::QueryThreadsW32()
	{
		std::vector<ThreadEntry> threads;

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snapshot == INVALID_HANDLE_VALUE) return;

		THREADENTRY32 entry{};
		entry.dwSize = sizeof(THREADENTRY32);

		if (Thread32First(snapshot, &entry))
		{
			do
			{
				if (entry.th32OwnerProcessID != m_processId)
					continue;

				ThreadEntry thread{};
				thread.size = entry.dwSize;
				thread.threadId = entry.th32ThreadID;
				thread.ownerProcessId = entry.th32OwnerProcessID;
				thread.basePriority = entry.tpBasePri;
				thread.deltaPriority = entry.tpDeltaPri;
				thread.flags = entry.dwFlags;
				m_threads.push_back(thread);

			} while (Thread32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
	}

	void WindowsProcessWin32::QueryHandlesW32()
	{
		HANDLE pHandle = OpenProcessHandleW32(m_processId, PROCESS_ALL_ACCESS);
		if (!IsValidHandle(pHandle))
			return;

		const PSS_CAPTURE_FLAGS captureFlags =
			PSS_CAPTURE_HANDLES |
			PSS_CAPTURE_HANDLE_NAME_INFORMATION |
			PSS_CAPTURE_HANDLE_BASIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION |
			PSS_CAPTURE_HANDLE_TRACE;

		HPSS hSnapshot{};
		if (PssCaptureSnapshot(pHandle, captureFlags, 0, &hSnapshot) != ERROR_SUCCESS)
		{
			CloseHandle(pHandle);
			return;
		}

		HPSSWALK hWalkMarker{};
		if (PssWalkMarkerCreate(nullptr, &hWalkMarker) != ERROR_SUCCESS)
		{
			PssFreeSnapshot(GetCurrentProcess(), hSnapshot);
			CloseHandle(pHandle);
			return;
		}

		while (true)
		{
			PSS_HANDLE_ENTRY handleBuffer{};
			const DWORD walkStatus = PssWalkSnapshot(
				hSnapshot,
				PSS_WALK_HANDLES,
				hWalkMarker,
				&handleBuffer,
				sizeof(handleBuffer)
			);

			if (walkStatus == ERROR_NO_MORE_ITEMS || walkStatus != ERROR_SUCCESS)
				break;

			HandleEntry handle{};
			handle.typeName = handleBuffer.TypeName ? handleBuffer.TypeName : L"";
			handle.objectName = handleBuffer.ObjectName ? handleBuffer.ObjectName : L"";
			handle.handle = handleBuffer.Handle;
			handle.flags = handleBuffer.Flags;
			handle.objectType = static_cast<HandleType>(handleBuffer.ObjectType);
			handle.attributes = handleBuffer.Attributes;
			handle.grantedAccess = handleBuffer.GrantedAccess;
			handle.handleCount = handleBuffer.HandleCount;
			m_handles.push_back(handle);
		}

		PssWalkMarkerFree(hWalkMarker);
		PssFreeSnapshot(pHandle, hSnapshot);
		CloseHandle(pHandle);
	}

	void WindowsProcessWin32::QueryArchitectureTypeW32()
	{
		HANDLE hProcess =
			OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION);

		if (!IsValidHandle(hProcess))
		{
			m_architectureType = ArchitectureType::Unknown;
			return;
		}

		USHORT processMachine{ IMAGE_FILE_MACHINE_UNKNOWN };
		USHORT nativeMachine{ IMAGE_FILE_MACHINE_UNKNOWN };

		if (!IsWow64Process2(hProcess, &processMachine, &nativeMachine))
		{
			CloseHandle(hProcess);
			m_architectureType = ArchitectureType::Unknown;
			return;
		}

		CloseHandle(hProcess);

		// If the process is emulated, use the emulated architecture.
		// Otherwise, use the native OS architecture.
		const USHORT machine{
			(processMachine != IMAGE_FILE_MACHINE_UNKNOWN)
			? processMachine
			: nativeMachine };

		switch (machine)
		{
		case IMAGE_FILE_MACHINE_UNKNOWN:
			m_architectureType = ArchitectureType::Unknown;
			break;

		case IMAGE_FILE_MACHINE_I386:
			m_architectureType = ArchitectureType::x86;
			break;

		case IMAGE_FILE_MACHINE_AMD64:
			m_architectureType = ArchitectureType::x64;
			break;

		case IMAGE_FILE_MACHINE_ARM:
			m_architectureType = ArchitectureType::arm;
			break;

		case IMAGE_FILE_MACHINE_ARM64:
			m_architectureType = ArchitectureType::arm64;
			break;

		default:
			m_architectureType = ArchitectureType::Unknown;
			break;
		}
	}

	void WindowsProcessWin32::QueryWow64W32()
	{
		HANDLE hProcess{ OpenProcessHandleW32(m_processId, PROCESS_QUERY_LIMITED_INFORMATION) };

		if (IsValidHandle(hProcess))
		{
			IsWow64Process(hProcess, &m_isWow64);
			CloseHandle(hProcess);
		}
	}

	void WindowsProcessWin32::QueryVisibleWindowW32()
	{
		m_hasVisibleWindow = FALSE;

		for (HWND hwnd = GetTopWindow(nullptr); hwnd; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			DWORD pid = 0;
			GetWindowThreadProcessId(hwnd, &pid);

			if (pid == m_processId && IsWindowVisible(hwnd))
			{
				m_hasVisibleWindow = TRUE;
				return;
			}
		}
	}

	std::vector<WindowsProcessWin32> WindowsProcessWin32::GetProcessListW32()
	{
		std::vector<WindowsProcessWin32> result{};

		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snapshot == INVALID_HANDLE_VALUE)
			return result;

		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);

		if (Process32FirstW(snapshot, &entry))
		{
			do
			{
				if (!entry.th32ProcessID)
					continue;
				WindowsProcessWin32 proc{ entry.th32ProcessID };
				result.push_back(proc);

			} while (Process32NextW(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return result;
	}

	HANDLE WindowsProcessWin32::OpenProcessHandleW32(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return OpenProcess(accessMask, FALSE, processId);
	}

	uintptr_t WindowsProcessWin32::GetModuleBaseAddressW32(const DWORD& processId, const std::wstring& moduleName)
	{
		// Take a snapshot of 32 & 64-bit modules
		HANDLE hSnapShotHandle{ CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId) };
		uintptr_t moduleBaseAddress{};

		if (!IsValidHandle(hSnapShotHandle))
		{
			return moduleBaseAddress;
		}

		MODULEENTRY32 modEntry{};
		modEntry.dwSize = sizeof(MODULEENTRY32);
		if (!Module32First(hSnapShotHandle, &modEntry))
		{
			CloseHandle(hSnapShotHandle);
			return moduleBaseAddress;
		}

		do
		{
			if (!_wcsicmp(modEntry.szModule, moduleName.c_str()))
			{
				CloseHandle(hSnapShotHandle);
				return reinterpret_cast<uintptr_t>(modEntry.modBaseAddr);
			}
		} while (Module32Next(hSnapShotHandle, &modEntry));

		CloseHandle(hSnapShotHandle);
		return moduleBaseAddress;
	}

	BOOL  WindowsProcessWin32::SuspendThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		SuspendThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	BOOL WindowsProcessWin32::ResumeThreadW32(const DWORD threadId)
	{
		HANDLE hThread{ OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId) };
		if (!hThread) return FALSE;
		ResumeThread(hThread);
		CloseHandle(hThread);
		return TRUE;
	}

	void WindowsProcessWin32::PatchExecutionEW32(HANDLE processHandle, DWORD destination, BYTE* value, unsigned int size)
	{
		// Changes the protection on a region of committed pages in the virtual address space of a specified process.
		// https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants

		DWORD oldPageProtection;
		VirtualProtectEx(processHandle, (void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		WriteProcessMemory(processHandle, (void*)destination, value, size, nullptr);
	}

	void WindowsProcessWin32::NopExecutionEW32(HANDLE processHandle, DWORD destination, unsigned int size)
	{
		// Filling an array with x86 NOP instructions (0x90)
		BYTE* noOperationArray = new BYTE[size];
		memset(noOperationArray, 0x90, size);

		PatchExecutionEW32(processHandle, destination, noOperationArray, size);
		delete[] noOperationArray;
	}

	// Find multi-level pointers (external)
	DWORD WindowsProcessWin32::FindDMAAddyEW32(HANDLE processHandle, DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			ReadProcessMemory(processHandle, (void*)addr, &addr, sizeof(addr), nullptr);
			addr += offsets[i];
		}
		return addr;
	}

	//Internal patch function, uses VirtualProtect instead of VirtualProtectEx
	void WindowsProcessWin32::PatchExecutionIW32(DWORD destination, BYTE* value, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memcpy((void*)destination, value, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	//Internal nop function, uses memset instead of WPM
	void  WindowsProcessWin32::NopExecutionIW32(DWORD destination, unsigned int size)
	{
		DWORD oldPageProtection;
		VirtualProtect((void*)destination, size, PAGE_EXECUTE_READWRITE, &oldPageProtection);
		memset((void*)destination, 0x90, size);
		VirtualProtect((void*)destination, size, oldPageProtection, &oldPageProtection);
	}

	// Internal Find multi-level pointers
	DWORD WindowsProcessWin32::FindDMAAddyIW32(DWORD ptr, std::vector<DWORD> offsets)
	{
		DWORD addr{ ptr };
		for (unsigned int i = 0; i < offsets.size(); ++i)
		{
			addr = *(DWORD*)addr;
			addr += offsets[i];
		}
		return addr;
	}

	BOOL WindowsProcessWin32::EnableSeDebugPrivilegeW32()
	{
		HANDLE hProc{ GetCurrentProcess() };
		HANDLE hToken{ nullptr };

		BOOL bToken{ OpenProcessToken(
			hProc,
			TOKEN_ADJUST_PRIVILEGES |
			TOKEN_QUERY,
			&hToken) };

		LUID luid{};
		BOOL bLookupPriv{ LookupPrivilegeValueW(
			nullptr,
			SE_DEBUG_NAME,
			&luid) };

		if (!bToken || !bLookupPriv)
		{
			if (hToken)
				CloseHandle(hToken);

			CloseHandle(hProc);
			return FALSE;
		}

		TOKEN_PRIVILEGES tp{
			tp.PrivilegeCount = 1,
			tp.Privileges[0].Luid = luid,
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		};

		BOOL bAdjustPriv{ AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(tp),
			nullptr,
			nullptr) };

		if (!bAdjustPriv)
		{
			CloseHandle(hToken);
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			CloseHandle(hToken);
			return FALSE;
		}

		CloseHandle(hToken);
		return TRUE;
	}

	BOOL WindowsProcessWin32::EnableSeDebugPrivilegeW32(const DWORD processId)
	{
		HANDLE hProc{ OpenProcessHandleW32(processId, PROCESS_ALL_ACCESS) };
		HANDLE hToken{ nullptr };

		BOOL bToken{ OpenProcessToken(
			hProc,
			TOKEN_ADJUST_PRIVILEGES |
			TOKEN_QUERY,
			&hToken) };

		LUID luid{};
		BOOL bLookupPriv{ LookupPrivilegeValueW(
			nullptr,
			SE_DEBUG_NAME,
			&luid) };

		if (!bToken || !bLookupPriv)
		{
			if (hToken)
				CloseHandle(hToken);

			CloseHandle(hProc);
			return FALSE;
		}

		TOKEN_PRIVILEGES tp{
			tp.PrivilegeCount = 1,
			tp.Privileges[0].Luid = luid,
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
		};

		BOOL bAdjustPriv{ AdjustTokenPrivileges(
			hToken,
			FALSE,
			&tp,
			sizeof(tp),
			nullptr,
			nullptr) };

		if (!bAdjustPriv)
		{
			CloseHandle(hToken);
			return FALSE;
		}

		if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			CloseHandle(hToken);
			return FALSE;
		}

		CloseHandle(hToken);
		return TRUE;
	}

	WindowsProcessWin32::WindowsProcessWin32(const DWORD processId)
		: WindowsProcessBase(processId)
	{
		QueryNameW32();
		QueryModulesW32();
		QueryThreadsW32();
		QueryHandlesW32();
		QueryArchitectureTypeW32();
		QueryWow64W32();
		QueryVisibleWindowW32();
	}

	std::vector<WindowsProcessNt> WindowsProcessNt::GetProcessListNt()
	{
		std::vector<WindowsProcessNt> result;

		// Get required buffer sizes for NtQSI calls
		const DWORD requiredSysProcInfoBufferSize{
			GetQSIBuffferSizeNt(SystemProcessInformation) + 0x1000 };
		const DWORD requiredExtHandleInfoBufferSize{
			GetQSIBuffferSizeNt(SystemExtendedHandleInformation) + 0x1000 };

		BYTE* sysProcInfoBuffer = new BYTE[requiredSysProcInfoBufferSize];
		BYTE* extHandleInfoBuffer = new BYTE[requiredExtHandleInfoBufferSize];

		// Query system process information
		NTSTATUS ntSysStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			sysProcInfoBuffer,
			requiredSysProcInfoBufferSize,
			nullptr) };

		// Query handle information
		NTSTATUS ntHandleStatus{ NtQuerySystemInformation(
			SystemExtendedHandleInformation,
			extHandleInfoBuffer,
			requiredExtHandleInfoBufferSize,
			nullptr) };

		if (!NT_SUCCESS(ntSysStatus))
		{
			delete[] sysProcInfoBuffer;
			delete[] extHandleInfoBuffer;
			return result;
		}

		PSYSTEM_PROCESS_INFORMATION pSys =
			reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(sysProcInfoBuffer);

		PSYSTEM_HANDLE_INFORMATION_EX pHandles =
			reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(extHandleInfoBuffer);

		while (pSys)
		{
			DWORD processId =
				static_cast<DWORD>(reinterpret_cast<uintptr_t>(pSys->UniqueProcessId));

			WindowsProcessNt wProcNt{ processId };

			// Process name
			wProcNt.m_name = (pSys->ImageName.Buffer)
				? pSys->ImageName.Buffer
				: L"Unknown Nt Process Name";

			// Open process
			HANDLE hProcess{ OpenProcessHandleNt(processId, PROCESS_ALL_ACCESS) };

			if (IsValidHandle(hProcess))
			{
				BYTE* pImageFileNameBuffer = new BYTE[200];
				BYTE* pExtendedInfoBuffer = new BYTE[200];

				NTSTATUS ntImageFileNameStatus = NtQueryInformationProcess(
					hProcess,
					ProcessImageFileName,
					pImageFileNameBuffer,
					200,
					nullptr);

				NTSTATUS ntProcExtendedInfoStatus = NtQueryInformationProcess(
					hProcess,
					ProcessBasicInformation,
					pExtendedInfoBuffer,
					200,
					nullptr);

				PROCESS_PRIORITY_CLASS procPriorityClassBuffer{};
				NTSTATUS ntProcPriorityClassStatus = NtQueryInformationProcess(
					hProcess,
					ProcessPriorityClass,
					&procPriorityClassBuffer,
					sizeof(procPriorityClassBuffer),
					nullptr);

				if (NT_SUCCESS(ntImageFileNameStatus) &&
					NT_SUCCESS(ntProcExtendedInfoStatus) &&
					NT_SUCCESS(ntProcPriorityClassStatus))
				{
					PUNICODE_STRING pImageFileName =
						reinterpret_cast<PUNICODE_STRING>(pImageFileNameBuffer);

					PPROCESS_EXTENDED_BASIC_INFORMATION pProcessExtendedInfo =
						reinterpret_cast<PPROCESS_EXTENDED_BASIC_INFORMATION>(pExtendedInfoBuffer);

					wProcNt.m_imageFilePath = pImageFileName->Buffer;

					wProcNt.m_pebAddress =
						reinterpret_cast<uintptr_t>(pProcessExtendedInfo->BasicInfo.PebBaseAddress);

					wProcNt.m_basePriority =
						pProcessExtendedInfo->BasicInfo.BasePriority;

					wProcNt.m_isWow64 =
						pProcessExtendedInfo->u.s.IsWow64Process;

					wProcNt.m_isProtectedProcess =
						pProcessExtendedInfo->u.s.IsProtectedProcess;

					wProcNt.m_isBackgroundProcess =
						pProcessExtendedInfo->u.s.IsBackground;

					wProcNt.m_isSecureProcess =
						pProcessExtendedInfo->u.s.IsSecureProcess;

					wProcNt.m_isSubsystemProcess =
						pProcessExtendedInfo->u.s.IsSubsystemProcess;

					wProcNt.m_priorityClass =
						procPriorityClassBuffer.PriorityClass;
				}

				delete[] pImageFileNameBuffer;
				delete[] pExtendedInfoBuffer;
				NtClose(hProcess);
			}

			// Threads
			for (ULONG i = 0; i < pSys->NumberOfThreads; ++i)
			{
				ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = pSys->Threads[i];

				threadEntry.size = sizeof(SYSTEM_THREAD_INFORMATION);
				threadEntry.threadId =
					static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
				threadEntry.ownerProcessId = processId;
				threadEntry.basePriority = sThreadInfo.BasePriority;
				threadEntry.startAddress = sThreadInfo.StartAddress;
				threadEntry.threadState = sThreadInfo.ThreadState;

				wProcNt.m_threads.push_back(threadEntry);
			}

			// Handle parsing
			if (NT_SUCCESS(ntHandleStatus))
			{
				for (ULONG i = 0; i < pHandles->NumberOfHandles; ++i)
				{
					const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& sHandleInfo =
						pHandles->Handles[i];

					if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) !=
						static_cast<uintptr_t>(processId))
						continue;

					HandleEntry handleEntry{};
					handleEntry.objectName = L"Unknown";
					handleEntry.typeName = L"Unknown";
					handleEntry.handle =
						reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
					handleEntry.objectType = HandleType::Unknown;
					handleEntry.attributes = sHandleInfo.HandleAttributes;
					handleEntry.grantedAccess = sHandleInfo.GrantedAccess;
					handleEntry.handleCount = pHandles->NumberOfHandles;
					handleEntry.objectTypeIndex = sHandleInfo.ObjectTypeIndex;

					wProcNt.m_handles.push_back(handleEntry);
				}
			}

			result.push_back(wProcNt);

			// Advance to next process (ALWAYS)
			if (pSys->NextEntryOffset)
			{
				pSys = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(pSys) + pSys->NextEntryOffset);
			}
			else
			{
				break;
			}
		}

		delete[] sysProcInfoBuffer;
		delete[] extHandleInfoBuffer;
		return result;
	}

	HANDLE WindowsProcessNt::OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask)
	{
		HANDLE pHandle{};
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
		objectAttributes.RootDirectory = nullptr;
		objectAttributes.ObjectName = nullptr;
		objectAttributes.Attributes = 0;
		objectAttributes.SecurityDescriptor = nullptr;
		objectAttributes.SecurityQualityOfService = nullptr;

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(processId);
		clientId.UniqueThread = nullptr;

		NTSTATUS ntStatus{ NtOpenProcess(&pHandle, accessMask, &objectAttributes, &clientId) };
		if (NT_SUCCESS(ntStatus) && IsValidHandle(pHandle))
		{
			return pHandle;
		}
		else return nullptr;
	}

	DWORD WindowsProcessNt::GetQSIBuffferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass)
	{
		DWORD requiredBufferSize{};

		NTSTATUS ntStatus{ NtQuerySystemInformation(
			sInfoClass,
			nullptr,
			0,
			&requiredBufferSize) };

		return requiredBufferSize;
	}

	WindowsProcessNt::WindowsProcessNt(const DWORD processId)
		: WindowsProcessBase(processId)
	{

	}
}