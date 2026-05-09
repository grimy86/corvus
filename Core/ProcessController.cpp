#include "ProcessController.h"
#undef NTSTATUS // Undefine the WindowsProvider32.h definition
#include <ntdef.h> // NTSTATUS codes

#ifndef MAX_MODULES
#define MAX_MODULES 128ul
#endif // !MAX_MODULES

#ifndef MAX_THREADS
#define MAX_THREADS 128ul
#endif // !MAX_THREADS

#ifndef MAX_HANDLES
#define MAX_HANDLES 128ul
#endif // !MAX_HANDLES

namespace Muninn::Controller
{
	ProcessController::ProcessController(
		const DWORD processId) noexcept
	{
		if (!SetProcessId(processId))
			m_state = ProcessControllerState::ConstructorError;
		else
			m_state = ProcessControllerState::Constructed;
	}

	ProcessController::ProcessController(
		const DWORD processId,
		const ACCESS_MASK accessMask) noexcept
	{
		if (!SetProcessId(processId))
			m_state = ProcessControllerState::ConstructorError;

		// A valid processId is required to be set before setting the process handle
		if (!SetProcessHandle(accessMask))
			m_state = ProcessControllerState::ConstructorError;
		else
			m_state = ProcessControllerState::Constructed;
	}

	bool ProcessController::Dispose() noexcept
	{
		if (!DAL_IsValidHandle(m_process.processHandle))
		{
			m_state = ProcessControllerState::Disposed;
			return true;
		}

		if (!NT_SUCCESS(DAL_Nt_CloseHandle(
			m_process.processHandle)))
		{
			m_state = ProcessControllerState::DisposeError;
			return false;
		}

		m_process.processHandle = nullptr;
		m_state = ProcessControllerState::Disposed;
		return true;
	}

	bool ProcessController::PopulateProcessEntryBasicInfo() noexcept
	{
		PROCESSENTRY32W processEntry32{};

		NTSTATUS status{ DAL_Win32_GetProcessInformation(
			m_process.processEntry.processId,
			&processEntry32) };
		if (!NT_SUCCESS(status))
			return false;

		m_process.processEntry.processName =
			processEntry32.szExeFile;

		return true;
	}

	bool ProcessController::PopulateProcessEntryImagePaths() noexcept
	{
		DWORD copiedLength{ 0ul };
		m_process.processEntry.userFullProcessImageName.resize(MAX_PATH);
		NTSTATUS status{ DAL_Nt_GetWin32ImageFileName(
			m_process.processHandle,
			m_process.processEntry.userFullProcessImageName.data(),
			MAX_PATH,
			&copiedLength) };
		if (!NT_SUCCESS(status))
			return false;

		// Trim back
		m_process.processEntry.userFullProcessImageName.resize(copiedLength);

		m_process.processEntry.NativeImageFileName.resize(MAX_PATH);
		copiedLength = 0ul;
		status = DAL_Nt_GetImageFileName(
			m_process.processHandle,
			m_process.processEntry.NativeImageFileName.data(),
			MAX_PATH,
			&copiedLength);
		if (!NT_SUCCESS(status))
			return false;

		// Trim back
		m_process.processEntry.NativeImageFileName.resize(copiedLength);

		return true;
	}

	bool ProcessController::PopulateProcessEntryExtendedInfo() noexcept
	{
		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};

		NTSTATUS status{ DAL_Nt_GetPebBaseAddressAndProcessInfo(
			m_process.processHandle,
			&m_process.processEntry.pebBaseAddress,
			&processInfo) };
		if (!NT_SUCCESS(status))
			return false;

		status = DAL_Nt_GetModuleBaseAddressFromPebBaseAddress(
			m_process.processHandle,
			&m_process.processEntry.pebBaseAddress,
			&m_process.processEntry.moduleBaseAddress);
		if (!NT_SUCCESS(status))
			return false;

		m_process.processEntry.parentProcessId =
			static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(
					processInfo.InheritedFromUniqueProcessId));

		m_process.processEntry.isProtectedProcess =
			processInfo.IsProtectedProcess;
		m_process.processEntry.isWow64Process =
			processInfo.IsWow64Process;
		m_process.processEntry.isBackgroundProcess =
			processInfo.IsBackground;
		m_process.processEntry.isSecureProcess =
			processInfo.IsSecureProcess;
		m_process.processEntry.isSubsystemProcess =
			processInfo.IsSubsystemProcess;

		return true;
	}

	bool ProcessController::PopulateProcessEntryWindowInfo() noexcept
	{
		NTSTATUS status{ DAL_Win32_GetWindowVisibility(
			m_process.processEntry.processId,
			&m_process.processEntry.hasVisibleWindow) };
		if (!NT_SUCCESS(status))
			return false;

		return true;
	}

	bool ProcessController::PopulateProcessEntryArchitecture() noexcept
	{
		USHORT processMachine{};
		USHORT nativeMachine{};
		BOOL isWow64{};

		NTSTATUS status{ DAL_Win32_GetProcessArchitecture(
			m_process.processHandle,
			&processMachine,
			&nativeMachine,
			&isWow64) };
		if (!NT_SUCCESS(status))
			return false;

		if (isWow64)
			m_process.processEntry.architectureType = 
			Muninn::Model::ArchitectureType::x86;
		else if (processMachine == IMAGE_FILE_MACHINE_AMD64)
			m_process.processEntry.architectureType = 
			Muninn::Model::ArchitectureType::x64;
		else
			m_process.processEntry.architectureType = 
			Muninn::Model::ArchitectureType::Unknown;

		return true;
	}

	ProcessController::~ProcessController() noexcept
	{
		if (!Dispose())
		{
			m_state = ProcessControllerState::DestructorError;
		}

		m_state = ProcessControllerState::Destructed;
	}

	bool ProcessController::SetProcessId(const DWORD processId) noexcept
	{
		if (!DAL_IsValidProcessId(processId))
			return false;

		m_process.processEntry.processId = processId;
	}

	bool ProcessController::SetProcessHandle(const ACCESS_MASK accessMask) noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;

		if (!DAL_IsValidHandle(m_process.processHandle))
		{
			NTSTATUS status{ DAL_Nt_OpenProcessHandle(
			m_process.processEntry.processId,
			accessMask,
			&m_process.processHandle) };

			if (!NT_SUCCESS(status) ||
				!DAL_IsValidHandle(m_process.processHandle))
				return false;
		}

		return true;
	}

	bool ProcessController::SetInjectorDllPathA(const char* dllPath) noexcept
	{
		if (dllPath == nullptr)
			return false;

		m_injector.DllPathA = dllPath;
		return true;
	}

	bool ProcessController::SetInjectorDllPathW(const wchar_t* dllPath) noexcept
	{
		if (dllPath == nullptr)
			return false;

		m_injector.DllPathW = dllPath;
		return true;
	}

	bool ProcessController::PopulateProcessEntry() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;
		
		// If-statements for debugging purposes instead of a compound statement.
		if (!PopulateProcessEntryBasicInfo())
			return false;
		if (!PopulateProcessEntryImagePaths())
			return false;
		if (!PopulateProcessEntryExtendedInfo())
			return false;
		if (!PopulateProcessEntryWindowInfo())
			return false;
		if (!PopulateProcessEntryArchitecture())
			return false;

		return true;
	}

	// To be reviewed
	bool ProcessController::PopulateProcessModuleList() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;
		if (m_process.processEntry.pebBaseAddress == NULL)
			return false;

		PEB* pPeb{ reinterpret_cast<PEB*>(
				m_process.processEntry.pebBaseAddress) };

		std::vector<LDR_DATA_TABLE_ENTRY> moduleList{ MAX_MODULES };

		DWORD copiedLength{0ul};

		NTSTATUS status{ DAL_Nt_GetProcessModules(
			m_process.processHandle,
			pPeb,
			moduleList.data(),
			MAX_MODULES,
			&copiedLength) };
		if (!NT_SUCCESS(status))
			return false;

		moduleList.resize(copiedLength);

		wchar_t buffer[MAX_PATH]{};

		for (DWORD i{0ul}; i < moduleList.size(); ++i)
		{
			Model::ModuleModel moduleEntry{};

			status = DAL_Nt_GetRemoteUnicodeString(
				m_process.processHandle,
				&moduleList[i].BaseDllName,
				buffer,
				MAX_PATH,
				&copiedLength);
			if (!NT_SUCCESS(status))
				continue;

			moduleEntry.moduleName = buffer;

			status = DAL_Nt_GetRemoteUnicodeString(
				m_process.processHandle,
				&moduleList[i].FullDllName,
				buffer,
				MAX_PATH,
				&copiedLength);
			if (!NT_SUCCESS(status))
				continue;

			moduleEntry.modulePath = buffer;

			moduleEntry.moduleLoadAddress =
				reinterpret_cast<uintptr_t>(
					moduleList[i].DllBase);

			moduleEntry.moduleEntryPoint =
				reinterpret_cast<uintptr_t>(
					moduleList[i].EntryPoint);

			moduleEntry.moduleBaseAddress =
				reinterpret_cast<uintptr_t>(
					moduleList[i].DllBase);

			moduleEntry.parentDllBaseAddress =
				reinterpret_cast<uintptr_t>(
					moduleList[i].ParentDllBase);

			moduleEntry.kernelModuleFlags =
				moduleList[i].Flags;

			moduleEntry.moduleImageSize =
				moduleList[i].SizeOfImage;

			moduleEntry.processId =
				m_process.processEntry.processId;

			moduleEntry.tlsIndex =
				moduleList[i].TlsIndex;

			m_process.moduleList.push_back(moduleEntry);
		}
		return true;
	}

	// To be reviewed
	bool ProcessController::PopulateProcessThreadList() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;

		std::vector<SYSTEM_THREAD_INFORMATION> threadList{ MAX_THREADS };
		DWORD copiedLength{ 0ul };

		NTSTATUS status{ DAL_Nt_GetProcessThreads(
			m_process.processHandle,
			m_process.processEntry.processId,
			threadList.data(),
			sizeof(MAX_THREADS),
			&copiedLength) };
		if (!NT_SUCCESS(status))
			return false;

		for (DWORD i{ 0ul }; i < copiedLength / sizeof(SYSTEM_THREAD_INFORMATION); ++i)
		{
			Model::ThreadModel threadEntry{};

			threadEntry.kernelThreadStartAddress =
				reinterpret_cast<uintptr_t>(
					threadList[i].StartAddress);

			threadEntry.threadId =
				static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(
					threadList[i].ClientId.UniqueThread));

			threadEntry.threadOwnerProcessId =
				static_cast<DWORD>(
					reinterpret_cast<uintptr_t>(
						threadList[i].ClientId.UniqueProcess));

			threadEntry.nativeThreadBasePriority =
				threadList[i].BasePriority;

			m_process.threadList.push_back(threadEntry);
		}
		return true;
	}

	// To be reviewed
	bool ProcessController::PopulateProcessHandleList() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;

		std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handleList{ MAX_HANDLES };
		DWORD copiedLength{ 0ul };
		NTSTATUS status{ DAL_Nt_GetProcessHandles(
			m_process.processHandle,
			m_process.processEntry.processId,
			handleList.data(),
			MAX_HANDLES,
			&copiedLength) };
		if (!NT_SUCCESS(status))
			return false;

		for (DWORD i{ 0ul }; i < copiedLength / sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO); ++i)
		{
			Model::HandleModel handleEntry{};
			handleEntry.objectName = std::wstring(
				reinterpret_cast<WCHAR*>(handleList[i].Object),
				MAX_PATH);

			handleEntry.handleValue =
				reinterpret_cast<HANDLE>(
					handleList[i].HandleValue);

			handleEntry.grantedAccess =
				handleList[i].GrantedAccess;

			handleEntry.userTargetProcessId =
				static_cast<DWORD>(
						handleList[i].UniqueProcessId);

			m_process.handleList.push_back(handleEntry);
		}
		return true;
	}

	// To be reviewed
	bool ProcessController::SimpleDLLInjectA() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;
		if(m_injector.DllPathA == nullptr)
			return false;

		NTSTATUS status{ DAL_Win32_RemoteLoadLibraryA(
			m_process.processHandle,
			m_injector.DllPathA,
			&m_injector.ModuleHandle) };

		if (!NT_SUCCESS(status))
		{
			m_injector.IsInjected = false;
			return false;
		}

		m_injector.IsInjected = true;
		return true;
	}

	// To be reviewed
	bool ProcessController::SimpleDLLInjectW() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;
		if (m_injector.DllPathW == nullptr)
			return false;

		NTSTATUS status{ DAL_Win32_RemoteLoadLibraryW32(
			m_process.processHandle,
			m_injector.DllPathW,
			&m_injector.ModuleHandle) };

		if (!NT_SUCCESS(status))
		{
			m_injector.IsInjected = false;
			return false;
		}

		m_injector.IsInjected = true;
		return true;
	}

	DWORD ProcessController::FindProcessId(
		const WCHAR* processName,
		bool& isRunning) noexcept
	{
		DWORD processId{ 0ul };
		BOOL isRunningBuffer{ FALSE };

		NTSTATUS status{ DAL_Win32_GetProcessId(
			processName,
			&processId,
			&isRunningBuffer) };

		isRunning = 
			(isRunningBuffer == TRUE);

		if (!NT_SUCCESS(status))
			return 0ul;
		
		return processId;
	}
}