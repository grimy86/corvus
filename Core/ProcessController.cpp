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
#pragma region Constructor, Destructor & Dispose

	ProcessController::ProcessController(
		const DWORD processId) noexcept
	{
		if (!SetProcessId(processId))
			SetState(ControllerState::ConstructorError);
		else
			SetState(ControllerState::Initialized);
	}

	ProcessController::ProcessController(
		const DWORD processId,
		const ACCESS_MASK accessMask) noexcept
	{
		if (!SetProcessId(processId))
			SetState(ControllerState::ConstructorError);

		// A valid processId is required to be set before setting the process handle
		if (!SetProcessHandle(accessMask))
			SetState(ControllerState::ConstructorError);
		else
			SetState(ControllerState::Initialized);
	}

	ProcessController::~ProcessController() noexcept
	{
		if (!Dispose())
		{
			SetState(ControllerState::DestructorError);
		}
	}

	bool ProcessController::Dispose() noexcept
	{
		if (!DAL_IsValidHandle(m_process.processHandle))
		{
			SetState(ControllerState::Disposed);
			return true;
		}

		if (!NT_SUCCESS(DAL_Nt_CloseHandle(
			m_process.processHandle)))
		{
			SetState(ControllerState::DisposeError);
			return false;
		}

		m_process.processHandle = nullptr;
		SetState(ControllerState::Disposed);
		return true;
	}

#pragma endregion

#pragma region Private Methods

	bool ProcessController::QueryBasicInfo() noexcept
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

	bool ProcessController::QueryImagePaths() noexcept
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

	bool ProcessController::QueryExtendedInfo() noexcept
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

	bool ProcessController::QueryWindowInfo() noexcept
	{
		NTSTATUS status{ DAL_Win32_GetWindowVisibility(
			m_process.processEntry.processId,
			&m_process.processEntry.hasVisibleWindow) };
		if (!NT_SUCCESS(status))
			return false;

		return true;
	}

	bool ProcessController::QueryArchitecture() noexcept
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

#pragma endregion

#pragma region Public Getters & Setters

	const Muninn::Model::ProcessModel& ProcessController::GetProcess() const noexcept
	{
		return m_process;
	}

	bool ProcessController::SetProcessId(const DWORD processId) noexcept
	{
		if (!DAL_IsValidProcessId(processId))
			return false;

		m_process.processEntry.processId = processId;
		return true;
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

#pragma endregion

#pragma region Public Methods
	bool ProcessController::RefreshProcessEntry() noexcept
	{
		if (!DAL_IsValidProcessId(m_process.processEntry.processId))
			return false;
		if (!DAL_IsValidHandle(m_process.processHandle))
			return false;
		
		// If-statements for debugging purposes instead of a compound statement.
		if (!QueryBasicInfo())
			return false;
		if (!QueryImagePaths())
			return false;
		if (!QueryExtendedInfo())
			return false;
		if (!QueryWindowInfo())
			return false;
		if (!QueryArchitecture())
			return false;

		return true;
	}

	bool ProcessController::RefreshModuleList() noexcept
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

	bool ProcessController::RefreshThreadList() noexcept
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

	bool ProcessController::RefreshHandleList() noexcept
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

#pragma endregion

#pragma region Static Factory Methods

	ProcessController ProcessController::FromName(
		const WCHAR* const processName,
		bool& isRunning,
		const ACCESS_MASK accessMask = PROCESS_ALL_ACCESS) noexcept
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
			return {}; // Return an empty ProcessController object if the process is not found or an error occurs
		
		return ProcessController{ processId, accessMask };
	}

	ProcessController ProcessController::FromName(
		const std::wstring& processName,
		bool& isRunning,
		const ACCESS_MASK accessMask = PROCESS_ALL_ACCESS) noexcept
	{
		return FromName(processName.c_str(), isRunning, accessMask);
	}

#pragma endregion
}