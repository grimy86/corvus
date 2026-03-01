#include "WindowsProviderNt.h"
#include "MemoryService.h"
#pragma comment(lib, "ntdll.lib")

#ifndef MAX_MODULES
#define MAX_MODULES 1024
#endif // !MAX_MODULES

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif // !PAGE_SIZE

#ifndef NT_CURRENT_PROCESS
#define NT_CURRENT_PROCESS ((HANDLE)(LONG_PTR)-1)
#endif // !NT_CURRENT_PROCESS

namespace Corvus::Data
{
#pragma region WRITE
	HANDLE OpenProcessHandleNt(DWORD processId, ACCESS_MASK accessMask)
	{
		OBJECT_ATTRIBUTES objectAttributes{};
		objectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(processId);
		clientId.UniqueThread = nullptr;

		HANDLE pHandle{ nullptr };
		NTSTATUS status{ NtOpenProcess(&pHandle, accessMask, &objectAttributes, &clientId) };
		if (NT_SUCCESS(status) && IsValidHandle(pHandle)) return pHandle;
		else return nullptr;
	}

	BOOL CloseHandleNt(HANDLE handle)
	{
		return NT_SUCCESS(NtClose(handle));
	}

	HANDLE DuplicateHandleNt(
		HANDLE sourceHandle,
		DWORD processId)
	{
		if (!IsValidHandle(sourceHandle)) return nullptr;
		if (!IsValidProcessId(processId)) return nullptr;

		OBJECT_ATTRIBUTES objectAttributes{};
		InitializeObjectAttributes(
			&objectAttributes,
			nullptr,
			0,
			nullptr,
			nullptr);

		CLIENT_ID clientId{};
		clientId.UniqueProcess = reinterpret_cast<HANDLE>(
			static_cast<ULONG_PTR>(processId));
		clientId.UniqueThread = nullptr;

		HANDLE remoteProcessHandle{};
		NTSTATUS status = NtOpenProcess(
			&remoteProcessHandle,
			PROCESS_DUP_HANDLE,
			&objectAttributes,
			&clientId);
		if (!NT_SUCCESS(status)) return nullptr;

		HANDLE duplicatedHandle{};
		status = NtDuplicateObject(
			remoteProcessHandle,
			sourceHandle,
			NT_CURRENT_PROCESS,
			&duplicatedHandle,
			0,
			0,
			DUPLICATE_SAME_ACCESS);
		CloseHandleNt(remoteProcessHandle);

		if (!NT_SUCCESS(status)) return nullptr;
		else return duplicatedHandle;
	}

	HANDLE OpenProcessTokenHandleNt(HANDLE hProcess, ACCESS_MASK accessMask)
	{
		if (!IsValidHandle(hProcess)) return nullptr;

		HANDLE tokenHandle{};
		NTSTATUS status{ NtOpenProcessToken(hProcess, accessMask, &tokenHandle) };
		if (!NT_SUCCESS(status)) return nullptr;
		else return tokenHandle;
	}
#pragma endregion

#pragma region READ
	uint64_t GetFullLuidNt(const LUID& luid)
	{
		return (uint64_t(luid.HighPart) << 32) | luid.LowPart;
	}

	DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS& infoClass)
	{
		ULONG requiredBufferSize{};
		BYTE buffer[0x20];

		NtQuerySystemInformation(
			infoClass,
			buffer,
			sizeof(buffer),
			&requiredBufferSize);
		if (!requiredBufferSize) return 0;

		return requiredBufferSize;
	}

	DWORD GetQOBufferSizeNt(HANDLE duplicateHandle, const OBJECT_INFORMATION_CLASS& infoClass)
	{
		if (!IsValidHandle(duplicateHandle)) return 0;

		ULONG requiredBufferSize{};
		NtQueryObject(
			duplicateHandle,
			infoClass,
			nullptr,
			0,
			&requiredBufferSize);
		if (!requiredBufferSize) return 0;

		return requiredBufferSize;
	}

	DWORD GetQITBufferSizeNt(HANDLE tokenHandle, const TOKEN_INFORMATION_CLASS& infoClass)
	{
		if (!IsValidHandle(tokenHandle)) return 0;

		ULONG requiredBufferSize{};
		NtQueryInformationToken(
			tokenHandle,
			infoClass,
			nullptr,
			0,
			&requiredBufferSize);
		if (!requiredBufferSize) return 0;

		return requiredBufferSize;
	}

	std::wstring GetObjectNameNt(HANDLE sourceHandle, DWORD processId)
	{
		if (!IsValidHandle(sourceHandle)) return L"";
		if (!IsValidProcessId(processId)) return L"";

		HANDLE duplicateHandle{ DuplicateHandleNt(sourceHandle, processId) };
		if (!IsValidHandle(duplicateHandle)) return L"";

		DWORD bufferSize{
			GetQOBufferSizeNt(duplicateHandle, ObjectNameInformation) };
		if (!bufferSize)
		{
			CloseHandleNt(duplicateHandle);
			return L"";
		}

		POBJECT_NAME_INFORMATION nameInfoBuffer{
			reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[bufferSize]) };
		NTSTATUS status{ NtQueryObject(
			duplicateHandle, ObjectNameInformation, nameInfoBuffer, bufferSize, nullptr) };
		if (!NT_SUCCESS(status))
		{
			delete[] nameInfoBuffer;
			CloseHandleNt(duplicateHandle);
			return L"";
		}

		std::wstring result{};
		if (nameInfoBuffer->Name.Buffer && nameInfoBuffer->Name.Length > 0)
			result.assign(nameInfoBuffer->Name.Buffer, nameInfoBuffer->Name.Length / sizeof(WCHAR));

		delete[] nameInfoBuffer;
		CloseHandleNt(duplicateHandle);
		return result;
	}

	std::wstring GetObjectTypeNameNt(HANDLE sourceHandle, DWORD processId)
	{
		if (!IsValidHandle(sourceHandle)) return L"";
		if (!IsValidProcessId(processId)) return L"";

		HANDLE duplicateHandle{ DuplicateHandleNt(sourceHandle, processId) };
		if (!IsValidHandle(duplicateHandle)) return L"";

		DWORD bufferSize{
			GetQOBufferSizeNt(duplicateHandle, ObjectTypeInformation) };
		if (!bufferSize)
		{
			CloseHandleNt(duplicateHandle);
			return L"";
		}

		POBJECT_TYPE_INFORMATION typeInfoBuffer{
			reinterpret_cast<POBJECT_TYPE_INFORMATION>(new BYTE[bufferSize]) };
		NTSTATUS status{ NT_SUCCESS(NtQueryObject(
			duplicateHandle, ObjectTypeInformation, typeInfoBuffer, bufferSize, nullptr)) };
		if (!NT_SUCCESS(status))
		{
			delete[] typeInfoBuffer;
			CloseHandleNt(duplicateHandle);
			return L"";
		}

		std::wstring result{};
		if (typeInfoBuffer->TypeName.Buffer && typeInfoBuffer->TypeName.Length > 0)
			result.assign(typeInfoBuffer->TypeName.Buffer, typeInfoBuffer->TypeName.Length / sizeof(WCHAR));

		delete[] typeInfoBuffer;
		CloseHandleNt(duplicateHandle);
		return result;
	}

	std::wstring GetRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString)
	{
		if (!unicodeString.Buffer || !unicodeString.Length) return L"";

		std::wstring s(unicodeString.Length / sizeof(wchar_t), L'\0');
		NtReadVirtualMemory(
			hProcess,
			reinterpret_cast<PVOID>(unicodeString.Buffer),
			s.data(),
			unicodeString.Length,
			nullptr);

		return s;
	}

	PROCESS_EXTENDED_BASIC_INFORMATION GetProcessInformationNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return {};

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS status{ NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&processInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(status)) return {};
		else return processInfo;
	}

	BOOL GetProcessInformationObjectNt(HANDLE hProcess, Corvus::Object::ProcessEntry& processEntry)
	{
		if (!IsValidHandle(hProcess)) return FALSE;

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS status{ NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&processInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(status)) return FALSE;

		processEntry.pebBaseAddress =
			reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress);
		processEntry.processId =
			static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo.BasicInfo.UniqueProcessId));
		processEntry.parentProcessId =
			static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo.BasicInfo.InheritedFromUniqueProcessId));
		processEntry.isProtectedProcess = processInfo.u.s.IsProtectedProcess;
		processEntry.isWow64Process = processInfo.u.s.IsWow64Process;
		processEntry.isBackgroundProcess = processInfo.u.s.IsBackground;
		processEntry.isSecureProcess = processInfo.u.s.IsSecureProcess;
		processEntry.isSubsystemProcess = processInfo.u.s.IsSubsystemProcess;
		return TRUE;
	}

	BOOL GetProcessInformationObjectExtendedNt(
		HANDLE hProcess,
		DWORD processId,
		Corvus::Object::ProcessEntry& processEntry)
	{
		if (!IsValidHandle(hProcess)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		const DWORD bufferSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* systemInfoBuffer = new BYTE[bufferSize];
		NTSTATUS qsiStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			systemInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(qsiStatus))
		{
			delete[] systemInfoBuffer;
			return FALSE;
		}

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{};
		NTSTATUS qipStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&processInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(qipStatus))
		{
			delete[] systemInfoBuffer;
			return FALSE;
		}

		PSYSTEM_PROCESS_INFORMATION systemInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(systemInfoBuffer) };
		while (systemInfo)
		{
			DWORD uniqueProcessId
			{ static_cast<DWORD>(reinterpret_cast<uintptr_t>(systemInfo->UniqueProcessId)) };
			if (uniqueProcessId == processId)
			{
				processEntry.processName = (systemInfo->ImageName.Buffer) ?
					systemInfo->ImageName.Buffer :
					L"";
				processEntry.NativeImageFileName = GetImageFileNameNt(hProcess);
				processEntry.architectureType = GetArchitectureTypeNt(hProcess);
				processEntry.pebBaseAddress =
					reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress);
				processEntry.processId =
					static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(processInfo.BasicInfo.UniqueProcessId));
				processEntry.parentProcessId =
					static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(processInfo.BasicInfo.InheritedFromUniqueProcessId));
				processEntry.isProtectedProcess = processInfo.u.s.IsProtectedProcess;
				processEntry.isWow64Process = processInfo.u.s.IsWow64Process;
				processEntry.isBackgroundProcess = processInfo.u.s.IsBackground;
				processEntry.isSecureProcess = processInfo.u.s.IsSecureProcess;
				processEntry.isSubsystemProcess = processInfo.u.s.IsSubsystemProcess;
				break;
			}
		}
		return TRUE;
	}

	std::wstring GetImageFileNameNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return L"";

		BYTE imageFileNameBuffer[_MAX_PATH]{};
		NTSTATUS status{ NtQueryInformationProcess(
			hProcess,
			ProcessImageFileName,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };
		if (!NT_SUCCESS(status)) return L"";

		std::wstring imageFileName{};
		PUNICODE_STRING pImageFileName{ reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer) };
		if (pImageFileName->Buffer && pImageFileName->Length)
		{
			imageFileName.assign(pImageFileName->Buffer,
				pImageFileName->Length / sizeof(wchar_t));
		}
		return imageFileName;
	}

	std::wstring GetImageFileNameWin32Nt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return L"";

		BYTE imageFileNameBuffer[_MAX_PATH]{};
		NTSTATUS status{ NtQueryInformationProcess(
			hProcess,
			ProcessImageFileNameWin32,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };
		if (!NT_SUCCESS(status)) return L"";

		std::wstring imageFileName{};
		PUNICODE_STRING pImageFileName{ reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer) };
		if (pImageFileName->Buffer && pImageFileName->Length)
		{
			imageFileName.assign(pImageFileName->Buffer,
				pImageFileName->Length / sizeof(wchar_t));
		}
		return imageFileName;
	}

	uintptr_t GetPebBaseAddressNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return {};

		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{ GetProcessInformationNt(hProcess) };
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebBaseAddress)) return {};
		else return pebBaseAddress;
	}

	uintptr_t GetPebBaseAddressNt(const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo)
	{
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebBaseAddress)) return {};
		else return pebBaseAddress;
	}

	uintptr_t GetPebBaseAddressNt(HANDLE hProcess, PROCESS_EXTENDED_BASIC_INFORMATION& processInfo)
	{
		if (!IsValidHandle(hProcess)) return {};
		processInfo = GetProcessInformationNt(hProcess);
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebBaseAddress)) return {};
		else return pebBaseAddress;
	}

	PEB GetPebNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return {};
		uintptr_t pebBaseAddress{ GetPebBaseAddressNt(hProcess) };
		if (!IsValidAddress(pebBaseAddress)) return {};

		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)))
			return {};
		else return peb;
	}

	PEB GetPebNt(HANDLE hProcess, uintptr_t& pebBaseAddress)
	{
		if (!IsValidHandle(hProcess)) return {};
		pebBaseAddress = GetPebBaseAddressNt(hProcess);
		if (!IsValidAddress(pebBaseAddress)) return {};

		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)))
			return {};
		else return peb;
	}

	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return {};

		// Get PEB address
		PROCESS_EXTENDED_BASIC_INFORMATION processInfo{ GetPebBaseAddressNt(hProcess) };
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebBaseAddress)) return {};

		// Read remote PEB
		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)))
			return {};
		if (!peb.Ldr) return {};

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return {};

		// Read loader data
		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData)))
			return {};

		// First module in load order list
		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(firstLink)) return {};

		// Get the LDR_DATA_TABLE_ENTRY
		uintptr_t entryAddress{ firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
		LDR_DATA_TABLE_ENTRY entry{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt(hProcess, entryAddress, entry)))
			return {};
		else return reinterpret_cast<uintptr_t>(entry.DllBase);
	}

	uintptr_t GetModuleBaseAddressNt(
		HANDLE hProcess, const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo)
	{
		if (!IsValidHandle(hProcess)) return {};
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(processInfo.BasicInfo.PebBaseAddress) };
		if (!IsValidAddress(pebBaseAddress)) return {};

		// Read remote PEB
		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)))
			return {};
		if (!peb.Ldr) return {};

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return {};

		// Read loader data
		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData)))
			return {};

		// First module in load order list
		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(firstLink)) return {};

		// Get the LDR_DATA_TABLE_ENTRY
		uintptr_t entryAddress{ firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
		LDR_DATA_TABLE_ENTRY entry{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt(hProcess, entryAddress, entry)))
			return {};
		else return reinterpret_cast<uintptr_t>(entry.DllBase);
	}

	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess, uintptr_t pebBaseAddress)
	{
		if (!IsValidHandle(hProcess)) return {};
		if (!IsValidAddress(pebBaseAddress)) return {};

		// Read remote PEB
		PEB peb{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)))
			return {};
		if (!peb.Ldr) return {};

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return {};

		// Read loader data
		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData)))
			return {};

		// First module in load order list
		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(firstLink)) return {};

		// Get the LDR_DATA_TABLE_ENTRY
		uintptr_t entryAddress{ firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
		LDR_DATA_TABLE_ENTRY entry{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt(hProcess, entryAddress, entry)))
			return {};
		else return reinterpret_cast<uintptr_t>(entry.DllBase);
	}

	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess, const PEB& peb)
	{
		if (!IsValidHandle(hProcess)) return {};
		if (!peb.Ldr) return {};

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return {};

		// Read loader data
		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData)))
			return {};

		// First module in load order list
		uintptr_t firstLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(firstLink)) return {};

		// Get the LDR_DATA_TABLE_ENTRY
		uintptr_t entryAddress{ firstLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
		LDR_DATA_TABLE_ENTRY entry{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt(hProcess, entryAddress, entry)))
			return {};
		else return reinterpret_cast<uintptr_t>(entry.DllBase);
	}

	Corvus::Object::ArchitectureType GetArchitectureTypeNt(HANDLE hProcess)
	{
		ULONG_PTR wow64Info{};
		if (!NT_SUCCESS(NtQueryInformationProcess(
			hProcess,
			ProcessWow64Information,
			&wow64Info,
			sizeof(ULONG_PTR),
			nullptr)))
			return Corvus::Object::ArchitectureType::Unknown;

		return (wow64Info) ?
			Corvus::Object::ArchitectureType::x86 :
			Corvus::Object::ArchitectureType::x64;
	}

	std::vector<LDR_DATA_TABLE_ENTRY> GetProcessModulesNt(HANDLE hProcess, const PEB& peb)
	{
		if (!IsValidHandle(hProcess)) return {};
		if (!peb.Ldr) return {};

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return {};

		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData))) return {};
		if (!loaderData.InLoadOrderModuleList.Flink) return {};

		uintptr_t listHead{ loaderAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };
		if (!IsValidAddress(listHead)) return {};

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(currentLink)) return {};

		std::vector<LDR_DATA_TABLE_ENTRY> modules{};
		size_t sanityCounter{ 0 };
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > MAX_MODULES)
				break;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddress{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{};
			if (!NT_SUCCESS(ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(hProcess, entryAddress, entry)))
				break;
			else modules.push_back(std::move(entry));

			uintptr_t next = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return modules;
	};

	BOOL GetProcessModuleObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		const PEB& peb,
		std::vector<Corvus::Object::ModuleEntry>& modules)
	{
		if (!IsValidHandle(hProcess)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;
		if (!peb.Ldr) return FALSE;

		uintptr_t loaderAddress{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!IsValidAddress(loaderAddress)) return FALSE;

		PEB_LDR_DATA loaderData{};
		if (!NT_SUCCESS(ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, loaderAddress, loaderData))) return {};
		if (!loaderData.InLoadOrderModuleList.Flink) return FALSE;

		uintptr_t listHead{ loaderAddress + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };
		if (!IsValidAddress(listHead)) return FALSE;

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(loaderData.InLoadOrderModuleList.Flink) };
		if (!IsValidAddress(currentLink)) return FALSE;

		size_t sanityCounter{ 0 };
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > MAX_MODULES)
				break;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddress{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{};
			if (!NT_SUCCESS(ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(hProcess, entryAddress, entry)))
				break;

			Corvus::Object::ModuleEntry moduleEntry{};
			moduleEntry.moduleBaseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
			moduleEntry.moduleBaseSize = entry.SizeOfImage;
			moduleEntry.moduleEntryPoint = reinterpret_cast<uintptr_t>(entry.EntryPoint);
			moduleEntry.processId = processId;
			moduleEntry.moduleName = GetRemoteUnicodeStringNt(hProcess, entry.BaseDllName);
			moduleEntry.modulePath = GetRemoteUnicodeStringNt(hProcess, entry.FullDllName);
			modules.push_back(std::move(moduleEntry));

			uintptr_t next = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return TRUE;
	};

	std::vector<SYSTEM_THREAD_INFORMATION> GetProcessThreadsNt(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};

		const DWORD bufferSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[bufferSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return {};
		}

		std::vector<SYSTEM_THREAD_INFORMATION> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_THREAD_INFORMATION& sThreadInfo = processInfo->Threads[i];
					threads.push_back(sThreadInfo);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return threads;
	}

	std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> GetProcessThreadsExtendedNt(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};
		if (!IsValidProcessId(processId)) return {};

		const DWORD bufferSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[bufferSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return {};
		}

		std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_EXTENDED_THREAD_INFORMATION& sThreadInfo = processInfo->ThreadsEx[i];
					threads.push_back(sThreadInfo);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return threads;
	}

	BOOL GetProcessThreadObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads)
	{
		if (!IsValidHandle(hProcess)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		const DWORD bufferSize{ GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[bufferSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemProcessInformation,
			processInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_THREAD_INFORMATION& sThreadInfo{ processInfo->Threads[i] };
					Corvus::Object::ThreadEntry threadEntry{};
					threadEntry.kernelThreadStartAddress =
						reinterpret_cast<uintptr_t>(sThreadInfo.StartAddress);
					threadEntry.nativeThreadBasePriority =
						static_cast<Corvus::Object::NativeThreadBasePriority>(sThreadInfo.BasePriority);
					threadEntry.threadId =
						static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
					threadEntry.threadOwnerProcessId = processId;
					threads.push_back(threadEntry);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return TRUE;
	}

	BOOL GetProcessThreadObjectsExtendedNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads)
	{
		if (!IsValidHandle(hProcess)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		const DWORD bufferSize{ GetQSIBufferSizeNt(SystemExtendedProcessInformation) };
		BYTE* processInfoBuffer = new BYTE[bufferSize];
		NTSTATUS status{ NtQuerySystemInformation(
			SystemExtendedProcessInformation,
			processInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(status))
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo)
		{
			delete[] processInfoBuffer;
			return FALSE;
		}

		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i{ 0 }; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_THREAD_INFORMATION& sThreadInfo{ processInfo->Threads[i] };
					const SYSTEM_EXTENDED_THREAD_INFORMATION& sThreadExInfo{ processInfo->ThreadsEx[i] };
					Corvus::Object::ThreadEntry threadEntry{};
					threadEntry.kernelThreadStartAddress =
						reinterpret_cast<uintptr_t>(sThreadInfo.StartAddress);
					threadEntry.win32ThreadStartAddress =
						reinterpret_cast<uintptr_t>(sThreadExInfo.Win32StartAddress);
					threadEntry.tebBaseAddress =
						reinterpret_cast<uintptr_t>(sThreadExInfo.TebBase);
					threadEntry.nativeThreadBasePriority =
						static_cast<Corvus::Object::NativeThreadBasePriority>(sThreadInfo.BasePriority);
					threadEntry.threadId =
						static_cast<DWORD>(
							reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
					threadEntry.threadOwnerProcessId = processId;
					threads.push_back(threadEntry);
				} break;
			}
			if (processInfo->NextEntryOffset == 0) break;

			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) +
				processInfo->NextEntryOffset);
		}
		delete[] processInfoBuffer;
		return TRUE;
	}

	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetProcessHandlesNt(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};
		if (!IsValidProcessId(processId)) return {};

		DWORD bufferSize{ GetQSIBufferSizeNt(SystemHandleInformation) + PAGE_SIZE };
		BYTE* handleInfoBuffer = new BYTE[bufferSize];
		NTSTATUS ntStatus{ NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfoBuffer,
				bufferSize,
				nullptr) };

		if (!NT_SUCCESS(ntStatus))
		{
			delete[] handleInfoBuffer;
			return {};
		}

		PSYSTEM_HANDLE_INFORMATION handleInfo{ reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer) };
		if (!handleInfo)
		{
			delete[] handleInfoBuffer;
			return {};
		}

		std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> handles{ PAGE_SIZE };
		for (ULONG i{ 0 }; i < handleInfo->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo{ handleInfo->Handles[i] };
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(processId))
				continue;

			handles.push_back(sHandleInfo);
		}
		delete[] handleInfoBuffer;
		return handles;
	}

	BOOL GetProcessHandleObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::HandleEntry>& handles)
	{
		if (!IsValidHandle(hProcess)) return FALSE;
		if (!IsValidProcessId(processId)) return FALSE;

		DWORD bufferSize{ GetQSIBufferSizeNt(SystemHandleInformation) + PAGE_SIZE };
		BYTE* handleInfoBuffer = new BYTE[bufferSize];
		NTSTATUS ntStatus{ NtQuerySystemInformation(
				SystemHandleInformation,
				handleInfoBuffer,
				bufferSize,
				nullptr) };

		if (!NT_SUCCESS(ntStatus))
		{
			delete[] handleInfoBuffer;
			return {};
		}

		PSYSTEM_HANDLE_INFORMATION handleInfo{ reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(handleInfoBuffer) };
		if (!handleInfo)
		{
			delete[] handleInfoBuffer;
			return {};
		}

		for (ULONG i{ 0 }; i < handleInfo->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo{ handleInfo->Handles[i] };
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(processId))
				continue;

			Corvus::Object::HandleEntry handleEntry{};
			handleEntry.handleValue = reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
			handleEntry.typeName = GetObjectTypeNameNt(handleEntry.handleValue, processId);
			handleEntry.objectName = GetObjectNameNt(handleEntry.handleValue, processId);
			handleEntry.grantedAccess = sHandleInfo.GrantedAccess;

			// experimental
			if (handleEntry.typeName == L"Process")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Process;
			else if (handleEntry.typeName == L"Thread")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Thread;
			else if (handleEntry.typeName == L"Mutant")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Mutant;
			else if (handleEntry.typeName == L"Event")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Event;
			else if (handleEntry.typeName == L"Section")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Section;
			else if (handleEntry.typeName == L"Semaphore")
				handleEntry.userHandleObjectType = Corvus::Object::UserHandleObjectType::Semaphore;

			handles.push_back(handleEntry);
		}
		delete[] handleInfoBuffer;
		return TRUE;
	}

	TOKEN_STATISTICS GetProcessTokenStatisticsNt(HANDLE tokenHandle)
	{
		if (!IsValidHandle(tokenHandle)) return {};

		TOKEN_STATISTICS statisticsBuffer{};
		// requiredBufferSize, the tarnished one
		DWORD requiredBufferSize{};
		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			TokenStatistics,
			&statisticsBuffer,
			sizeof(TOKEN_STATISTICS),
			&requiredBufferSize) };
		if (!NT_SUCCESS(status)) return {};
		else return statisticsBuffer;
	}

	std::vector<LUID_AND_ATTRIBUTES> GetProcessTokenPriviligesNt(HANDLE tokenHandle)
	{
		if (!IsValidHandle(tokenHandle)) return {};

		DWORD bufferSize{
			GetQITBufferSizeNt(tokenHandle, TokenPrivileges) };
		if (!bufferSize) return {};

		std::vector<BYTE> privilegesBuffer(bufferSize);
		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			TokenPrivileges,
			privilegesBuffer.data(),
			bufferSize,
			&bufferSize) };
		if (!NT_SUCCESS(status)) return {};

		PTOKEN_PRIVILEGES privileges
		{ reinterpret_cast<PTOKEN_PRIVILEGES>(privilegesBuffer.data()) };

		return std::vector<LUID_AND_ATTRIBUTES>(
			privileges->Privileges,
			privileges->Privileges + privileges->PrivilegeCount);
	}

	BOOL GetProcessTokenPriviligeObjectsNt(HANDLE tokenHandle, std::vector<Corvus::Object::PrivilegeEntry>& privileges)
	{
		if (!IsValidHandle(tokenHandle)) return FALSE;

		std::vector<LUID_AND_ATTRIBUTES> priviligesBuffer
		{ GetProcessTokenPriviligesNt(tokenHandle) };
		if (priviligesBuffer.empty()) return FALSE;

		std::vector<Corvus::Object::PrivilegeEntry> privileges{};
		for (LUID_AND_ATTRIBUTES privilege : priviligesBuffer)
		{
			Corvus::Object::PrivilegeEntry privilegeEntry{};
			privilegeEntry.TokenLuid = GetFullLuidNt(privilege.Luid);
			privilegeEntry.TokenAttributes = privilege.Attributes;
			privileges.push_back(privilegeEntry);
		}
		return TRUE;
	}

	DWORD GetProcessTokenSessionIdNt(HANDLE tokenHandle)
	{
		if (!IsValidHandle(tokenHandle)) return {};

		ULONG sessionIdBuffer{};
		// requiredBufferSize, the tarnished one
		DWORD requiredBufferSize{};
		NTSTATUS status{ NtQueryInformationToken(
			tokenHandle,
			TokenSessionId,
			&sessionIdBuffer,
			sizeof(ULONG),
			&requiredBufferSize) };
		if (!NT_SUCCESS(status)) return {};
		else return sessionIdBuffer;
	}

	BOOL GetProcessAccessTokenObjectNt(
		HANDLE hProcess,
		ACCESS_MASK accessMask,
		Corvus::Object::AccessToken& accessToken)
	{
		if (!IsValidHandle(hProcess)) return FALSE;

		HANDLE tokenHandle{ OpenProcessTokenHandleNt(hProcess, accessMask) };
		if (!IsValidHandle(tokenHandle)) return FALSE;

		TOKEN_STATISTICS statistics{
			GetProcessTokenStatisticsNt(tokenHandle) };
		if (!IsValidLuid(statistics.TokenId)) return FALSE;
		if (statistics.PrivilegeCount <= 0) return FALSE;

		DWORD sessionId{ GetProcessTokenSessionIdNt(tokenHandle) };
		if (!sessionId) return FALSE;

		std::vector<Corvus::Object::PrivilegeEntry> privileges{};
		if (!GetProcessTokenPriviligeObjectsNt(tokenHandle, privileges))
			return FALSE;

		accessToken.TokenPrivileges = privileges;
		accessToken.TokenId = GetFullLuidNt(statistics.TokenId);
		accessToken.AuthenticationId = GetFullLuidNt(statistics.AuthenticationId);
		accessToken.SessionId = sessionId;
		return TRUE;
	}
#pragma endregion

	/*
	std::vector<Corvus::Object::ProcessEntry> WindowsProviderNt::QueryProcesses()
	{
		const DWORD bufferSize{ Corvus::Service::GetQSIBufferSizeNt(SystemProcessInformation) };
		std::unique_ptr<BYTE[]> buffer(new BYTE[bufferSize]);
		NTSTATUS systemInfoStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			buffer.get(),
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(systemInfoStatus)) return {};

		std::vector<Corvus::Object::ProcessEntry> processList{};
		PSYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.get());
		while (processInfo)
		{
			Corvus::Object::ProcessEntry pEntry{};
			pEntry.processId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId));
			pEntry.parentProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(processInfo->InheritedFromUniqueProcessId));
			pEntry.processName = (processInfo->ImageName.Buffer) ? processInfo->ImageName.Buffer : L"";
			QueryModuleBaseAddress(pEntry.processId, pEntry.processName);

			ACCESS_MASK accessMasks[]{
				PROCESS_ALL_ACCESS,
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				PROCESS_QUERY_LIMITED_INFORMATION
			};

			HANDLE hProc{};
			for (ACCESS_MASK accessMask : accessMasks)
			{
				hProc = Corvus::Service::OpenHandleNt(pEntry.processId, accessMask);
				if (Corvus::Service::IsValidHandle(hProc)) break;
				else return{};
			}

			GetExtendedProcessInfo(hProc);
			GetImageFileNameNt(hProc);
			QueryPriorityClassNt(hProc);
			QueryArchitectureNt(hProc);

			// Threads
			for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
			{
				Corvus::Object::ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = processInfo->Threads[i];

				threadEntry.structureSize = sizeof(SYSTEM_THREAD_INFORMATION);
				threadEntry.threadId = static_cast<DWORD>(
					reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
				threadEntry.ownerProcessId = pEntry.processId;
				threadEntry.basePriority = sThreadInfo.BasePriority;
				threadEntry.startAddress = sThreadInfo.StartAddress;
				threadEntry.threadState = sThreadInfo.ThreadState;
				pEntry.threads.push_back(threadEntry);
			}
			processList.push_back(pEntry);
			Corvus::Service::CloseHandleNt(hProc);

			// Advance to next process (ALWAYS)
			if (processInfo->NextEntryOffset)
			{
				processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset);
			}
			else break;
		}
		return processList;
	}*/
}