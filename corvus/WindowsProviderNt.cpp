#include "WindowsProviderNt.h"
#include "MemoryService.h"
#pragma comment(lib, "ntdll.lib")

#ifndef MAX_MODULES
#define MAX_MODULES 1024
#endif // !MAX_MODULES


namespace Corvus::Data
{

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

	BOOL CloseProcessHandleNt(HANDLE handle)
	{
		return NT_SUCCESS(NtClose(handle));
	}

	std::wstring ReadRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString)
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

		PROCESS_EXTENDED_BASIC_INFORMATION pInfo{};
		NTSTATUS status{ NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr) };

		if (!NT_SUCCESS(status)) return {};
		else return pInfo;
	}

	std::wstring GetImageFileNameNt(HANDLE hProcess)
	{
		if (!IsValidHandle(hProcess)) return {};

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
		if (!IsValidHandle(hProcess)) return {};

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

	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess, const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo)
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
		size_t sanityCounter = 0;
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

	std::vector<Corvus::Object::ModuleEntry> GetProcessModulesNt(HANDLE hProcess, DWORD processId, const PEB& peb)
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

		std::vector<Corvus::Object::ModuleEntry> modules{};
		size_t sanityCounter = 0;
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
			moduleEntry.moduleName = ReadRemoteUnicodeStringNt(hProcess, entry.BaseDllName);
			moduleEntry.modulePath = ReadRemoteUnicodeStringNt(hProcess, entry.FullDllName);
			modules.push_back(std::move(moduleEntry));

			uintptr_t next = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return modules;
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
		if (!processInfo) return {};

		std::vector<SYSTEM_THREAD_INFORMATION> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
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

	std::vector<Corvus::Object::ThreadEntry> GetProcessThreadObjectsNt(HANDLE hProcess, DWORD processId)
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
		if (!processInfo) return {};

		std::vector<Corvus::Object::ThreadEntry> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_THREAD_INFORMATION& sThreadInfo = processInfo->Threads[i];
					Corvus::Object::ThreadEntry threadEntry{};
					threadEntry.kernelThreadStartAddress = reinterpret_cast<uintptr_t>(sThreadInfo.StartAddress);
					threadEntry.nativeThreadBasePriority = static_cast<Corvus::Object::NativeThreadBasePriority>(sThreadInfo.BasePriority);
					threadEntry.threadId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
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
		return threads;
	}

	std::vector<Corvus::Object::ThreadEntry> GetExtendedProcessThreadObjectsNt(HANDLE hProcess, DWORD processId)
	{
		if (!IsValidHandle(hProcess)) return {};

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
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION processInfo
		{ reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer) };
		if (!processInfo) return {};

		std::vector<Corvus::Object::ThreadEntry> threads{};
		while (processInfo)
		{
			DWORD processInfoId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId)) };

			if (processInfoId == processId)
			{
				for (ULONG i = 0; i < processInfo->NumberOfThreads; ++i)
				{
					const SYSTEM_EXTENDED_THREAD_INFORMATION& sThreadInfo = processInfo->Threads[i];
					Corvus::Object::ThreadEntry threadEntry{};
					threadEntry.kernelThreadStartAddress = reinterpret_cast<uintptr_t>(sThreadInfo.s);
					threadEntry.nativeThreadBasePriority = static_cast<Corvus::Object::NativeThreadBasePriority>(sThreadInfo.BasePriority);
					threadEntry.threadId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
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
		return threads;
	}

	std::vector<Corvus::Object::HandleEntry> WindowsProviderNt::QueryHandles(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		DWORD processId{ Object.GetProcessId() };
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		DWORD requiredBufferSize{ Corvus::Service::GetQSIBufferSizeNt(
			SystemHandleInformation) + 0x1000 };
		BYTE* hInfoBuffer = new BYTE[requiredBufferSize];
		NTSTATUS ntStatus{ NtQuerySystemInformation(
				SystemHandleInformation,
				hInfoBuffer,
				requiredBufferSize,
				nullptr) };

		if (!NT_SUCCESS(ntStatus))
		{
			delete[] hInfoBuffer;
			return {};
		}

		PSYSTEM_HANDLE_INFORMATION pHandles = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION>(hInfoBuffer);

		// Pre-allocate memory
		std::vector<Corvus::Object::HandleEntry> handles(2000);
		for (ULONG i = 0; i < pHandles->NumberOfHandles; ++i)
		{
			const SYSTEM_HANDLE_TABLE_ENTRY_INFO& sHandleInfo = pHandles->Handles[i];
			if (static_cast<uintptr_t>(sHandleInfo.UniqueProcessId) != static_cast<uintptr_t>(processId))
				continue;

			Corvus::Object::HandleEntry handle{};
			handle.handle = reinterpret_cast<HANDLE>(sHandleInfo.HandleValue);
			handle.typeName = QueryObjectTypeNameNt(handle.handle, sHandleInfo.UniqueProcessId);
			handle.objectName = QueryObjectNameNt(handle.handle, sHandleInfo.UniqueProcessId);
			handle.attributes = sHandleInfo.HandleAttributes;
			handle.grantedAccess = sHandleInfo.GrantedAccess;
			handles.push_back(handle);
		}

		delete[] hInfoBuffer;
		return handles;
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

	// fix dup handle bug later
	std::wstring WindowsProviderNt::QueryObjectNameNt(HANDLE hObject, DWORD processId)
	{
		if (!Corvus::Service::IsValidHandle(hObject)) return L"";
		HANDLE localProcessHandle{ OpenProcess(processId, FALSE, PROCESS_DUP_HANDLE) };
		if (!Corvus::Service::IsValidHandle(localProcessHandle)) return L"";

		HANDLE dupHandle{};
		if (!DuplicateHandle(
			localProcessHandle,
			hObject,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			Corvus::Service::CloseHandleNt(localProcessHandle);
			return L"";
		}

		ULONG size{};
		NtQueryObject(dupHandle, ObjectNameInformation, nullptr, 0, &size);
		if (!size)
		{
			Corvus::Service::CloseHandleNt(localProcessHandle);
			Corvus::Service::CloseHandleNt(dupHandle);
			return L"";
		}

		POBJECT_NAME_INFORMATION nameBuffer{
			reinterpret_cast<POBJECT_NAME_INFORMATION>(new BYTE[size]) };
		std::wstring result{};
		if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, nameBuffer, size, nullptr)))
		{
			if (nameBuffer->Name.Buffer && nameBuffer->Name.Length > 0)
			{
				result.assign(nameBuffer->Name.Buffer, nameBuffer->Name.Length / sizeof(WCHAR));
			}
		}

		delete[] nameBuffer;
		Corvus::Service::CloseHandleNt(localProcessHandle);
		Corvus::Service::CloseHandleNt(dupHandle);
		return result;
	}

	std::wstring WindowsProviderNt::QueryObjectTypeNameNt(HANDLE hObject, DWORD processId)
	{
		if (!Corvus::Service::IsValidHandle(hObject)) return L"";
		// Fix this later
		HANDLE localProcessHandle{ OpenProcess(processId, FALSE, PROCESS_DUP_HANDLE) };
		if (!Corvus::Service::IsValidHandle(localProcessHandle)) return L"";

		HANDLE dupHandle{};
		if (!DuplicateHandle(
			localProcessHandle,
			hObject,
			GetCurrentProcess(),
			&dupHandle,
			0,
			FALSE,
			DUPLICATE_SAME_ACCESS))
		{
			Corvus::Service::CloseHandleNt(localProcessHandle);
			return L"";
		}

		ULONG size{};
		NtQueryObject(dupHandle, ObjectTypeInformation, nullptr, 0, &size);
		if (!size)
		{
			Corvus::Service::CloseHandleNt(localProcessHandle);
			Corvus::Service::CloseHandleNt(dupHandle);
			return L"";
		}

		POBJECT_TYPE_INFORMATION typeInfo{
			reinterpret_cast<POBJECT_TYPE_INFORMATION>(new BYTE[size]) };
		std::wstring result{};
		if (NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, typeInfo, size, nullptr)))
		{
			if (typeInfo->TypeName.Buffer && typeInfo->TypeName.Length > 0)
				result.assign(typeInfo->TypeName.Buffer, typeInfo->TypeName.Length / sizeof(WCHAR));
		}

		delete[] typeInfo;
		Corvus::Service::CloseHandleNt(localProcessHandle);
		Corvus::Service::CloseHandleNt(dupHandle);
		return result;
	}

	/*
Corvus::Object::ProcessEntry QueryProcessInfo(HANDLE hProcess, DWORD processId)
{
	if (!IsValidHandle(hProcess)) return {};
	Corvus::Object::ProcessEntry pEntry{};

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

	PSYSTEM_PROCESS_INFORMATION processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(processInfoBuffer);
	std::vector<Corvus::Object::ProcessEntry> processes;
	while (processInfo)
	{
		DWORD uniqueProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(processInfo->UniqueProcessId));
		if (uniqueProcessId == processId)
		{
			pEntry.processName = (processInfo->ImageName.Buffer) ? processInfo->ImageName.Buffer : L"";
			pEntry.imageFilePath = GetImageFileNameNt(hProcess);
			pEntry.priorityClass = QueryPriorityClassNt(hProcess);
			pEntry.architectureType = QueryArchitectureNt(hProcess);

			PROCESS_EXTENDED_BASIC_INFORMATION pInfoExtended{
				WindowsProviderNt::GetExtendedProcessInfo(hProcess) };
			pEntry.parentProcessId =
				static_cast<DWORD>(reinterpret_cast<uintptr_t>(
					pInfoExtended.BasicInfo.InheritedFromUniqueProcessId));
			pEntry.pebBaseAddress =
				reinterpret_cast<uintptr_t>(pInfoExtended.BasicInfo.PebBaseAddress);
			pEntry.isWow64 = pInfoExtended.u.s.IsWow64Process;
			pEntry.isProtectedProcess = pInfoExtended.u.s.IsProtectedProcess;
			pEntry.isBackgroundProcess = pInfoExtended.u.s.IsBackground;
			pEntry.isSubsystemProcess = pInfoExtended.u.s.IsSubsystemProcess;

			break;
		}

		// Advance to next process (ALWAYS)
		if (processInfo->NextEntryOffset)
		{
			processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(processInfo) + processInfo->NextEntryOffset);
		}
		else break;
	}

	delete[] processInfoBuffer;
	return pEntry;
}*/

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