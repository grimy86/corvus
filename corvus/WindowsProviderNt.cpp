#include "WindowsProviderNt.h"
#include "MemoryServiceNt.h"
#pragma comment(lib, "ntdll.lib")

namespace Corvus::Data
{
	HANDLE WindowsProviderNt::OpenProcessHandle(const DWORD processId, const ACCESS_MASK accessMask)
	{
		return Corvus::Service::OpenHandleNt(processId, accessMask);
	}

	BOOL WindowsProviderNt::CloseProcessHandle(HANDLE handle)
	{
		return Corvus::Service::CloseHandleNt(handle);
	}

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
		PSYSTEM_PROCESS_INFORMATION pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer.get());
		while (pInfo)
		{
			Corvus::Object::ProcessEntry pEntry{};
			pEntry.processId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pInfo->UniqueProcessId));
			pEntry.parentProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pInfo->InheritedFromUniqueProcessId));
			pEntry.processName = (pInfo->ImageName.Buffer) ? pInfo->ImageName.Buffer : L"";
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

			QueryExtendedProcessInfo(hProc);
			QueryImageFilePathNt(hProc);
			QueryPriorityClassNt(hProc);
			QueryArchitectureNt(hProc);

			// Threads
			for (ULONG i = 0; i < pInfo->NumberOfThreads; ++i)
			{
				Corvus::Object::ThreadEntry threadEntry{};
				const SYSTEM_THREAD_INFORMATION& sThreadInfo = pInfo->Threads[i];

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
			if (pInfo->NextEntryOffset)
			{
				pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
			}
			else break;
		}
		return processList;
	}

	Corvus::Object::ProcessEntry WindowsProviderNt::QueryProcessInfo(HANDLE hProcess, DWORD processId)
	{
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};
		Corvus::Object::ProcessEntry pEntry{};

		const DWORD bufferSize{ Corvus::Service::GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* pInfoBuffer = new BYTE[bufferSize];
		NTSTATUS ntSysStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			pInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(ntSysStatus))
		{
			delete[] pInfoBuffer;
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pInfoBuffer);
		std::vector<Corvus::Object::ProcessEntry> processes;
		while (pInfo)
		{
			DWORD uniqueProcessId = static_cast<DWORD>(reinterpret_cast<uintptr_t>(pInfo->UniqueProcessId));
			if (uniqueProcessId == processId)
			{
				pEntry.processName = (pInfo->ImageName.Buffer) ? pInfo->ImageName.Buffer : L"";
				pEntry.imageFilePath = QueryImageFilePathNt(hProcess);
				pEntry.priorityClass = QueryPriorityClassNt(hProcess);
				pEntry.architectureType = QueryArchitectureNt(hProcess);

				PROCESS_EXTENDED_BASIC_INFORMATION pInfoExtended{
					WindowsProviderNt::QueryExtendedProcessInfo(hProcess) };
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
			if (pInfo->NextEntryOffset)
			{
				pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
					reinterpret_cast<BYTE*>(pInfo) + pInfo->NextEntryOffset);
			}
			else break;
		}

		delete[] pInfoBuffer;
		return pEntry;
	}

	std::vector<Corvus::Object::ModuleEntry> WindowsProviderNt::QueryModules(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		PROCESS_EXTENDED_BASIC_INFORMATION pInfo{ QueryExtendedProcessInfo(hProcess) };
		uintptr_t pebBaseAddress{ reinterpret_cast<uintptr_t>(pInfo.BasicInfo.PebBaseAddress) };
		if (!Corvus::Service::IsValidAddress(pebBaseAddress)) return {};

		PEB peb{};
		if (!NT_SUCCESS(Corvus::Service::ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb))) return {};
		if (!peb.Ldr) return {};

		uintptr_t ldrAddr{ reinterpret_cast<uintptr_t>(peb.Ldr) };
		if (!Corvus::Service::IsValidAddress(ldrAddr)) return {};

		PEB_LDR_DATA ldr{};
		if (!NT_SUCCESS(Corvus::Service::ReadVirtualMemoryNt<PEB_LDR_DATA>(hProcess, ldrAddr, ldr))) return {};
		if (!ldr.InLoadOrderModuleList.Flink) return {};

		uintptr_t listHead{ ldrAddr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList) };
		if (!Corvus::Service::IsValidAddress(listHead)) return {};

		uintptr_t currentLink{ reinterpret_cast<uintptr_t>(ldr.InLoadOrderModuleList.Flink) };
		if (!Corvus::Service::IsValidAddress(currentLink)) return {};

		std::vector<Corvus::Object::ModuleEntry> modules{};
		size_t sanityCounter = 0;
		while (currentLink && currentLink != listHead)
		{
			if (++sanityCounter > 1024)
				break;

			// first remote module = fLink - ILOL offset
			uintptr_t entryAddr{ currentLink - offsetof(LDR_DATA_TABLE_ENTRY, InLoadOrderLinks) };
			LDR_DATA_TABLE_ENTRY entry{};
			if (!NT_SUCCESS(Corvus::Service::ReadVirtualMemoryNt<LDR_DATA_TABLE_ENTRY>(hProcess, entryAddr, entry)))
				break;

			Corvus::Object::ModuleEntry mEntry{};
			mEntry.baseAddress = reinterpret_cast<uintptr_t>(entry.DllBase);
			mEntry.moduleBaseSize = entry.SizeOfImage;
			mEntry.entryPoint = entry.EntryPoint;
			mEntry.globalLoadCount = entry.ObsoleteLoadCount;
			mEntry.processLoadCount = 0;
			mEntry.processId = reinterpret_cast<DWORD>(pInfo.BasicInfo.UniqueProcessId);
			mEntry.moduleName = Corvus::Service::ReadRemoteUnicodeStringNt(hProcess, entry.BaseDllName);
			mEntry.modulePath = Corvus::Service::ReadRemoteUnicodeStringNt(hProcess, entry.FullDllName);
			modules.push_back(std::move(mEntry));

			uintptr_t next = reinterpret_cast<uintptr_t>(entry.InLoadOrderLinks.Flink);
			if (!Corvus::Service::IsValidAddress(next) || next == currentLink) break;
			else currentLink = next;
		};
		return modules;
	};

	std::vector<Corvus::Object::ThreadEntry> WindowsProviderNt::QueryThreads(const Corvus::Object::ProcessObject& Object)
	{
		HANDLE hProcess{ Object.GetProcessHandle() };
		DWORD processId{ Object.GetProcessId() };
		if (!Corvus::Service::IsValidHandle(hProcess)) return {};

		const DWORD bufferSize{ Corvus::Service::GetQSIBufferSizeNt(SystemProcessInformation) };
		BYTE* pInfoBuffer = new BYTE[bufferSize];
		NTSTATUS ntSysStatus{ NtQuerySystemInformation(
			SystemProcessInformation,
			pInfoBuffer,
			bufferSize,
			nullptr) };

		if (!NT_SUCCESS(ntSysStatus))
		{
			delete[] pInfoBuffer;
			return {};
		}

		PSYSTEM_PROCESS_INFORMATION pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(pInfoBuffer);
		if (!pInfo) return {};

		std::vector<Corvus::Object::ThreadEntry> threads{};
		while (pInfo)
		{
			DWORD pInfoProcessId{ static_cast<DWORD>(
				reinterpret_cast<uintptr_t>(pInfo->UniqueProcessId)) };

			if (pInfoProcessId == processId)
			{
				// Threads
				for (ULONG i = 0; i < pInfo->NumberOfThreads; ++i)
				{
					Corvus::Object::ThreadEntry threadEntry{};
					const SYSTEM_THREAD_INFORMATION& sThreadInfo = pInfo->Threads[i];

					threadEntry.structureSize = sizeof(SYSTEM_THREAD_INFORMATION);
					threadEntry.threadId = static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueThread));
					threadEntry.ownerProcessId = static_cast<DWORD>(
						reinterpret_cast<uintptr_t>(sThreadInfo.ClientId.UniqueProcess));
					threadEntry.basePriority = sThreadInfo.BasePriority;
					threadEntry.startAddress = sThreadInfo.StartAddress;
					threadEntry.threadState = sThreadInfo.ThreadState;
					threads.push_back(threadEntry);
				} break;
			}

			if (pInfo->NextEntryOffset == 0) break;

			pInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(
				reinterpret_cast<BYTE*>(pInfo) +
				pInfo->NextEntryOffset);
		}
		delete[] pInfoBuffer;
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

	PROCESS_EXTENDED_BASIC_INFORMATION WindowsProviderNt::QueryExtendedProcessInfo(HANDLE hProcess)
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pInfo{};
		NTSTATUS ntProcExtendedInfoStatus = NtQueryInformationProcess(
			hProcess,
			ProcessBasicInformation,
			&pInfo,
			sizeof(PROCESS_EXTENDED_BASIC_INFORMATION),
			nullptr);
		if (!NT_SUCCESS(ntProcExtendedInfoStatus)) return {};
		else return pInfo;
	}

	std::wstring WindowsProviderNt::QueryImageFilePathNt(HANDLE hProcess)
	{
		BYTE imageFileNameBuffer[512]{};
		NTSTATUS ntImageFileNameStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessImageFileName,
			imageFileNameBuffer,
			sizeof(imageFileNameBuffer),
			nullptr) };
		if (!NT_SUCCESS(ntImageFileNameStatus)) return L"";

		PUNICODE_STRING imageFileName = reinterpret_cast<PUNICODE_STRING>(imageFileNameBuffer);
		std::wstring result{};
		if (imageFileName->Buffer && imageFileName->Length)
		{
			result.assign(
				imageFileName->Buffer,
				imageFileName->Length / sizeof(wchar_t));
		}
		return result;
	}

	// TO DO
	uintptr_t WindowsProviderNt::QueryModuleBaseAddress(DWORD processId, const std::wstring& processName)
	{
		return 0;
	}

	Corvus::Object::UserProcessBasePriorityClass WindowsProviderNt::QueryPriorityClassNt(HANDLE hProcess)
	{
		PROCESS_PRIORITY_CLASS pPriorityClass{};
		NTSTATUS ntProcPriorityClassStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessPriorityClass,
			&pPriorityClass,
			sizeof(PROCESS_PRIORITY_CLASS),
			nullptr) };
		if (!NT_SUCCESS(ntProcPriorityClassStatus))
			return Corvus::Object::UserProcessBasePriorityClass::Undefined;

		switch (pPriorityClass.UserProcessBasePriorityClass)
		{
		case 0U: return Corvus::Object::UserProcessBasePriorityClass::Undefined;
		case 1U: return Corvus::Object::UserProcessBasePriorityClass::Idle;
		case 2U: return Corvus::Object::UserProcessBasePriorityClass::Normal;
		case 3U: return Corvus::Object::UserProcessBasePriorityClass::High;
		case 4U: return Corvus::Object::UserProcessBasePriorityClass::Realtime;
		case 5U: return Corvus::Object::UserProcessBasePriorityClass::BelowNormal;
		case 6U: return Corvus::Object::UserProcessBasePriorityClass::AboveNormal;
		default: return Corvus::Object::UserProcessBasePriorityClass::Undefined;
		}
	}

	Corvus::Object::ArchitectureType WindowsProviderNt::QueryArchitectureNt(HANDLE hProcess)
	{
		PVOID wow64Info{};
		NTSTATUS ntWow64InfoStatus{ NtQueryInformationProcess(
			hProcess,
			ProcessWow64Information,
			&wow64Info,
			sizeof(PVOID),
			nullptr) };

		if (!NT_SUCCESS(ntWow64InfoStatus))
			return Corvus::Object::ArchitectureType::Unknown;

		// nullptr = native process, Wow64 pointer = 32-bit process
		return (wow64Info != nullptr) ?
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
}