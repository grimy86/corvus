#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
#pragma region WRITE
	HANDLE OpenProcessHandleNt(DWORD processId, ACCESS_MASK accessMask);

	BOOL CloseHandleNt(HANDLE handle);

	/// <summary>
	/// Handles are per-process, duplicating allows us to safely query objects from another process.
	/// </summary>
	/// <param name="sourceHandle"> The source handle to duplicate.
	/// This value is meaningful in the context of the source process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A duplicated handle from the source process. </returns>
	HANDLE DuplicateHandleNt(HANDLE sourceHandle, DWORD processId);

	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="accessMask"> The desired handle access mask. </param>
	/// <returns> A handle to the acess token of the process. </returns>
	HANDLE OpenProcessTokenHandleNt(HANDLE hProcess, ACCESS_MASK accessMask);

	template <typename T>
	NTSTATUS WriteVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress, const T& value)
	{
		return WriteVirtualMemoryNt(
			hProc,
			reinterpret_cast<PVOID>(baseAddress),
			&value,
			sizeof(T),
			nullptr);
	}
#pragma endregion

#pragma region READ
	template <typename T>
	NTSTATUS ReadVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress, T& out)
	{
		return NtReadVirtualMemory(
			hProc,
			reinterpret_cast<PVOID>(baseAddress),
			&out,
			sizeof(T),
			nullptr);
	}

	uint64_t GetFullLuidNt(const LUID& luid);

	/// <param name="infoClass"> One of the values enumerated in SYSTEM_INFORMATION_CLASS,
	/// which indicate the kind of system information to be retrieved. </param>
	/// <returns> The required buffer size for a NtQuerySystemInformation() call. </returns>
	DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS& infoClass);

	/// <param name="duplicateHandle"> A kernel handle reference to query information about.
	/// The handle does not need to grant any specific access. </param>
	/// <param name="infoClass"> One of the values enumerated in OBJECT_INFORMATION_CLASS,
	/// which indicate the kind of object information to be retrieved. </param>
	/// <returns> The required buffer size for a NtQueryObject() call. </returns>
	DWORD GetQOBufferSizeNt(HANDLE duplicateHandle, const OBJECT_INFORMATION_CLASS& infoClass);
	DWORD GetQITBufferSizeNt(HANDLE tokenHandle, const TOKEN_INFORMATION_CLASS& infoClass);

	std::wstring GetObjectNameNt(HANDLE sourceHandle, DWORD processId);
	std::wstring GetObjectTypeNameNt(HANDLE sourceHandle, DWORD processId);
	std::wstring GetRemoteUnicodeStringNt(
		HANDLE hProcess,
		const UNICODE_STRING& unicodeString);

	PROCESS_EXTENDED_BASIC_INFORMATION GetProcessInformationNt(HANDLE hProcess);
	BOOL GetProcessInformationObjectNt(HANDLE hProcess, Corvus::Object::ProcessEntry& processEntry);

	/// <summary>
	/// Assigns extended native process information to a process entry object reference.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="processEntry"> A reference to the process entry object. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessInformationObjectExtendedNt(HANDLE hProcess, DWORD processId, Corvus::Object::ProcessEntry& processEntry);
	std::wstring GetImageFileNameNt(HANDLE hProcess);
	std::wstring GetImageFileNameWin32Nt(HANDLE hProcess);

	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(HANDLE hProcess);

	/// <param name="processInfo"> A reference to the process information. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(
		const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <summary>
	/// Gets the PEB base address and initializes processInfo reference.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processInfo"> A reference to the process information. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(
		HANDLE hProcess,
		PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns> The PEB structure. </returns>
	PEB GetPebNt(HANDLE hProcess);

	/// <summary>
	/// Gets the PEB structure and initializes the PEB base address reference.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> A reference to the PEB base address. </param>
	/// <returns> The PEB structure. </returns>
	PEB GetPebNt(
		HANDLE hProcess,
		uintptr_t& pebBaseAddress);

	/// <summary>
	/// Internally calls the GetPebBaseAddressNt(hProcess) function.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns> The module base address of the process. </returns>
	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess);

	/// <summary>
	/// Initializes the PEB base address using processInfo instead of calling the GetPebBaseAddressNt() function.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processInfo"> The extended native process structure containing the PEB base address. </param>
	/// <returns> The module base address of the process. </returns>
	uintptr_t GetModuleBaseAddressNt(
		HANDLE hProcess,
		const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <summary>
	/// Initializes the PEB using ReadVirtualMemoryNt<PEB>(hProcess, pebBaseAddress, peb)
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> The PEB base address. </param>
	/// <returns></returns>
	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess, uintptr_t pebBaseAddress);

	/// <summary>
	/// Directly uses the PEB from reference.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> The PEB base address. </param>
	/// <returns></returns>
	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess, const PEB& peb);

	std::vector<LDR_DATA_TABLE_ENTRY> GetProcessModulesNt(
		HANDLE hProcess,
		const PEB& peb);

	/// <summary>
	/// IF ProcessWow64Information is not NULL, the process is running under WoW64 and is a 32-bit process.
	/// <para> If it is NULL, the process is running natively and is a 64-bit process. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns>
	/// Corvus::Object::ArchitectureType
	/// </returns>
	Corvus::Object::ArchitectureType GetArchitectureTypeNt(HANDLE hProcess);

	/// <summary>
	/// Adds module entry objects to the list of module entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="peb"> A const reference to the PEB. </param>
	/// <param name="modules"> A reference to the list of module entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessModuleObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		const PEB& peb,
		std::vector<Corvus::Object::ModuleEntry>& modules);

	std::vector<SYSTEM_THREAD_INFORMATION> GetProcessThreadsNt(
		HANDLE hProcess,
		DWORD processId);

	/// <summary>
	/// EXPERIMENTAL: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A list of SYSTEM_EXTENDED_THREAD_INFORMATION objects. </returns>
	[[deprecated("Uses experimental NT structure: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.")]]
	std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> GetProcessThreadsExtendedNt(
		HANDLE hProcess,
		DWORD processId);

	/// <summary>
	/// Adds thread entry objects to the list of thread entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="threads"> A reference to the list of thread entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessThreadObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads);

	/// <summary>
	/// Initializes the win32ThreadStartAddress and the tebBaseAddress.
	/// <para> EXPERIMENTAL: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A list of ThreadEntry objects. </returns>
	[[deprecated("Uses experimental NT structure: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.")]]
	BOOL GetProcessThreadObjectsExtendedNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads);

	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetProcessHandlesNt(
		HANDLE hProcess,
		DWORD processId);

	/// <summary>
	/// Adds handle entry objects to the list of handle entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="handles"> A reference to the list of handle entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessHandleObjectsNt(
		HANDLE hProcess,
		DWORD processId,
		std::vector<Corvus::Object::HandleEntry>& handles);

	TOKEN_STATISTICS GetProcessTokenStatisticsNt(HANDLE tokenHandle);
	std::vector<LUID_AND_ATTRIBUTES> GetProcessTokenPriviligesNt(HANDLE tokenHandle);

	BOOL GetProcessTokenPriviligeObjectsNt(
		HANDLE tokenHandle,
		std::vector<Corvus::Object::PrivilegeEntry>& privileges);

	/// <summary>
	/// Requires SeTcbPrivilege.
	/// </summary>
	/// <param name="tokenHandle"> A handle to the token. </param>
	/// <returns> The session ID of the token. </returns>
	DWORD GetProcessTokenSessionIdNt(HANDLE tokenHandle);

#pragma endregion
}