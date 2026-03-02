#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
#pragma region WRITE
	HANDLE OpenProcessHandleNt(const DWORD processId, const ACCESS_MASK accessMask);

	BOOL CloseHandleNt(const HANDLE handle);

	/// <summary>
	/// Handles are per-process, duplicating allows us to safely query objects from another process.
	/// </summary>
	/// <param name="sourceHandle"> The source handle to duplicate.
	/// This value is meaningful in the context of the source process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A duplicated handle from the source process. </returns>
	HANDLE DuplicateHandleNt(const HANDLE sourceHandle, const DWORD processId);

	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="accessMask"> The desired handle access mask. </param>
	/// <returns> A handle to the acess token of the process. </returns>
	HANDLE OpenProcessTokenHandleNt(const HANDLE hProcess, const ACCESS_MASK accessMask);

	template <typename T>
	NTSTATUS WriteVirtualMemoryNt(const HANDLE processHandle, const uintptr_t baseAddress, const T& value)
	{
		return NtWriteVirtualMemory(
			processHandle,
			reinterpret_cast<PVOID>(baseAddress),
			&value,
			sizeof(T),
			nullptr);
	}
#pragma endregion

#pragma region READ
	template <typename T>
	NTSTATUS ReadVirtualMemoryNt(const HANDLE processHandle, const uintptr_t baseAddress, T& out)
	{
		return NtReadVirtualMemory(
			processHandle,
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

	/// <param name="duplicatedHandle"> A kernel handle reference to query information about.
	/// The handle does not need to grant any specific access. </param>
	/// <param name="infoClass"> One of the values enumerated in OBJECT_INFORMATION_CLASS,
	/// which indicate the kind of object information to be retrieved. </param>
	/// <returns> The required buffer size for a NtQueryObject() call. </returns>
	DWORD GetQOBufferSizeNt(const HANDLE duplicatedHandle, const OBJECT_INFORMATION_CLASS& infoClass);
	DWORD GetQITBufferSizeNt(const HANDLE tokenHandle, const TOKEN_INFORMATION_CLASS& infoClass);

	std::wstring GetObjectNameNt(const HANDLE sourceHandle, const DWORD processId);
	std::wstring GetObjectTypeNameNt(const HANDLE sourceHandle, const DWORD processId);
	std::wstring GetRemoteUnicodeStringNt(
		const HANDLE processHandle,
		const UNICODE_STRING& unicodeString);

	PROCESS_EXTENDED_BASIC_INFORMATION GetProcessInformationNt(const HANDLE processHandle);
	BOOL GetProcessInformationObjectNt(const HANDLE processHandle, Corvus::Object::ProcessEntry& processEntry);

	/// <summary>
	/// Assigns extended native process information to a process entry object reference.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="processEntry"> A reference to the process entry object. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessInformationObjectExtendedNt(
		const HANDLE processHandle,
		const DWORD processId,
		Corvus::Object::ProcessEntry& processEntry);

	std::wstring GetImageFileNameNt(const HANDLE processHandle);
	std::wstring GetImageFileNameWin32Nt(const HANDLE processHandle);

	/// <param name="processHandle"> A handle to the process. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(const HANDLE processHandle);

	/// <param name="processInfo"> A reference to the process information. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(
		const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <summary>
	/// Gets the PEB base address and initializes processInfo reference.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processInfo"> A reference to the process information. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(
		const HANDLE processHandle,
		PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <param name="processHandle"> A handle to the process. </param>
	/// <returns> The PEB structure. </returns>
	PEB GetPebNt(const HANDLE processHandle);

	/// <summary>
	/// Gets the PEB structure and initializes the PEB base address reference.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> A reference to the PEB base address. </param>
	/// <returns> The PEB structure. </returns>
	PEB GetPebNt(
		const HANDLE processHandle,
		uintptr_t& pebBaseAddress);

	/// <summary>
	/// Internally calls the GetPebBaseAddressNt(processHandle) function.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <returns> The module base address of the process. </returns>
	uintptr_t GetModuleBaseAddressNt(const HANDLE processHandle);

	/// <summary>
	/// Initializes the PEB base address using processInfo instead of calling the GetPebBaseAddressNt() function.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processInfo"> The extended native process structure containing the PEB base address. </param>
	/// <returns> The module base address of the process. </returns>
	uintptr_t GetModuleBaseAddressNt(
		const HANDLE processHandle,
		const PROCESS_EXTENDED_BASIC_INFORMATION& processInfo);

	/// <summary>
	/// Initializes the PEB using ReadVirtualMemoryNt<PEB>(processHandle, pebBaseAddress, peb)
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> The PEB base address. </param>
	/// <returns></returns>
	uintptr_t GetModuleBaseAddressNt(
		const HANDLE processHandle,
		const uintptr_t pebBaseAddress);

	/// <summary>
	/// Directly uses the PEB from reference.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="pebBaseAddress"> The PEB base address. </param>
	/// <returns></returns>
	uintptr_t GetModuleBaseAddressNt(const HANDLE processHandle, const PEB& peb);

	/// <summary>
	/// IF ProcessWow64Information is not NULL, the process is running under WoW64 and is a 32-bit process.
	/// <para> If it is NULL, the process is running natively and is a 64-bit process. </para>
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <returns>
	/// Corvus::Object::ArchitectureType
	/// </returns>
	Corvus::Object::ArchitectureType GetArchitectureTypeNt(const HANDLE processHandle);

	std::vector<LDR_DATA_TABLE_ENTRY> GetProcessModulesNt(
		const HANDLE processHandle,
		const PEB& peb);

	/// <summary>
	/// Adds module entry objects to the list of module entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="peb"> A const reference to the PEB. </param>
	/// <param name="modules"> A reference to the list of module entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessModuleObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		const PEB& peb,
		std::vector<Corvus::Object::ModuleEntry>& modules);

	std::vector<SYSTEM_THREAD_INFORMATION> GetProcessThreadsNt(
		const HANDLE processHandle,
		const DWORD processId);

	/// <summary>
	/// EXPERIMENTAL: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A list of SYSTEM_EXTENDED_THREAD_INFORMATION objects. </returns>
	[[deprecated("Uses experimental NT structure: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.")]]
	std::vector<SYSTEM_EXTENDED_THREAD_INFORMATION> GetProcessThreadsExtendedNt(
		const HANDLE processHandle,
		const DWORD processId);

	/// <summary>
	/// Adds thread entry objects to the list of thread entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="threads"> A reference to the list of thread entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessThreadObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads);

	/// <summary>
	/// Initializes the win32ThreadStartAddress and the tebBaseAddress.
	/// <para> EXPERIMENTAL: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION. </para>
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A list of ThreadEntry objects. </returns>
	[[deprecated("Uses experimental NT structure: SYSTEM_EXTENDED_THREAD_INFORMATION @ SYSTEM_PROCESS_INFORMATION.")]]
	BOOL GetProcessThreadObjectsExtendedNt(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Corvus::Object::ThreadEntry>& threads);

	std::vector<SYSTEM_HANDLE_TABLE_ENTRY_INFO> GetProcessHandlesNt(
		const HANDLE processHandle,
		const DWORD processId);

	/// <summary>
	/// Adds handle entry objects to the list of handle entry objects.
	/// <para> Does not do any kind of validation on the list. </para>
	/// </summary>
	/// <param name="processHandle"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <param name="handles"> A reference to the list of handle entry objects. </param>
	/// <returns> TRUE if all values are sucessfully assigned. </returns>
	BOOL GetProcessHandleObjectsNt(
		const HANDLE processHandle,
		const DWORD processId,
		std::vector<Corvus::Object::HandleEntry>& handles);

	TOKEN_STATISTICS GetProcessTokenStatisticsNt(const HANDLE tokenHandle);
	std::vector<LUID_AND_ATTRIBUTES> GetProcessTokenPriviligesNt(const HANDLE tokenHandle);

	BOOL GetProcessTokenPriviligeObjectsNt(
		const HANDLE tokenHandle,
		std::vector<Corvus::Object::PrivilegeEntry>& privileges);

	/// <summary>
	/// Requires SeTcbPrivilege.
	/// </summary>
	/// <param name="tokenHandle"> A handle to the token. </param>
	/// <returns> The session ID of the token. </returns>
	DWORD GetProcessTokenSessionIdNt(const HANDLE tokenHandle);
#pragma endregion
}