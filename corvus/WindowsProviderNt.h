#pragma once
#include "WindowsStructures.h"

namespace Corvus::Data
{
	HANDLE OpenProcessHandleNt(DWORD processId, ACCESS_MASK accessMask);
	BOOL CloseProcessHandleNt(HANDLE handle);

	std::wstring ReadRemoteUnicodeStringNt(
		HANDLE hProcess,
		const UNICODE_STRING& unicodeString);

	PROCESS_EXTENDED_BASIC_INFORMATION GetProcessInformationNt(HANDLE hProcess);
	std::wstring GetImageFileNameNt(HANDLE hProcess);
	std::wstring GetImageFileNameWin32Nt(HANDLE hProcess);

	/// <summary>
	/// Gets the PEB base address.
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns> The PEB base address. </returns>
	uintptr_t GetPebBaseAddressNt(HANDLE hProcess);

	/// <summary>
	/// Gets the PEB base address.
	/// </summary>
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

	/// <summary>
	/// Gets the PEB structure.
	/// </summary>
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
	/// Calls GetPebBaseAddressNt(hProcess)
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns> The module base address of the process. </returns>
	uintptr_t GetModuleBaseAddressNt(HANDLE hProcess);

	/// <summary>
	/// Initializes the PEB base address using processInfo instead of calling GetPebBaseAddressNt().
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

	std::vector<Corvus::Object::ModuleEntry> GetProcessModulesNt(
		HANDLE hProcess,
		DWORD processId,
		const PEB& peb);

	std::vector<SYSTEM_THREAD_INFORMATION> GetProcessThreadsNt(
		HANDLE hProcess,
		DWORD processId);

	std::vector<Corvus::Object::ThreadEntry> GetProcessThreadObjectsNt(
		HANDLE hProcess,
		DWORD processId);

	/// <summary>
	/// Initializes the win32ThreadStartAddress.
	/// <para> EXPERIMENTAL @ SYSTEM_PROCESS_INFORMATION</para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <param name="processId"> The unique process identifier. </param>
	/// <returns> A list of ThreadEntry objects. </returns>
	std::vector<Corvus::Object::ThreadEntry> GetExtendedProcessThreadObjectsNt(
		HANDLE hProcess,
		DWORD processId);

	/// <summary>
	/// IF ProcessWow64Information is not NULL, the process is running under WoW64 and is a 32-bit process.
	/// <para> If it is NULL, the process is running natively and is a 64-bit process. </para>
	/// </summary>
	/// <param name="hProcess"> A handle to the process. </param>
	/// <returns>
	/// Corvus::Object::ArchitectureType
	/// </returns>
	Corvus::Object::ArchitectureType GetArchitectureTypeNt(HANDLE hProcess);




	DWORD GetQSIBufferSizeNt(const SYSTEM_INFORMATION_CLASS sInfoClass);
	std::wstring GetRemoteUnicodeStringNt(HANDLE hProcess, const UNICODE_STRING& unicodeString);

	uintptr_t GetModuleBaseAddressNt(DWORD processId, const std::wstring& processName);
	Corvus::Object::ArchitectureType GetArchitectureTypeNt(HANDLE hProcess);
	std::wstring GetObjectNameNt(HANDLE hObject, DWORD processId);
	std::wstring GetObjectTypeNameNt(HANDLE hObject, DWORD processId);
	BOOL GetModuleInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL GetThreadInformation(Corvus::Object::ProcessEntry& processEntry);
	BOOL GetHandleInformation(Corvus::Object::ProcessEntry& processEntry);

	template <typename T>
	NTSTATUS SetVirtualMemoryNt(HANDLE hProc, uintptr_t baseAddress, const T& value)
	{
		return WriteVirtualMemoryNt(
			hProc,
			reinterpret_cast<PVOID>(baseAddress),
			&value,
			sizeof(T),
			nullptr);
	}

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
}