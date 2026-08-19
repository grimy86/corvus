#include "WindowsMemoryProvider.h"
#include "MuninnOpcodes.h"

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteVirtualMemory(
	HANDLE processHandle,
	uintptr_t address,
	const void* value,
	SIZE_T size)
{
	SIZE_T bytesWritten = 0ull;
	if (!WriteProcessMemory(
		processHandle,
		(LPVOID)address,
		value,
		size,
		&bytesWritten))
		return STATUS_UNSUCCESSFUL;

	if (bytesWritten != size)
		return STATUS_PARTIAL_COPY;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_WriteVirtualMemory(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t address,
	_In_ const void* const value,
	_In_ const SIZE_T size)
{
	return NtWriteVirtualMemory(
		processHandle,
		(PVOID)address,
		value,
		size,
		NULL);
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_ReadVirtualMemory(
	HANDLE processHandle,
	uintptr_t address,
	void* out,
	SIZE_T size)
{
	SIZE_T bytesRead = 0ull;
	if (!ReadProcessMemory(
		processHandle,
		(LPCVOID)address,
		out,
		size,
		&bytesRead))
		return STATUS_UNSUCCESSFUL;

	if (bytesRead != size)
		return STATUS_PARTIAL_COPY;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Nt_ReadVirtualMemory(
	_In_ const HANDLE processHandle,
	_In_ const uintptr_t address,
	_Out_ void* const out,
	_In_ const SIZE_T size)
{
	return NtReadVirtualMemory(
		processHandle,
		(PVOID)address,
		out,
		size,
		NULL);
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_PatchMemory(
	_In_ LPVOID const targetAddress,
	_In_ const BYTE* const patchBytes,
	_In_ SIZE_T size,
	_Out_opt_ BYTE* originalBytes)
{
	if (targetAddress == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (patchBytes == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (size == 0ul)
		return STATUS_INVALID_PARAMETER_3;

	DWORD pageProtection = 0ul;
	BOOL status = VirtualProtect(
		targetAddress,
		size,
		PAGE_EXECUTE_READWRITE,
		&pageProtection);

	if (!status)
		return STATUS_UNSUCCESSFUL;

	if (originalBytes != NULL)
		memcpy(originalBytes, targetAddress, size);

	memcpy(targetAddress, patchBytes, size);

	DWORD buffer = 0ul;
	status = VirtualProtect(
		targetAddress,
		size,
		pageProtection,
		&buffer);

	if (!status)
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteRelativeHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const detourAddress,
	_In_ SIZE_T const size,
	_Out_opt_ BYTE* originalBytes)
{
	if (targetAddress == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (detourAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (size < JMP_REL32_LENGTH)
		return STATUS_INVALID_PARAMETER_3;

	ptrdiff_t relativeOffset =
		(uintptr_t)detourAddress -
		((uintptr_t)targetAddress +
			JMP_REL32_LENGTH);

	// Ensure the offset fits within rel32 range (±2GB)
	if (relativeOffset < (ptrdiff_t)INT32_MIN ||
		relativeOffset >(ptrdiff_t)INT32_MAX)
		return STATUS_NOT_SUPPORTED;

	BYTE shellcode[32] = { 0 };
	memset(shellcode, NOP_OPCODE, size);
	shellcode[0] = JMP_REL32_OPCODE;
	memcpy(shellcode + 1, &relativeOffset, sizeof(DWORD));

	return DAL_Win32_PatchMemory(targetAddress, shellcode, size, originalBytes);
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteRelativeTrampolineHook(
	_In_  LPVOID const  targetAddress,
	_In_  LPVOID const  detourAddress,
	_In_  SIZE_T const  size,
	_Out_ LPVOID* const pGatewayOut)
{
	if (targetAddress == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (detourAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (size < JMP_REL32_LENGTH)
		return STATUS_INVALID_PARAMETER_3;
	if (pGatewayOut == NULL)
		return STATUS_INVALID_PARAMETER_4;

	BYTE* gateway = (BYTE*)VirtualAlloc(
		NULL,
		size + JMP_REL32_LENGTH,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (gateway == NULL)
		return STATUS_NO_MEMORY;

	// Copy stolen bytes to gateway
	memcpy(gateway, targetAddress, size);

	ptrdiff_t jumpBackOffset =
		(uintptr_t)targetAddress + size -
		((uintptr_t)gateway + size + JMP_REL32_LENGTH);

	// Ensure the offset fits within rel32 range (±2GB)
	if (jumpBackOffset < (ptrdiff_t)INT32_MIN ||
		jumpBackOffset >(ptrdiff_t)INT32_MAX)
	{
		VirtualFree(gateway, 0, MEM_RELEASE);
		return STATUS_NOT_SUPPORTED;
	}

	// Write jump back at end of stolen bytes
	gateway[size] = JMP_REL32_OPCODE;
	memcpy(gateway + size + 1, &jumpBackOffset, sizeof(DWORD));

	NTSTATUS status = DAL_Win32_WriteRelativeHook(
		targetAddress,
		detourAddress,
		size,
		NULL);

	if (!NT_SUCCESS(status))
	{
		VirtualFree(gateway, 0, MEM_RELEASE);
		return status;
	}

	*pGatewayOut = gateway;
	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreRelativeTrampolineHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const gatewayAddress,
	_In_ SIZE_T const size)
{
	if (targetAddress == NULL)
		return STATUS_INVALID_PARAMETER_1;
	if (gatewayAddress == NULL)
		return STATUS_INVALID_PARAMETER_2;
	if (size < JMP_REL32_LENGTH)
		return STATUS_INVALID_PARAMETER_3;

	// Restore original bytes from gateway back to target
	NTSTATUS status = DAL_Win32_PatchMemory(
		targetAddress,
		(BYTE*)gatewayAddress,
		size,
		NULL);

	if (!NT_SUCCESS(status))
		return status;

	// Free the gateway
	if (!VirtualFree(gatewayAddress, 0, MEM_RELEASE))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteAbsoluteHook(
	_In_ LPVOID const targetAddress,
	_In_ LPVOID const detourAddress,
	_In_ SIZE_T const size)
{
#ifndef _WIN64
	return STATUS_NOT_IMPLEMENTED;
#endif

	if (targetAddress == NULL)
		return STATUS_INVALID_PARAMETER_1;
	// Ensure address is canonical (user space, bits 63-48 must be zero)
	if ((uintptr_t)detourAddress >> 48 != 0)
		return STATUS_INVALID_PARAMETER_2;
	if (size < JMP_ABS64_LENGTH)
		return STATUS_INVALID_PARAMETER_3;

	BYTE shellcode[32] = { 0 };
	memset(shellcode, NOP_OPCODE, size);

	// FF 25 00000000 — JMP QWORD PTR [RIP+0]
	shellcode[0] = JMP_ABS64_OPCODE;
	shellcode[1] = JMP_ABS64_MODRM;

	// RIP-relative offset = 0
	memset(shellcode + 2, 0x00, sizeof(DWORD));

	// 8-byte absolute destination address
	memcpy(shellcode + 6, &detourAddress, sizeof(UINT64));

	return DAL_Win32_PatchMemory(targetAddress, shellcode, size, NULL);
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteVTableHook(
	_In_  LPVOID const  pObject,
	_In_  DWORD const   methodIndex,
	_In_  LPVOID const  hookAddress,
	_Out_ LPVOID* const pOriginalOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreVTableHook(
	_In_ LPVOID const pObject,
	_In_ DWORD const  methodIndex,
	_In_ LPVOID const originalAddress)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteInlineVTableHook(
	_In_  LPVOID const  vTableAddress,
	_In_  DWORD const   methodIndex,
	_In_  LPVOID const  hookAddress,
	_Out_ LPVOID* const pOriginalOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreInlineVTableHook(
	_In_ LPVOID const vTableAddress,
	_In_ DWORD const methodIndex,
	_In_ LPVOID const originalAddress)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteIATHook(
	_In_  const WCHAR* const moduleName,
	_In_  const WCHAR* const functionName,
	_In_  LPVOID const hookAddress,
	_Out_ LPVOID* const pOriginalOut)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreIATHook(
	_In_ LPCWSTR const moduleName,
	_In_ LPCWSTR const functionName,
	_In_ LPVOID const originalAddress)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_WriteHWBPHook(
	_In_ LPVOID const targetAddress,
	_In_ DWORD const condition,
	_In_ PVECTORED_EXCEPTION_HANDLER const veHandler)
{
	return STATUS_NOT_IMPLEMENTED;
}

MUNINN_API NTSTATUS MUNINN_CALL
DAL_Win32_RestoreHWBPHook(
	_In_ LPVOID const targetAddress,
	_In_ PVECTORED_EXCEPTION_HANDLER const veHandler)
{
	return STATUS_NOT_IMPLEMENTED;
}