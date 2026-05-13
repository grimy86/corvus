#pragma once
#include <Windows.h>

namespace Muninn::Model
{
	enum class PatchType : int
	{
		/// <summary>
		/// Overwrites target bytes with a JMP to a hook function,
		/// execution does not return to original.
		/// </summary>
		Detour,
		
		/// <summary>
		/// Overwrites target bytes with a JMP to a hook function,
		/// stolen bytes are preserved in a gateway so original
		/// can still be called.
		/// </summary>
		Trampoline,
		
		/// <summary>
		/// Overwrites target bytes with arbitrary shellcode,
		/// no hook function involved.
		/// </summary>
		Patch,
		
		/// <summary>
		/// Overwrites a single object instance's vtable pointer
		/// to redirect virtual function calls.
		/// </summary>
		VTable,
		
		/// <summary>
		/// Overwrites the vtable itself,
		/// affects all instances of the class.
		/// </summary>
		VTableInline,
		
		/// <summary>
		/// Overwrites the import address table entry for a function,
		/// redirects all calls to an imported DLL function.
		/// </summary>
		IAT,
		
		/// <summary>
		/// Uses x86 debug registers (DR0-DR3) to 
		/// trigger an exception on access/execution,
		/// handled via VEH.
		/// Zero bytes written to target.
		/// </summary>
		HWBP
	};

	/// <summary>
	/// A state machine for tracking the lifecycle of the Patch's original bytes ownership.
	/// </summary>
	enum class ByteOwnership : int
	{
		UserProvided,
		Internal
	};

	/// <summary>
	/// Holds all data needed to manage a single patch operation.
	/// </summary>
	struct PatchModel
	{
		/// <summary>
		/// Address in memory that will be patched.
		/// </summary>
		LPVOID targetAddress = nullptr;

		/// <summary>
		/// Address of the hook function to redirect execution to.
		/// </summary>
		LPVOID hookAddress = nullptr;

		/// <summary>
		/// Pointer to the gateway buffer holding stolen bytes.
		/// Used by PatchType::Trampoline to allow calling the original function.
		/// </summary>
		LPVOID gateway = nullptr;

		/// <summary>
		/// Pointer to the original function before patching.
		/// </summary>
		LPVOID originalFunction = nullptr;

		/// <summary>
		/// Pointer to the vtable slot that was overwritten.
		/// </summary>
		LPVOID* vtableEntry = nullptr;

		/// <summary>
		/// Number of bytes affected by the patch.
		/// </summary>
		SIZE_T size = 0;

		/// <summary>
		/// Buffer holding the original bytes before patching.
		/// Used for restoration.
		/// </summary>
		BYTE* originalBytes = nullptr;

		/// <summary>
		/// Buffer holding the (shellcode) bytes to write during patching.
		/// </summary>
		BYTE* patchBytes = nullptr;

		/// <summary>
		/// The type of patch this model represents.
		/// Determines which fields are valid and how the patch is applied.
		/// </summary>
		PatchType type = PatchType::Detour;

		/// <summary>
		/// Determines who owns the original bytes.
		/// </summary>
		ByteOwnership byteOwnership = ByteOwnership::UserProvided;
	};
}