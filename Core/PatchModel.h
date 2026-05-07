#pragma once
#include <Windows.h>

namespace Muninn::Model
{
	enum class PatchType : int
	{
		Detour,      // Overwrites target bytes with a JMP to a hook function, execution does not return to original
		Trampoline,  // Overwrites target bytes with a JMP to a hook function, stolen bytes are preserved in a gateway so original can still be called
		Patch,       // Overwrites target bytes with arbitrary shellcode, no hook function involved
		VTable,      // Overwrites a single object instance's vtable pointer to redirect virtual function calls
		VTableInline,// Overwrites the vtable itself, affects all instances of the class
		IAT,         // Overwrites the import address table entry for a function, redirects all calls to an imported DLL function
		HWBP         // Uses x86 debug registers (DR0-DR3) to trigger an exception on access/execution, handled via VEH. Zero bytes written to target.
	};

	struct PatchModel
	{
		LPVOID targetAddress;
		LPVOID hookAddress;
		LPVOID gateway;
		SIZE_T size;
		BYTE* originalBytes;
		BYTE* patchBytes;
		PatchType type = PatchType::Detour;
		BOOL ownsOriginalBytes = FALSE;
	};
}