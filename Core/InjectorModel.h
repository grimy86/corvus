#pragma once
#include <Windows.h>

namespace Muninn::Model
{
	struct InjectorModel
	{
		bool IsInjected{ false };
		LPCSTR DllPathA{ nullptr };
		LPWSTR DllPathW{ nullptr };
		HMODULE ModuleHandle{ nullptr };
		// HANDLE InjectionThreadHandle{ nullptr };
	};
}