#pragma once
#include <Windows.h>
#include <string>
#include "process.hpp"

namespace corvus::injection
{
	BOOL Inject(const std::wstring& dllPath, const corvus::process::WIN32Process& proc);
}