#pragma once
#include <string>
#include "win32_process.hpp"


namespace corvus::converter
{
	std::wstring StringToWString(const std::string& string);
	std::string WStringToString(const std::wstring& wstring);
	const char* ArchitectureToString(corvus::process::Architecture arch);
}