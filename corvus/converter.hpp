#pragma once
#include <string>
#include "process.hpp"


namespace corvus::converter
{
	std::wstring StringToWString(const std::string& string);
	std::string WStringToString(const std::wstring& wstring);
	const char* ArchitectureToString(corvus::process::ArchitectureType arch);
}