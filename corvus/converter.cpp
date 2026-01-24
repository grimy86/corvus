#include "converter.hpp"
#include <windows.h>

namespace corvus::converter
{
	std::wstring StringToWString(const std::string& s)
	{
		if (s.empty())
			return {};

		// 1) Ask Windows: how many wide chars do I need?
		int len = MultiByteToWideChar(
			CP_UTF8,        // input is UTF-8
			0,
			s.c_str(),      // input string
			-1,             // null-terminated
			nullptr,        // no output yet
			0               // request required size
		);

		// 2) Allocate that many wchar_t (minus the null terminator)
		std::wstring out(len - 1, L'\0');

		// 3) Do the actual conversion
		MultiByteToWideChar(
			CP_UTF8,
			0,
			s.c_str(),
			-1,
			out.data(),
			len
		);

		return out;
	}


	std::string WStringToString(const std::wstring& ws)
	{
		if (ws.empty())
			return {};

		// 1) Ask Windows how many UTF-8 bytes we need
		int len = WideCharToMultiByte(
			CP_UTF8,        // output encoding
			0,
			ws.c_str(),     // input UTF-16
			-1,             // null-terminated
			nullptr,        // no output yet
			0,              // request required size
			nullptr,
			nullptr
		);

		// 2) Allocate (minus null terminator)
		std::string out(len - 1, '\0');

		// 3) Convert
		WideCharToMultiByte(
			CP_UTF8,
			0,
			ws.c_str(),
			-1,
			out.data(),
			len,
			nullptr,
			nullptr
		);

		return out;
	}

	const char* ArchitectureToString(corvus::process::Architecture arch)
	{
		switch (arch)
		{
		case corvus::process::Architecture::x86:
			return "x86";
		case corvus::process::Architecture::x64:
			return "x64";
		case corvus::process::Architecture::arm:
			return "ARM";
		case corvus::process::Architecture::arm64:
			return "ARM64";
		case corvus::process::Architecture::Native:
			return "Native";
		default:
			return "Unknown";
		}
	}
}