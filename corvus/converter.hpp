#pragma once
#include <string>
#include <windows.h>

namespace corvus::converter
{
    std::wstring StringToWString(const std::string& string);
    std::string WStringToString(const std::wstring& wstring);
}