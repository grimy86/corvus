#include "converter.hpp"

namespace corvus::converter
{
    std::wstring StringToWString(const std::string& string)
    {
        if (string.empty())
            return {};

        int size = MultiByteToWideChar(
            CP_UTF8, 0,
            string.c_str(), -1,
            nullptr, 0
        );

        std::wstring result(size - 1, 0);
        MultiByteToWideChar(
            CP_UTF8, 0,
            string.c_str(), -1,
            result.data(), size
        );

        return result;
    }

    std::string WStringToString(const std::wstring& wstring)
    {
        if (wstring.empty())
            return {};

        int size = WideCharToMultiByte(
            CP_UTF8, 0,
            wstring.c_str(), -1,
            nullptr, 0,
            nullptr, nullptr
        );

        std::string result(size - 1, 0);
        WideCharToMultiByte(
            CP_UTF8, 0,
            wstring.c_str(), -1,
            result.data(), size,
            nullptr, nullptr
        );

        return result;
    }
}