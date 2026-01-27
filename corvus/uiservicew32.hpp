#pragma once
#include <WinUser.h>
#include <string>

class UIServiceW32
{
private:
	UIServiceW32() = delete;

public:
	inline static BOOL ShowMessageBoxWW32(
		const std::wstring& text,
		const std::wstring& title,
		UINT MB_Type = MB_OK)
	{
		return ::MessageBoxW(
			nullptr,
			text.c_str(),
			title.c_str(),
			MB_Type);
	}
};