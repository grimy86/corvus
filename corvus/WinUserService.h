#pragma once
#include <WinUser.h>
#include <string>

namespace Muninn::View
{
	BOOL ShowMessageBox(
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
}