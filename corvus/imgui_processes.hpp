#pragma once
#include <vector>
#include <imgui.h>
#include <TlHelp32.h>
#include "process.hpp"
#include "converter.hpp"

namespace corvus::imgui
{
	// =====================
	// Shared state
	// =====================
	inline DWORD g_SelectedPid = 0;
	inline std::vector<corvus::process::ProcessInfo> g_ProcessCache;

	// =====================
	// Process List
	// =====================
	inline void DrawProcessList()
	{
		if (g_ProcessCache.empty())
			g_ProcessCache = corvus::process::EnumerateProcesses(true);

		if (ImGui::Button("Refresh"))
		{
			g_ProcessCache = corvus::process::EnumerateProcesses(true);
			g_SelectedPid = 0;
		}

		ImGui::Separator();

		if (ImGui::BeginTable(
			"process_table",
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Name");
			ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableHeadersRow();

			for (const auto& proc : g_ProcessCache)
			{
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				if (ImGui::Selectable(
					std::to_string(proc.pid).c_str(),
					g_SelectedPid == proc.pid,
					ImGuiSelectableFlags_SpanAllColumns))
				{
					g_SelectedPid = proc.pid;
				}

				ImGui::TableSetColumnIndex(1);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(proc.exeName).c_str());

				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(proc.isWow64 ? "x86" : "x64");
			}

			ImGui::EndTable();
		}
	}

	// =====================
	// Modules View
	// =====================
	inline void DrawModulesView()
	{
		if (g_SelectedPid == 0)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		// Detect architecture mismatch
		BOOL targetWow64 = FALSE;
		HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_SelectedPid);
		if (hProc)
		{
			IsWow64Process(hProc, &targetWow64);
			CloseHandle(hProc);
		}

#ifdef _WIN64
		const bool toolIsWow64 = false;
#else
		const bool toolIsWow64 = true;
#endif

		if (toolIsWow64 && !targetWow64)
		{
			ImGui::TextColored(
				ImVec4(1, 0.4f, 0.4f, 1),
				"Cannot enumerate 64-bit modules from a 32-bit build");
			ImGui::TextDisabled("Build this tool as x64 to fix this");
			return;
		}

		HANDLE snap = CreateToolhelp32Snapshot(
			TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
			g_SelectedPid);

		if (snap == INVALID_HANDLE_VALUE)
		{
			ImGui::Text("CreateToolhelp32Snapshot failed (err=%lu)", GetLastError());
			return;
		}

		MODULEENTRY32W me{};
		me.dwSize = sizeof(me);

		if (!Module32FirstW(snap, &me))
		{
			ImGui::Text("Module32FirstW failed (err=%lu)", GetLastError());
			CloseHandle(snap);
			return;
		}

		if (ImGui::BeginTable(
			"modules_table",
			4,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 110);
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90);
			ImGui::TableSetupColumn("Name");
			ImGui::TableSetupColumn("Path");
			ImGui::TableHeadersRow();

			do
			{
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%p", me.modBaseAddr);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%lu", me.modBaseSize);

				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(me.szModule).c_str());

				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(me.szExePath).c_str());

			} while (Module32NextW(snap, &me));

			ImGui::EndTable();
		}

		CloseHandle(snap);
	}

	// =====================
	// Threads View
	// =====================
	inline void DrawThreadsView()
	{
		if (g_SelectedPid == 0)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (snap == INVALID_HANDLE_VALUE)
		{
			ImGui::TextDisabled("Failed to enumerate threads");
			return;
		}

		THREADENTRY32 te{};
		te.dwSize = sizeof(te);

		if (ImGui::BeginTable(
			"threads_table",
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 90);
			ImGui::TableSetupColumn("Owner PID", ImGuiTableColumnFlags_WidthFixed, 90);
			ImGui::TableSetupColumn("Base Priority");
			ImGui::TableHeadersRow();

			if (Thread32First(snap, &te))
			{
				do
				{
					if (te.th32OwnerProcessID != g_SelectedPid)
						continue;

					ImGui::TableNextRow();

					ImGui::TableSetColumnIndex(0);
					ImGui::Text("%lu", te.th32ThreadID);

					ImGui::TableSetColumnIndex(1);
					ImGui::Text("%lu", te.th32OwnerProcessID);

					ImGui::TableSetColumnIndex(2);
					ImGui::Text("%ld", te.tpBasePri);

				} while (Thread32Next(snap, &te));
			}

			ImGui::EndTable();
		}

		CloseHandle(snap);
	}

	// =====================
	// Handles View (stub)
	// =====================
	inline void DrawHandlesView()
	{
		if (g_SelectedPid == 0)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		ImGui::TextDisabled(
			"Handles view requires NtQuerySystemInformation\n"
			"(will be implemented later)");
	}
}
