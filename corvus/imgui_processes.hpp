#pragma once
#include <imgui.h>
#include <memory>
#include <vector>
#include <algorithm>

#include "process.hpp"
#include "converter.hpp"

namespace corvus::imgui
{
	// ============================================================
	// External UI state (owned by root UI)
	// ============================================================
	extern std::atomic<bool> g_loading;
	extern bool g_hasLoadedProcesses;

	// ============================================================
	// Shared state (populated by loader thread)
	// ============================================================
	inline std::vector<corvus::process::WindowsProcessWin32> g_ProcessCache;
	inline std::vector<corvus::process::WindowsProcessNt>    g_ProcessCacheNt;

	inline std::shared_ptr<corvus::process::WindowsProcessWin32> g_SelectedProcess;
	inline std::shared_ptr<corvus::process::WindowsProcessNt>    g_SelectedProcessNt;

	// ============================================================
	// Loading API (CALLED BY LOADER THREAD ONLY)
	// ============================================================
	inline void LoadProcessList()
	{
		g_ProcessCache = corvus::process::WindowsProcessWin32::GetProcessListW32();
		g_ProcessCacheNt = corvus::process::WindowsProcessNt::GetProcessListNt();

		g_SelectedProcess.reset();
		g_SelectedProcessNt.reset();
	}

	// ============================================================
	// Helpers
	// ============================================================
	inline void DrawSectionHeader(const char* label)
	{
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);
		ImGui::TextDisabled(label);
	}

	inline void DrawProcessRowWin32(corvus::process::WindowsProcessWin32& proc)
	{
		ImGui::TableNextRow();

		const bool selected =
			g_SelectedProcess &&
			g_SelectedProcess->GetProcessId() == proc.GetProcessId();

		ImGui::TableSetColumnIndex(0);
		if (ImGui::Selectable(
			std::to_string(proc.GetProcessId()).c_str(),
			selected,
			ImGuiSelectableFlags_SpanAllColumns))
		{
			g_SelectedProcess = std::make_shared<corvus::process::WindowsProcessWin32>(proc);
			g_SelectedProcessNt.reset();
		}

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(
			corvus::converter::WStringToString(proc.GetName()).c_str());

		ImGui::TableSetColumnIndex(2);
		ImGui::TextUnformatted(
			corvus::converter::ArchitectureToString(proc.GetArchitecture()));
	}

	inline void DrawProcessRowNt(corvus::process::WindowsProcessNt& proc)
	{
		ImGui::TableNextRow();

		const bool selected =
			g_SelectedProcessNt &&
			g_SelectedProcessNt->GetProcessId() == proc.GetProcessId();

		ImGui::TableSetColumnIndex(0);
		if (ImGui::Selectable(
			std::to_string(proc.GetProcessId()).c_str(),
			selected,
			ImGuiSelectableFlags_SpanAllColumns))
		{
			g_SelectedProcessNt = std::make_shared<corvus::process::WindowsProcessNt>(proc);
			g_SelectedProcess.reset();
		}

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(
			corvus::converter::WStringToString(proc.GetName()).c_str());
	}

	// ============================================================
	// Win32 Process List
	// ============================================================
	inline void DrawProcessList()
	{
		if (ImGui::Button("Refresh") && !g_loading)
		{
			// request reload — actual thread is owned elsewhere
			g_hasLoadedProcesses = false;
		}

		ImGui::Separator();

		if (g_ProcessCache.empty())
		{
			ImGui::TextDisabled("No process data available");
			return;
		}

		std::vector<std::reference_wrapper<corvus::process::WindowsProcessWin32>> foreground;
		std::vector<std::reference_wrapper<corvus::process::WindowsProcessWin32>> background;

		for (auto& proc : g_ProcessCache)
		{
			if (proc.HasVisibleWindow())
				foreground.emplace_back(proc);
			else
				background.emplace_back(proc);
		}

		if (ImGui::BeginTable(
			"process_table_w32",
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 150.0f);
			ImGui::TableSetupColumn("Process Name", ImGuiTableColumnFlags_WidthStretch, 220.0f);
			ImGui::TableSetupColumn("CPU ISA", ImGuiTableColumnFlags_WidthStretch, 100.0f);

			ImGui::TableHeadersRow();

			if (!foreground.empty())
			{
				DrawSectionHeader("Windowed Processes");
				for (auto& proc : foreground)
					DrawProcessRowWin32(proc.get());
			}

			if (!background.empty())
			{
				DrawSectionHeader("Background Processes");
				for (auto& proc : background)
					DrawProcessRowWin32(proc.get());
			}

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Native NT Process List (visual only)
	// ============================================================
	inline void DrawProcessListNt()
	{
		ImGui::Separator();

		if (g_ProcessCacheNt.empty())
		{
			ImGui::TextDisabled("No native process data available");
			return;
		}

		if (ImGui::BeginTable(
			"process_table_nt",
			2,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Image Name", ImGuiTableColumnFlags_WidthStretch, 300.0f);

			ImGui::TableHeadersRow();

			for (auto& proc : g_ProcessCacheNt)
				DrawProcessRowNt(proc);

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Modules View
	// ============================================================
	inline void DrawModulesView()
	{
		if (!g_SelectedProcess)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& modules = g_SelectedProcess->GetModules();

		if (ImGui::BeginTable(
			"modules_table",
			8,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Image Size", ImGuiTableColumnFlags_WidthFixed, 100.0f);
			ImGui::TableSetupColumn("Entry", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 60.0f);
			ImGui::TableSetupColumn("Load Cnt (G)", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Load Cnt (P)", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch, 200.0f);

			ImGui::TableHeadersRow();

			for (const auto& m : modules)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("0x%p", (void*)m.baseAddress);
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llu", (unsigned long long)m.size);
				ImGui::TableSetColumnIndex(2); ImGui::Text("%llu", (unsigned long long)m.moduleBaseSize);
				ImGui::TableSetColumnIndex(3); ImGui::Text("0x%p", m.entryPoint);
				ImGui::TableSetColumnIndex(4); ImGui::Text("%lu", m.processId);
				ImGui::TableSetColumnIndex(5); ImGui::Text("%lu", m.globalLoadCount);
				ImGui::TableSetColumnIndex(6); ImGui::Text("%lu", m.processLoadCount);
				ImGui::TableSetColumnIndex(7);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(m.moduleName).c_str());
			}

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Threads View
	// ============================================================
	inline void DrawThreadsView()
	{
		if (!g_SelectedProcess)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& threads = g_SelectedProcess->GetThreads();

		if (ImGui::BeginTable(
			"threads_table",
			7,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Usage", ImGuiTableColumnFlags_WidthFixed, 70.0f);
			ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Owner PID", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Base Pri", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Delta Pri", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthStretch, 100.0f);

			ImGui::TableHeadersRow();

			for (const auto& t : threads)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("%llu", (unsigned long long)t.size);
				ImGui::TableSetColumnIndex(1); ImGui::Text("%lu", t.cntUsage);
				ImGui::TableSetColumnIndex(2); ImGui::Text("%lu", t.threadId);
				ImGui::TableSetColumnIndex(3); ImGui::Text("%lu", t.ownerProcessId);
				ImGui::TableSetColumnIndex(4); ImGui::Text("%ld", t.basePriority);
				ImGui::TableSetColumnIndex(5); ImGui::Text("%ld", t.deltaPriority);
				ImGui::TableSetColumnIndex(6); ImGui::Text("0x%08lX", t.flags);
			}

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Handles View
	// ============================================================
	inline void DrawHandlesView()
	{
		if (!g_SelectedProcess)
		{
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& handles = g_SelectedProcess->GetHandles();

		if (ImGui::BeginTable(
			"handles_table",
			12,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 100.0f);
			ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 60.0f);
			ImGui::TableSetupColumn("Type Name", ImGuiTableColumnFlags_WidthStretch, 140.0f);
			ImGui::TableSetupColumn("Object", ImGuiTableColumnFlags_WidthStretch, 200.0f);
			ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 70.0f);
			ImGui::TableSetupColumn("Attrib", ImGuiTableColumnFlags_WidthFixed, 70.0f);
			ImGui::TableSetupColumn("Handles", ImGuiTableColumnFlags_WidthFixed, 70.0f);
			ImGui::TableSetupColumn("Ptrs", ImGuiTableColumnFlags_WidthFixed, 60.0f);
			ImGui::TableSetupColumn("Paged", ImGuiTableColumnFlags_WidthFixed, 70.0f);
			ImGui::TableSetupColumn("NonPaged", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Lengths", ImGuiTableColumnFlags_WidthFixed, 80.0f);

			ImGui::TableHeadersRow();

			for (const auto& h : handles)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);  ImGui::Text("0x%p", h.handle);
				ImGui::TableSetColumnIndex(1);  ImGui::Text("%u", (unsigned)h.objectType);
				ImGui::TableSetColumnIndex(2);  ImGui::TextUnformatted(corvus::converter::WStringToString(h.TypeName).c_str());
				ImGui::TableSetColumnIndex(3);  ImGui::TextUnformatted(corvus::converter::WStringToString(h.ObjectName).c_str());
				ImGui::TableSetColumnIndex(4);  ImGui::Text("0x%08lX", h.GrantedAccess);
				ImGui::TableSetColumnIndex(5);  ImGui::Text("0x%08lX", h.flags);
				ImGui::TableSetColumnIndex(6);  ImGui::Text("0x%08lX", h.Attributes);
				ImGui::TableSetColumnIndex(7);  ImGui::Text("%lu", h.HandleCount);
				ImGui::TableSetColumnIndex(8);  ImGui::Text("%lu", h.PointerCount);
				ImGui::TableSetColumnIndex(9);  ImGui::Text("%lu", h.PagedPoolCharge);
				ImGui::TableSetColumnIndex(10); ImGui::Text("%lu", h.NonPagedPoolCharge);
				ImGui::TableSetColumnIndex(11); ImGui::Text("%hu / %hu", h.TypeNameLength, h.ObjectNameLength);
			}

			ImGui::EndTable();
		}
	}
}