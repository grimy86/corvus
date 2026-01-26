#pragma once
#include <imgui.h>
#include <memory>
#include <vector>
#include <algorithm>
#include <atomic>

#include "process.hpp"
#include "converter.hpp"

namespace corvus::imgui {

	// ============================================================
	// External UI state (owned by root UI)
	// ============================================================
	extern std::atomic<bool> g_loading;
	extern bool g_hasLoadedProcesses;
	extern bool g_useNtProcessList;

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
	inline void LoadProcessList() {
		g_ProcessCache = corvus::process::WindowsProcessWin32::GetProcessListW32();
		g_ProcessCacheNt = corvus::process::WindowsProcessNt::GetProcessListNt();
		g_SelectedProcess.reset();
		g_SelectedProcessNt.reset();
	}

	// ============================================================
	// Helpers
	// ============================================================
	inline void DrawSectionHeader(const char* label) {
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);
		ImGui::TextDisabled(label);
	}

	// ============================================================
	// Process Rows
	// ============================================================
	inline void DrawProcessRowWin32(corvus::process::WindowsProcessWin32& proc) {
		ImGui::TableNextRow();
		const bool selected =
			g_SelectedProcess &&
			g_SelectedProcess->GetProcessId() == proc.GetProcessId();

		ImGui::TableSetColumnIndex(0);
		if (ImGui::Selectable(std::to_string(proc.GetProcessId()).c_str(),
			selected, ImGuiSelectableFlags_SpanAllColumns))
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

	inline void DrawProcessRowNt(corvus::process::WindowsProcessNt& proc) {
		ImGui::TableNextRow();
		const bool selected =
			g_SelectedProcessNt &&
			g_SelectedProcessNt->GetProcessId() == proc.GetProcessId();

		ImGui::TableSetColumnIndex(0);
		if (ImGui::Selectable(std::to_string(proc.GetProcessId()).c_str(),
			selected, ImGuiSelectableFlags_SpanAllColumns))
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
	inline void DrawProcessList() {
		if (ImGui::Button("Refresh") && !g_loading)
			g_hasLoadedProcesses = false;

		ImGui::Separator();

		if (g_ProcessCache.empty()) {
			ImGui::TextDisabled("No process data available");
			return;
		}

		std::vector<std::reference_wrapper<corvus::process::WindowsProcessWin32>> fg, bg;
		for (auto& p : g_ProcessCache)
			(p.HasVisibleWindow() ? fg : bg).emplace_back(p);

		if (ImGui::BeginTable("process_table_w32", 3,
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 120.f);
			ImGui::TableSetupColumn("Process Name");
			ImGui::TableSetupColumn("CPU ISA", ImGuiTableColumnFlags_WidthFixed, 90.f);
			ImGui::TableHeadersRow();

			if (!fg.empty()) {
				DrawSectionHeader("Windowed Processes");
				for (auto& p : fg) DrawProcessRowWin32(p.get());
			}
			if (!bg.empty()) {
				DrawSectionHeader("Background Processes");
				for (auto& p : bg) DrawProcessRowWin32(p.get());
			}

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Native NT Process List (visual-only)
	// ============================================================
	inline void DrawProcessListNt() {
		ImGui::Separator();

		if (g_ProcessCacheNt.empty()) {
			ImGui::TextDisabled("No native process data available");
			return;
		}

		if (ImGui::BeginTable("process_table_nt", 2,
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 120.f);
			ImGui::TableSetupColumn("Image Name");
			ImGui::TableHeadersRow();

			for (auto& p : g_ProcessCacheNt)
				DrawProcessRowNt(p);

			ImGui::EndTable();
		}
	}

	// ============================================================
	// Modules View (Win32 ONLY)
	// ============================================================
	inline void DrawModulesView() {
		if (g_useNtProcessList) {
			ImGui::TextDisabled("Modules are not implemented for NT processes yet.");
			return;
		}

		if (!g_SelectedProcess) {
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& modules = g_SelectedProcess->GetModules();
		if (modules.empty()) {
			ImGui::TextDisabled("No module data available");
			return;
		}

		if (ImGui::BeginTable("modules_table", 8,
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Base");
			ImGui::TableSetupColumn("Size");
			ImGui::TableSetupColumn("Image Size");
			ImGui::TableSetupColumn("Entry");
			ImGui::TableSetupColumn("PID");
			ImGui::TableSetupColumn("Load (G)");
			ImGui::TableSetupColumn("Load (P)");
			ImGui::TableSetupColumn("Name");
			ImGui::TableHeadersRow();

			for (const auto& m : modules) {
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("0x%p", (void*)m.baseAddress);
				ImGui::TableSetColumnIndex(1); ImGui::Text("%llu", (uint64_t)m.size);
				ImGui::TableSetColumnIndex(2); ImGui::Text("%llu", (uint64_t)m.moduleBaseSize);
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
	// Threads View (Win32 ONLY)
	// ============================================================
	inline void DrawThreadsView() {
		if (g_useNtProcessList) {
			ImGui::TextDisabled("Thread analysis not wired for NT yet.");
			return;
		}

		if (!g_SelectedProcess) {
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& threads = g_SelectedProcess->GetThreads();
		if (threads.empty()) {
			ImGui::TextDisabled("No thread data available");
			return;
		}

		if (ImGui::BeginTable("threads_table", 6,
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("TID");
			ImGui::TableSetupColumn("Owner PID");
			ImGui::TableSetupColumn("Base Pri");
			ImGui::TableSetupColumn("Delta Pri");
			ImGui::TableSetupColumn("State");
			ImGui::TableSetupColumn("Wait Reason");
			ImGui::TableHeadersRow();

			for (const auto& t : threads) {
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("%lu", t.threadId);
				ImGui::TableSetColumnIndex(1); ImGui::Text("%lu", t.ownerProcessId);
				ImGui::TableSetColumnIndex(2); ImGui::Text("%ld", t.basePriority);
				ImGui::TableSetColumnIndex(3); ImGui::Text("%ld", t.deltaPriority);
				ImGui::TableSetColumnIndex(4); ImGui::Text("%d", (int)t.threadState);
				ImGui::TableSetColumnIndex(5); ImGui::Text("%d", (int)t.waitReason);
			}
			ImGui::EndTable();
		}
	}

	// ============================================================
	// Handles View (Win32 ONLY)
	// ============================================================
	inline void DrawHandlesView() {
		if (g_useNtProcessList) {
			ImGui::TextDisabled("Handle analysis not wired for NT yet.");
			return;
		}

		if (!g_SelectedProcess) {
			ImGui::TextDisabled("No process selected");
			return;
		}

		const auto& handles = g_SelectedProcess->GetHandles();
		if (handles.empty()) {
			ImGui::TextDisabled("No handle data available");
			return;
		}

		if (ImGui::BeginTable("handles_table", 8,
			ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
			ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("Handle");
			ImGui::TableSetupColumn("Type");
			ImGui::TableSetupColumn("Type Name");
			ImGui::TableSetupColumn("Object");
			ImGui::TableSetupColumn("Access");
			ImGui::TableSetupColumn("Flags");
			ImGui::TableSetupColumn("Attrib");
			ImGui::TableSetupColumn("RefCnt");
			ImGui::TableHeadersRow();

			for (const auto& h : handles) {
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0); ImGui::Text("0x%p", h.handle);
				ImGui::TableSetColumnIndex(1); ImGui::Text("%u", (uint32_t)h.objectType);
				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(h.typeName).c_str());
				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(h.objectName).c_str());
				ImGui::TableSetColumnIndex(4); ImGui::Text("0x%08lX", h.grantedAccess);
				ImGui::TableSetColumnIndex(5); ImGui::Text("0x%08lX", h.flags);
				ImGui::TableSetColumnIndex(6); ImGui::Text("0x%08lX", h.attributes);
				ImGui::TableSetColumnIndex(7); ImGui::Text("%lu", h.handleCount);
			}
			ImGui::EndTable();
		}
	}
}