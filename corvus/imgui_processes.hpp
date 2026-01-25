#pragma once
#include <imgui.h>
#include <memory>
#include <vector>
#include <algorithm>

#include "process.hpp"
#include "converter.hpp"

namespace corvus::imgui
{
	// =====================
	// Shared state
	// =====================
	inline std::vector<corvus::process::WIN32Process> g_ProcessCache;
	inline std::shared_ptr<corvus::process::WIN32Process> g_SelectedProcess;

	// =====================
	// Helpers
	// =====================
	inline void DrawProcessRow(corvus::process::WIN32Process& proc)
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
			g_SelectedProcess =
				std::make_shared<corvus::process::WIN32Process>(proc);
		}

		ImGui::TableSetColumnIndex(1);
		ImGui::TextUnformatted(
			corvus::converter::WStringToString(proc.GetName()).c_str());

		ImGui::TableSetColumnIndex(2);
		ImGui::TextUnformatted(
			corvus::converter::ArchitectureToString(proc.GetArchitecture()));
	}

	inline void DrawSectionHeader(const char* label)
	{
		ImGui::TableNextRow();
		ImGui::TableSetColumnIndex(0);
		ImGui::TextDisabled(label);
	}

	// =====================
	// Process List
	// =====================
	inline void DrawProcessList()
	{
		if (g_ProcessCache.empty())
			g_ProcessCache = corvus::process::WIN32Process::GetProcessListW32();

		if (ImGui::Button("Refresh"))
		{
			g_ProcessCache = corvus::process::WIN32Process::GetProcessListW32();
			g_SelectedProcess.reset();
		}

		ImGui::Separator();

		std::vector<std::reference_wrapper<corvus::process::WIN32Process>> foreground;
		std::vector<std::reference_wrapper<corvus::process::WIN32Process>> background;

		for (auto& proc : g_ProcessCache)
		{
			if (proc.HasVisibleWindow())
				foreground.emplace_back(proc);
			else
				background.emplace_back(proc);
		}

		if (ImGui::BeginTable(
			"process_table",
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingStretchProp))
		{
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 25.0f);
			ImGui::TableSetupColumn("Process Name");
			ImGui::TableSetupColumn("CPU ISA");
			ImGui::TableHeadersRow();

			if (!foreground.empty())
			{
				DrawSectionHeader("Windowed Processes");
				for (auto& proc : foreground)
					DrawProcessRow(proc.get());
			}

			if (!background.empty())
			{
				DrawSectionHeader("Background Processes");
				for (auto& proc : background)
					DrawProcessRow(proc.get());
			}

			ImGui::EndTable();
		}
	}

	// =====================
	// Modules View
	// =====================
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
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("Base");
			ImGui::TableSetupColumn("Size");
			ImGui::TableSetupColumn("Image Size");
			ImGui::TableSetupColumn("Entry");
			ImGui::TableSetupColumn("PID");
			ImGui::TableSetupColumn("Load Cnt (G)");
			ImGui::TableSetupColumn("Load Cnt (P)");
			ImGui::TableSetupColumn("Name");
			ImGui::TableHeadersRow();

			for (const auto& m : modules)
			{
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%p", (void*)m.baseAddress);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%llu", (unsigned long long)m.size);

				ImGui::TableSetColumnIndex(2);
				ImGui::Text("%llu", (unsigned long long)m.moduleBaseSize);

				ImGui::TableSetColumnIndex(3);
				ImGui::Text("0x%p", m.entryPoint);

				ImGui::TableSetColumnIndex(4);
				ImGui::Text("%lu", m.processId);

				ImGui::TableSetColumnIndex(5);
				ImGui::Text("%lu", m.globalLoadCount);

				ImGui::TableSetColumnIndex(6);
				ImGui::Text("%lu", m.processLoadCount);

				ImGui::TableSetColumnIndex(7);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(m.moduleName).c_str());
			}

			ImGui::EndTable();
		}
	}

	// =====================
	// Threads View
	// =====================
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
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("Size");
			ImGui::TableSetupColumn("Usage");
			ImGui::TableSetupColumn("TID");
			ImGui::TableSetupColumn("Owner PID");
			ImGui::TableSetupColumn("Base Pri");
			ImGui::TableSetupColumn("Delta Pri");
			ImGui::TableSetupColumn("Flags");
			ImGui::TableHeadersRow();

			for (const auto& t : threads)
			{
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%llu", (unsigned long long)t.size);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%lu", t.cntUsage);

				ImGui::TableSetColumnIndex(2);
				ImGui::Text("%lu", t.threadId);

				ImGui::TableSetColumnIndex(3);
				ImGui::Text("%lu", t.ownerProcessId);

				ImGui::TableSetColumnIndex(4);
				ImGui::Text("%ld", t.basePriority);

				ImGui::TableSetColumnIndex(5);
				ImGui::Text("%ld", t.deltaPriority);

				ImGui::TableSetColumnIndex(6);
				ImGui::Text("0x%08lX", t.flags);
			}

			ImGui::EndTable();
		}
	}

	// =====================
	// Handles View (stubbed)
	// =====================
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
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY |
			ImGuiTableFlags_SizingFixedFit))
		{
			ImGui::TableSetupColumn("Handle");
			ImGui::TableSetupColumn("Type");
			ImGui::TableSetupColumn("Type Name");
			ImGui::TableSetupColumn("Object Name");
			ImGui::TableSetupColumn("Access");
			ImGui::TableSetupColumn("Flags");
			ImGui::TableSetupColumn("Attrs");
			ImGui::TableSetupColumn("Handles");
			ImGui::TableSetupColumn("Pointers");
			ImGui::TableSetupColumn("Paged Pool");
			ImGui::TableSetupColumn("NonPaged Pool");
			ImGui::TableSetupColumn("Name Len");
			ImGui::TableHeadersRow();

			for (const auto& h : handles)
			{
				ImGui::TableNextRow();

				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%p", h.handle);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%u", static_cast<unsigned>(h.objectType));

				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(h.TypeName).c_str());

				ImGui::TableSetColumnIndex(3);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(h.ObjectName).c_str());

				ImGui::TableSetColumnIndex(4);
				ImGui::Text("0x%08lX", h.GrantedAccess);

				ImGui::TableSetColumnIndex(5);
				ImGui::Text("0x%08lX", h.flags);

				ImGui::TableSetColumnIndex(6);
				ImGui::Text("0x%08lX", h.Attributes);

				ImGui::TableSetColumnIndex(7);
				ImGui::Text("%lu", h.HandleCount);

				ImGui::TableSetColumnIndex(8);
				ImGui::Text("%lu", h.PointerCount);

				ImGui::TableSetColumnIndex(9);
				ImGui::Text("%lu", h.PagedPoolCharge);

				ImGui::TableSetColumnIndex(10);
				ImGui::Text("%lu", h.NonPagedPoolCharge);

				ImGui::TableSetColumnIndex(11);
				ImGui::Text("%hu / %hu",
					h.TypeNameLength,
					h.ObjectNameLength);
			}

			ImGui::EndTable();
		}
	}
}
