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
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Process Name");
			ImGui::TableSetupColumn("CPU ISA", ImGuiTableColumnFlags_WidthFixed, 150.0f);
			ImGui::TableHeadersRow();

			if (!foreground.empty())
			{
				DrawSectionHeader("Foreground Processes");
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
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 110.0f);
			ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Name");
			ImGui::TableHeadersRow();

			for (const auto& m : modules)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%p", m.baseAddress);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%llu", static_cast<unsigned long long>(m.size));

				ImGui::TableSetColumnIndex(2);
				ImGui::TextUnformatted(
					corvus::converter::WStringToString(m.description).c_str());
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
			3,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Base Priority");
			ImGui::TableHeadersRow();

			for (const auto& t : threads)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("%lu", t.threadId);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("%lu", g_SelectedProcess->GetProcessId());

				ImGui::TableSetColumnIndex(2);
				ImGui::Text("%ld", t.priority);
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
			4,
			ImGuiTableFlags_RowBg |
			ImGuiTableFlags_Borders |
			ImGuiTableFlags_Resizable |
			ImGuiTableFlags_ScrollY))
		{
			ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 90.0f);
			ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 120.0f);
			ImGui::TableSetupColumn("TypeIdx", ImGuiTableColumnFlags_WidthFixed, 80.0f);
			ImGui::TableSetupColumn("Object");
			ImGui::TableHeadersRow();

			for (const auto& h : handles)
			{
				ImGui::TableNextRow();
				ImGui::TableSetColumnIndex(0);
				ImGui::Text("0x%llX", h.handleValue);

				ImGui::TableSetColumnIndex(1);
				ImGui::Text("0x%08X", h.grantedAccess);

				ImGui::TableSetColumnIndex(2);
				ImGui::Text("%u", static_cast<unsigned>(h.type));

				ImGui::TableSetColumnIndex(3);
				ImGui::Text("0x%p", h.object);
			}

			ImGui::EndTable();
		}
	}
}
