#pragma once
#include <imgui.h>
#include "imgui_processes.hpp"

namespace corvus::imgui
{
	enum class CanvasView
	{
		None,
		ProcessList,
		Attach,
		Modules,
		Threads,
		Handles
	};

	inline CanvasView g_CurrentView = CanvasView::None;

	inline void root()
	{
		ImGuiIO& io = ImGui::GetIO();

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(io.DisplaySize);

		ImGui::Begin("##root", nullptr,
			ImGuiWindowFlags_NoDecoration |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoBringToFrontOnFocus);

		// =====================
		// Left panel (navigation)
		// =====================
		ImGui::BeginChild("left", ImVec2(300, 0), true);
		ImGui::TextUnformatted("Modules");
		ImGui::Separator();

		ImGuiTreeNodeFlags section_flags =
			ImGuiTreeNodeFlags_DefaultOpen |
			ImGuiTreeNodeFlags_FramePadding |
			ImGuiTreeNodeFlags_SpanAvailWidth;

		if (ImGui::TreeNodeEx("Process", section_flags))
		{
			if (ImGui::Selectable(
				"Process List",
				g_CurrentView == CanvasView::ProcessList))
			{
				g_CurrentView = CanvasView::ProcessList;
			}

			if (ImGui::Selectable(
				"Attach / Detach",
				g_CurrentView == CanvasView::Attach))
			{
				g_CurrentView = CanvasView::Attach;
			}

			if (ImGui::Selectable(
				"Modules",
				g_CurrentView == CanvasView::Modules))
			{
				g_CurrentView = CanvasView::Modules;
			}

			if (ImGui::Selectable(
				"Threads",
				g_CurrentView == CanvasView::Threads))
			{
				g_CurrentView = CanvasView::Threads;
			}

			if (ImGui::Selectable(
				"Handles",
				g_CurrentView == CanvasView::Handles))
			{
				g_CurrentView = CanvasView::Handles;
			}

			ImGui::SeparatorText("Injection");

			ImGui::Selectable("Manual Map");
			ImGui::Selectable("LoadLibrary");
			ImGui::Selectable("Shellcode");

			ImGui::TreePop();
		}

		if (ImGui::TreeNodeEx("Memory Editor", section_flags))
		{
			ImGui::Selectable("RPM / WPM");
			ImGui::Selectable("Pattern Scan");

			ImGui::TreePop();
		}

		if (ImGui::TreeNodeEx("ReClass.NET DSA Visualization", section_flags))
		{
			ImGui::Selectable("Linked List");
			ImGui::Selectable("Binary Tree");
			ImGui::Selectable("Heap");
			ImGui::Selectable("Graph");

			ImGui::TreePop();
		}

		if (ImGui::TreeNodeEx("Utilities", section_flags))
		{
			ImGui::Selectable("Hook Creator");
			ImGui::Selectable("Shellcode Creator");
			ImGui::Selectable("Pointer Calculator");
			ImGui::Selectable("Address Converter");

			ImGui::TreePop();
		}

		ImGui::EndChild();

		// =====================
		// Canvas (content)
		// =====================
		ImGui::SameLine();
		ImGui::BeginChild("canvas", ImVec2(0, 0), true,
			ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse);

		switch (g_CurrentView)
		{
		case CanvasView::ProcessList:
			DrawProcessList();
			break;

		case CanvasView::Modules:
			DrawModulesView();
			break;

		case CanvasView::Threads:
			DrawThreadsView();
			break;

		case CanvasView::Handles:
			DrawHandlesView();
			break;

		default:
			ImGui::TextDisabled("Select a module from the left");
			break;
		}

		ImGui::EndChild();
		ImGui::End();
	}
}