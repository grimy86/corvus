#pragma once
#include "MainView.h"
#include "WindowsProcessView.h"

namespace Corvus::UserInterface
{
	void MainView::Init()
	{
		s_viewport = ImGui::GetMainViewport();
		s_isSeDebugEnabled = Corvus::Data::WindowsProvider32::QuerySeDebugPrivilege32(GetCurrentProcess());
		m_system.UpdateProcessList32();
		m_system.UpdateProcessListNt();
	}

	void MainView::DrawHeader()
	{
		if (ImGui::BeginTable("##infobar_table", 2))
		{
			ImVec4 debugTextColor
			{
				s_isSeDebugEnabled ?
				ImVec4(0, 1, 0, 1) : ImVec4(1, 0, 0, 1)
			};

			ImGui::TableNextColumn();
			ImGui::Text("SeDebugPrivilege:");
			ImGui::SameLine();
			ImGui::TextColored(debugTextColor, s_isSeDebugEnabled ? "Enabled" : "Disabled");
			ImGui::Spacing();
			ImGui::Checkbox("Ntdll backend", &s_isNtChecked);
			if (ImGui::Button("Refresh"))
			{
				m_system.UpdateProcessList32();
				m_system.UpdateProcessListNt();
			}
		}
		ImGui::EndTable();
	}

	void MainView::DrawNavBar()
	{
		bool open = ImGui::TreeNodeEx("Process", Corvus::UserInterface::g_tnFlags);
		if (ImGui::IsItemClicked()) s_view = View::Object;

		if (open)
		{
			ImGui::Indent();
			if (ImGui::Selectable("Threads", s_view == View::Threads))
				s_view = View::Threads;

			if (ImGui::Selectable("Modules", s_view == View::Modules))
				s_view = View::Modules;

			if (ImGui::Selectable("Handles", s_view == View::Handles))
				s_view = View::Handles;
			ImGui::Unindent();
			ImGui::TreePop();
		}
	}

	void MainView::DrawContentView()
	{
		switch (s_view)
		{
		case View::Object:
			WindowsProcessView::DrawProcessView();
			break;
		case View::Threads:
			WindowsProcessView::DrawThreadView();
			break;
		case View::Modules:
			WindowsProcessView::DrawModuleView();
			break;
		case View::Handles:
			WindowsProcessView::DrawHandleView();
			break;
		default:
			WindowsProcessView::DrawProcessView();
			break;
		}
	}

	void MainView::DrawMainView()
	{
		Corvus::Service::SetThreadPriority32(ABOVE_NORMAL_PRIORITY_CLASS);
		ImGui::SetNextWindowPos(s_viewport->Pos, ImGuiCond_Always);
		ImGui::SetNextWindowSize(s_viewport->Size, ImGuiCond_Always);

		if (ImGui::Begin("##mainWindow", nullptr, g_wndFlags))
		{
			ImGui::BeginChild("##infobar", ImVec2(0, 80.0f), false);
			DrawHeader();
			ImGui::EndChild();

			// NAVBAR
			ImGui::BeginChild("##navbar", ImVec2(150.0f, 0), true);
			DrawNavBar();
			ImGui::EndChild();

			// CONTENT VIEW
			ImGui::SameLine();
			ImGui::BeginChild("##contentview", ImVec2(0, 0), false);
			DrawContentView();
			ImGui::EndChild();
		}
		ImGui::End();
	}
}