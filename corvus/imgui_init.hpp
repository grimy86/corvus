#pragma once
#include <imgui.h>

namespace corvus::imgui
{
	static bool open{ true };

	void init_gui()
	{
		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);

		ImGui::Begin("root", &open,
			ImGuiWindowFlags_NoDecoration |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoCollapse |
			ImGuiWindowFlags_NoResize);

		ImGui::End();
	}
}