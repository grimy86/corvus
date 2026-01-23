#pragma once

#include <imgui.h>
#include <vector>
#include <utility>

namespace corvus
{
	// -----------------------------
	// Core data model (NO ImGui logic)
	// -----------------------------

	struct Node
	{
		ImVec2 pos;
		ImVec2 size;
		const char* label;
	};

	struct Graph
	{
		std::vector<Node> nodes;
		std::vector<std::pair<int, int>> edges;
	};
}

namespace corvus::imgui
{
	// -----------------------------
	// Demo / current state
	// -----------------------------

	inline corvus::Graph current_graph = [] {
		corvus::Graph g;

		g.nodes.push_back({ { 50,  50 }, { 120, 50 }, "Node A" });
		g.nodes.push_back({ { 250, 80 }, { 120, 50 }, "Node B" });
		g.nodes.push_back({ { 180, 180 }, { 120, 50 }, "Node C" });

		g.edges.emplace_back(0, 1);
		g.edges.emplace_back(1, 2);

		return g;
		}();

	// -----------------------------
	// Forward declarations
	// -----------------------------

	void draw_graph(const corvus::Graph& graph);

	// -----------------------------
	// Root UI
	// -----------------------------

	inline void init_gui()
	{
		ImGuiIO& io = ImGui::GetIO();

		ImGui::SetNextWindowPos(ImVec2(0, 0));
		ImGui::SetNextWindowSize(io.DisplaySize);

		ImGui::Begin("##root", nullptr,
			ImGuiWindowFlags_NoDecoration |
			ImGuiWindowFlags_NoMove |
			ImGuiWindowFlags_NoSavedSettings |
			ImGuiWindowFlags_NoBringToFrontOnFocus);

		// -----------------------------
		// Left panel
		// -----------------------------

		ImGui::BeginChild("left", ImVec2(300, 0), true);
		ImGui::TextUnformatted("Structures");
		ImGui::Separator();

		if (ImGui::Button("Linked List"))
		{
			// later: rebuild graph
		}

		if (ImGui::Button("Binary Tree"))
		{
		}

		if (ImGui::Button("Heap"))
		{
		}

		ImGui::EndChild();

		ImGui::SameLine();

		// -----------------------------
		// Canvas
		// -----------------------------

		ImGui::BeginChild("canvas", ImVec2(0, 0), true,
			ImGuiWindowFlags_NoScrollbar |
			ImGuiWindowFlags_NoScrollWithMouse);

		draw_graph(current_graph);

		ImGui::EndChild();
		ImGui::End();
	}

	// -----------------------------
	// Graph renderer
	// -----------------------------

	inline ImVec2 add(ImVec2 a, ImVec2 b)
	{
		return ImVec2(a.x + b.x, a.y + b.y);
	}

	inline ImVec2 mul(ImVec2 v, float s)
	{
		return ImVec2(v.x * s, v.y * s);
	}

	inline void draw_graph(const corvus::Graph& graph)
	{
		ImDrawList* dl = ImGui::GetWindowDrawList();
		ImVec2 origin = ImGui::GetCursorScreenPos();

		// Edges
		for (auto& [a, b] : graph.edges)
		{
			if (a < 0 || b < 0 ||
				a >= (int)graph.nodes.size() ||
				b >= (int)graph.nodes.size())
				continue;

			const auto& na = graph.nodes[a];
			const auto& nb = graph.nodes[b];

			ImVec2 ca = add(origin, add(na.pos, mul(na.size, 0.5f)));
			ImVec2 cb = add(origin, add(nb.pos, mul(nb.size, 0.5f)));

			dl->AddLine(ca, cb, IM_COL32(200, 200, 100, 255), 2.0f);
		}

		// Nodes
		for (const auto& node : graph.nodes)
		{
			ImVec2 p0 = add(origin, node.pos);
			ImVec2 p1 = add(p0, node.size);

			dl->AddRectFilled(p0, p1, IM_COL32(45, 45, 48, 255), 6.0f);
			dl->AddRect(p0, p1, IM_COL32(110, 110, 120, 255), 6.0f);
			dl->AddText(add(p0, ImVec2(8, 8)),
				IM_COL32(230, 230, 230, 255),
				node.label);
		}
	}
}
