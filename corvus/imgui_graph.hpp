#pragma once
#include <imgui.h>
#include <vector>
#include <utility>

namespace corvus::imgui
{
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

	inline ImVec2 add(ImVec2 a, ImVec2 b)
	{
		return ImVec2(a.x + b.x, a.y + b.y);
	}

	inline ImVec2 mul(ImVec2 v, float s)
	{
		return ImVec2(v.x * s, v.y * s);
	}

	inline void draw_graph(const Graph& graph)
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
