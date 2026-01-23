#pragma once
#include <vector>
#include <imgui.h>
#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "process.hpp"
#include "converter.hpp"

#pragma comment(lib, "ntdll.lib")

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation ((SYSTEM_INFORMATION_CLASS)64)
#endif

namespace corvus::imgui
{
    // =====================
    // Shared state
    // =====================
    inline DWORD g_SelectedPid = 0;
    inline std::vector<corvus::process::ProcessInfo> g_ProcessCache;

    // =====================
    // NT internals
    // =====================
    typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
        SYSTEM_INFORMATION_CLASS,
        PVOID,
        ULONG,
        PULONG
        );

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
    {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

    typedef struct _SYSTEM_HANDLE_INFORMATION_EX
    {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
    } SYSTEM_HANDLE_INFORMATION_EX;

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

        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            g_SelectedPid);

        if (snap == INVALID_HANDLE_VALUE)
        {
            ImGui::Text("CreateToolhelp32Snapshot failed");
            return;
        }

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (!Module32FirstW(snap, &me))
        {
            CloseHandle(snap);
            ImGui::Text("Module enumeration failed");
            return;
        }

        if (ImGui::BeginTable("modules_table", 4,
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
            return;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        if (ImGui::BeginTable("threads_table", 3,
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 90);
            ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 90);
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
    // Handles View (REAL)
    // =====================
    inline void DrawHandlesView()
    {
        if (g_SelectedPid == 0)
        {
            ImGui::TextDisabled("No process selected");
            return;
        }

        static NtQuerySystemInformation_t NtQuerySystemInformation =
            (NtQuerySystemInformation_t)GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"),
                "NtQuerySystemInformation");

        if (!NtQuerySystemInformation)
        {
            ImGui::TextColored(ImVec4(1, 0, 0, 1), "NtQuerySystemInformation not found");
            return;
        }

        ULONG size = 0x10000;
        std::vector<uint8_t> buffer;

        NTSTATUS status;
        do
        {
            buffer.resize(size);
            status = NtQuerySystemInformation(
                SystemExtendedHandleInformation,
                buffer.data(),
                size,
                &size);
            size *= 2;
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(status))
        {
            ImGui::Text("NtQuerySystemInformation failed");
            return;
        }

        auto* info = (SYSTEM_HANDLE_INFORMATION_EX*)buffer.data();

        if (ImGui::BeginTable("handles_table", 4,
            ImGuiTableFlags_RowBg |
            ImGuiTableFlags_Borders |
            ImGuiTableFlags_Resizable |
            ImGuiTableFlags_ScrollY))
        {
            ImGui::TableSetupColumn("Handle", ImGuiTableColumnFlags_WidthFixed, 90);
            ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 120);
            ImGui::TableSetupColumn("TypeIdx", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Object");
            ImGui::TableHeadersRow();

            for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i)
            {
                const auto& h = info->Handles[i];
                if ((DWORD)h.UniqueProcessId != g_SelectedPid)
                    continue;

                ImGui::TableNextRow();

                ImGui::TableSetColumnIndex(0);
                ImGui::Text("0x%llX", (unsigned long long)h.HandleValue);

                ImGui::TableSetColumnIndex(1);
                ImGui::Text("0x%08X", h.GrantedAccess);

                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%u", h.ObjectTypeIndex);

                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%p", h.Object);
            }

            ImGui::EndTable();
        }
    }
}
