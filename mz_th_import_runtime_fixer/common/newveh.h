// vehdbg.hpp
#pragma once

#include <windows.h>
#include <cstdint>

namespace vehdbg
{
    enum class BreakType : uint8_t
    {
        Execute = 0,
        Write = 1,
        Access = 3
    };

    enum class BreakSize : uint8_t
    {
        Size1 = 0,
        Size2 = 1,
        Size4 = 3,
        Size8 = 2
    };

    struct HitInfo
    {
        int slot = -1;
        uintptr_t address = 0;
        BreakType type = BreakType::Execute;
        BreakSize size = BreakSize::Size1;
        bool singleShot = false;
        void* userParam = nullptr;
    };

    using Callback = void(*)(void* userParam, CONTEXT* ctx, const HitInfo& hit);

    // Function declarations
    bool Initialize();
    void Shutdown();
    int AddBreakpoint(void* address, Callback cb, void* userParam = nullptr,
        BreakType type = BreakType::Execute, BreakSize size = BreakSize::Size1,
        bool singleShot = true, bool applyNow = true);
    bool RemoveBreakpoint(int slot, bool refreshNow = true);
    bool RefreshAllThreads();
    void DumpThreadDebugRegisters(HANDLE hThread);
}