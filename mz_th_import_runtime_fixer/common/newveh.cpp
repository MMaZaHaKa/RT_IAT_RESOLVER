// vehdbg.hpp / vehdbg.cpp (single-file friendly)

#include <windows.h>
#include <tlhelp32.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace vehdbg
{
    LONG WINAPI VehHandler(PEXCEPTION_POINTERS ex);
    bool RefreshAllThreads();

    enum class BreakType : uint8_t
    {
        Execute = 0,   // DR7 RW = 00
        Write = 1,   // DR7 RW = 01
        Access = 3    // DR7 RW = 11
    };

    enum class BreakSize : uint8_t
    {
        Size1 = 0,     // DR7 LEN = 00
        Size2 = 1,     // DR7 LEN = 01
        Size4 = 3,     // DR7 LEN = 11
        Size8 = 2      // DR7 LEN = 10
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

    struct BreakpointSlot
    {
        std::atomic<bool> active{ false };
        std::atomic<uintptr_t> address{ 0 };
        std::atomic<void*> userParam{ nullptr };
        std::atomic<Callback> callback{ nullptr };
        std::atomic<uint8_t> type{ static_cast<uint8_t>(BreakType::Execute) };
        std::atomic<uint8_t> size{ static_cast<uint8_t>(BreakSize::Size1) };
        std::atomic<bool> singleShot{ true };
    };

    struct BreakpointSnapshot
    {
        bool active = false;
        uintptr_t address = 0;
        void* userParam = nullptr;
        Callback callback = nullptr;
        BreakType type = BreakType::Execute;
        BreakSize size = BreakSize::Size1;
        bool singleShot = true;
    };

    static CRITICAL_SECTION g_cs;
    static bool g_csInited = false;
    static PVOID g_vehHandle = nullptr;
    static std::array<BreakpointSlot, 4> g_slots{};
    static thread_local bool g_inVehHandler = false;

    static void ClearSlotState(int slot)
    {
        if (slot < 0 || slot >= 4) return;

        g_slots[slot].active.store(false, std::memory_order_release);
        g_slots[slot].address.store(0, std::memory_order_relaxed);
        g_slots[slot].userParam.store(nullptr, std::memory_order_relaxed);
        g_slots[slot].callback.store(nullptr, std::memory_order_relaxed);
        g_slots[slot].type.store(static_cast<uint8_t>(BreakType::Execute), std::memory_order_relaxed);
        g_slots[slot].size.store(static_cast<uint8_t>(BreakSize::Size1), std::memory_order_relaxed);
        g_slots[slot].singleShot.store(true, std::memory_order_relaxed);
    }

    static std::array<BreakpointSnapshot, 4> SnapshotSlots()
    {
        std::array<BreakpointSnapshot, 4> out{};

        for (int i = 0; i < 4; ++i)
        {
            const bool active = g_slots[i].active.load(std::memory_order_acquire);
            out[i].active = active;
            if (!active)
                continue;

            out[i].address = g_slots[i].address.load(std::memory_order_relaxed);
            out[i].userParam = g_slots[i].userParam.load(std::memory_order_relaxed);
            out[i].callback = g_slots[i].callback.load(std::memory_order_relaxed);
            out[i].type = static_cast<BreakType>(g_slots[i].type.load(std::memory_order_relaxed));
            out[i].size = static_cast<BreakSize>(g_slots[i].size.load(std::memory_order_relaxed));
            out[i].singleShot = g_slots[i].singleShot.load(std::memory_order_relaxed);
        }

        return out;
    }

    static std::vector<DWORD> GetAllThreadIds()
    {
        std::vector<DWORD> ids;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return ids;

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);

        if (Thread32First(snap, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == GetCurrentProcessId())
                    ids.push_back(te.th32ThreadID);
            } while (Thread32Next(snap, &te));
        }

        CloseHandle(snap);
        return ids;
    }

    static HANDLE OpenThreadWithRights(DWORD tid)
    {
        return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            FALSE,
            tid);
    }

    static void ClearOurDebugRegs(CONTEXT& ctx)
    {
        // We own all 4 slots in this module.
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;

        for (int i = 0; i < 4; ++i)
        {
            const int enableBit = i * 2;
            const int rwShift = 16 + i * 4;
            const int lenShift = 18 + i * 4;

            ctx.Dr7 &= ~(1ULL << enableBit);         // Lx
            ctx.Dr7 &= ~(1ULL << (enableBit + 1));   // Gx
            ctx.Dr7 &= ~(3ULL << rwShift);           // RWx
            ctx.Dr7 &= ~(3ULL << lenShift);          // LENx
        }

        ctx.Dr6 = 0;
    }

    static void ApplySnapshotToContext(CONTEXT& ctx, const std::array<BreakpointSnapshot, 4>& snap)
    {
        ClearOurDebugRegs(ctx);

        for (int i = 0; i < 4; ++i)
        {
            if (!snap[i].active)
                continue;

            const uintptr_t addr = snap[i].address;
            const uint64_t rw = static_cast<uint64_t>(snap[i].type);
            const uint64_t len = static_cast<uint64_t>(snap[i].size);

            switch (i)
            {
            case 0: ctx.Dr0 = addr; break;
            case 1: ctx.Dr1 = addr; break;
            case 2: ctx.Dr2 = addr; break;
            case 3: ctx.Dr3 = addr; break;
            }

            const int enableBit = i * 2;
            const int rwShift = 16 + i * 4;
            const int lenShift = 18 + i * 4;

            ctx.Dr7 |= (1ULL << enableBit);          // local enable
            ctx.Dr7 |= (rw << rwShift);              // RW
            ctx.Dr7 |= (len << lenShift);            // LEN
        }
    }

    static bool ApplySnapshotToThread(DWORD tid, const std::array<BreakpointSnapshot, 4>& snap)
    {
        HANDLE hThread = OpenThreadWithRights(tid);
        if (!hThread)
            return false;

        const DWORD suspendCount = SuspendThread(hThread);
        if (suspendCount == (DWORD)-1)
        {
            CloseHandle(hThread);
            return false;
        }

        bool ok = false;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (GetThreadContext(hThread, &ctx))
        {
            ApplySnapshotToContext(ctx, snap);
            ok = (SetThreadContext(hThread, &ctx) != FALSE);
        }

        ResumeThread(hThread);
        CloseHandle(hThread);
        return ok;
    }

    static bool ApplySnapshotToAllThreads(const std::array<BreakpointSnapshot, 4>& snap)
    {
        const DWORD selfTid = GetCurrentThreadId();
        const std::vector<DWORD> tids = GetAllThreadIds();

        bool ok = true;

        for (DWORD tid : tids)
        {
            if (tid == selfTid)
                continue;

            if (!ApplySnapshotToThread(tid, snap))
                ok = false;
        }

        return ok;
    }

    struct WorkerJob
    {
        std::array<BreakpointSnapshot, 4> snap{};
        bool ok = false;
    };

    static DWORD WINAPI WorkerProc(LPVOID param)
    {
        auto* job = static_cast<WorkerJob*>(param);
        job->ok = ApplySnapshotToAllThreads(job->snap);
        return 0;
    }

    bool Initialize()
    {
        if (g_vehHandle)
            return true;

        if (!g_csInited)
        {
            InitializeCriticalSection(&g_cs);
            g_csInited = true;
        }

        g_vehHandle = AddVectoredExceptionHandler(1, &VehHandler);
        if (!g_vehHandle)
            return false;

        return true;
    }

    void Shutdown()
    {
        if (g_vehHandle)
        {
            RemoveVectoredExceptionHandler(g_vehHandle);
            g_vehHandle = nullptr;
        }

        if (g_csInited)
        {
            EnterCriticalSection(&g_cs);
            for (int i = 0; i < 4; ++i)
                ClearSlotState(i);
            LeaveCriticalSection(&g_cs);

            DeleteCriticalSection(&g_cs);
            g_csInited = false;
        }
    }

    int AddBreakpoint(void* address,
        Callback cb,
        void* userParam = nullptr,
        BreakType type = BreakType::Execute,
        BreakSize size = BreakSize::Size1,
        bool singleShot = true,
        bool applyNow = true)
    {
        if (!address || !cb)
            return -1;

        if (!Initialize())
            return -1;

        EnterCriticalSection(&g_cs);

        int slot = -1;
        for (int i = 0; i < 4; ++i)
        {
            if (!g_slots[i].active.load(std::memory_order_acquire))
            {
                slot = i;
                break;
            }
        }

        if (slot == -1)
        {
            LeaveCriticalSection(&g_cs);
            return -1;
        }

        g_slots[slot].address.store(reinterpret_cast<uintptr_t>(address), std::memory_order_relaxed);
        g_slots[slot].userParam.store(userParam, std::memory_order_relaxed);
        g_slots[slot].callback.store(cb, std::memory_order_relaxed);
        g_slots[slot].type.store(static_cast<uint8_t>(type), std::memory_order_relaxed);
        g_slots[slot].size.store(static_cast<uint8_t>(size), std::memory_order_relaxed);
        g_slots[slot].singleShot.store(singleShot, std::memory_order_relaxed);
        g_slots[slot].active.store(true, std::memory_order_release);

        LeaveCriticalSection(&g_cs);

        if (applyNow && !RefreshAllThreads())
        {
            EnterCriticalSection(&g_cs);
            ClearSlotState(slot);
            LeaveCriticalSection(&g_cs);
            return -1;
        }

        return slot;
    }

    bool RemoveBreakpoint(int slot, bool refreshNow = true)
    {
        if (slot < 0 || slot >= 4)
            return false;

        if (!Initialize())
            return false;

        EnterCriticalSection(&g_cs);
        ClearSlotState(slot);
        LeaveCriticalSection(&g_cs);

        return refreshNow ? RefreshAllThreads() : true;
    }

    bool RefreshAllThreads()
    {
        if (!Initialize())
            return false;

        WorkerJob job{};
        job.snap = SnapshotSlots();

        HANDLE hThread = CreateThread(nullptr, 0, &WorkerProc, &job, 0, nullptr);
        if (!hThread)
            return false;

        WaitForSingleObject(hThread, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        CloseHandle(hThread);

        return job.ok;
    }

    LONG WINAPI VehHandler(PEXCEPTION_POINTERS ex)
    {
        if (!ex || !ex->ExceptionRecord || !ex->ContextRecord)
            return EXCEPTION_CONTINUE_SEARCH;

        if (ex->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
            return EXCEPTION_CONTINUE_SEARCH;

        if (g_inVehHandler)
            return EXCEPTION_CONTINUE_SEARCH;

        struct Guard
        {
            Guard() { g_inVehHandler = true; }
            ~Guard() { g_inVehHandler = false; }
        } guard;

        CONTEXT* ctx = ex->ContextRecord;

        // DR6 status bits: B0..B3
        const DWORD64 dr6 = ctx->Dr6;
        bool handled = false;

        for (int slot = 0; slot < 4; ++slot)
        {
            if ((dr6 & (1ULL << slot)) == 0)
                continue;

            BreakpointSnapshot bp{};
            bp.active = g_slots[slot].active.load(std::memory_order_acquire);
            if (!bp.active)
                continue;

            bp.address = g_slots[slot].address.load(std::memory_order_relaxed);
            bp.userParam = g_slots[slot].userParam.load(std::memory_order_relaxed);
            bp.callback = g_slots[slot].callback.load(std::memory_order_relaxed);
            bp.type = static_cast<BreakType>(g_slots[slot].type.load(std::memory_order_relaxed));
            bp.size = static_cast<BreakSize>(g_slots[slot].size.load(std::memory_order_relaxed));
            bp.singleShot = g_slots[slot].singleShot.load(std::memory_order_relaxed);

            if (bp.type == BreakType::Execute)
            {
                if (ex->ExceptionRecord->ExceptionAddress != reinterpret_cast<PVOID>(bp.address))
                    continue;
            }

            // Clear status for safe re-entry.
            ctx->Dr6 = 0;

            HitInfo hit{};
            hit.slot = slot;
            hit.address = bp.address;
            hit.type = bp.type;
            hit.size = bp.size;
            hit.singleShot = bp.singleShot;
            hit.userParam = bp.userParam;

            if (bp.callback)
                bp.callback(bp.userParam, ctx, hit);

            // Local disable for one-shot in the current thread.
            if (bp.singleShot)
            {
                ctx->Dr7 &= ~(1ULL << (slot * 2));
                g_slots[slot].active.store(false, std::memory_order_release);
            }

            handled = true;
        }

        return handled ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
    }

    // Optional diagnostic helper.
    void DumpThreadDebugRegisters(HANDLE hThread)
    {
        if (!hThread)
        {
            printf("[vehdbg] invalid thread handle\n");
            return;
        }

        DWORD sc = SuspendThread(hThread);
        if (sc == (DWORD)-1)
        {
            printf("[vehdbg] SuspendThread failed: %lu\n", GetLastError());
            return;
        }

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(hThread, &ctx))
        {
            printf("[vehdbg] GetThreadContext failed: %lu\n", GetLastError());
            ResumeThread(hThread);
            return;
        }

        printf("[vehdbg] DR0=%p DR1=%p DR2=%p DR3=%p\n",
            (void*)ctx.Dr0, (void*)ctx.Dr1, (void*)ctx.Dr2, (void*)ctx.Dr3);
        printf("[vehdbg] DR6=0x%08llX DR7=0x%08llX\n",
            (unsigned long long)ctx.Dr6, (unsigned long long)ctx.Dr7);

        ResumeThread(hThread);
    }
}

// ----------------------
// Example usage
// ----------------------
//
// static void OnVeh(void* p, CONTEXT* ctx, const vehdbg::HitInfo& hit)
// {
//     printf("VEH hit slot=%d addr=%p\n", hit.slot, (void*)hit.address);
//     // Don't block here.
// }
//
// int main()
// {
//     vehdbg::Initialize();
//     int slot = vehdbg::AddBreakpoint((void*)tmp, OnVeh, nullptr,
//                                       vehdbg::BreakType::Execute,
//                                       vehdbg::BreakSize::Size1,
//                                       true,
//                                       true);
//     if (slot < 0) { printf("add breakpoint failed\n"); }
//     ...
//     vehdbg::Shutdown();
// }