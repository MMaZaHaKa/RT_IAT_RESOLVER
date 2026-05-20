#include "tools.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <assert.h>
#include <mutex>
#include "hdeminhook/hde32.h"
#include "common/XMemory.h"
#include "common/newveh.h"

#pragma comment(lib, "user32.lib")

TCHAR g_dllPath[MAX_PATH];

DWORD GetProcessIdByName(const char* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                if (strcmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

DWORD_PTR GetModuleBaseAddress(DWORD pid, const char* moduleName) {
    DWORD_PTR baseAddress = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

    if (snapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me32;
        me32.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(snapshot, &me32)) {
            do {
                if (strcmp(me32.szModule, moduleName) == 0) {
                    baseAddress = (DWORD_PTR)me32.modBaseAddr;
                    break;
                }
            } while (Module32Next(snapshot, &me32));
        }
        CloseHandle(snapshot);
    }
    return baseAddress;
}

std::string SanitizeIdaName(const std::string& in)
{
    std::string s = in;
    for (char& c : s)
    {
        unsigned char uc = static_cast<unsigned char>(c);
        if (!(std::isalnum(uc) || c == '_'))
            c = '_';
    }
    if (s.empty())
        s = "unk";
    if (std::isdigit(static_cast<unsigned char>(s[0])))
        s = "_" + s;
    return s;
}

struct tInputData {
    uintptr_t pBase;
    uintptr_t pStart;
    uintptr_t pEnd;
    uint32_t nSize;
    int32_t nMaxJunkSteps;
    uintptr_t pIDBBase;
};

void GetInputData(tInputData* pInput)
{
    assert(pInput);

    char moduleName[MAX_PATH];
    char startAddrStr[20], endAddrStr[20];
    char maxStepsStr[20];
    char idaBaseStr[20];

    printf("Enter module name (DLL/EXE) (example: game.exe or lib.dll): ");
    scanf("%s", moduleName);

    // Find process ID by module name (search in all processes)
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32))
        {
            do {
                // Check if module exists in this process
                HANDLE moduleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
                if (moduleSnapshot != INVALID_HANDLE_VALUE) {
                    MODULEENTRY32 me32;
                    me32.dwSize = sizeof(MODULEENTRY32);

                    if (Module32First(moduleSnapshot, &me32)) {
                        do {
                            if (strcmp(me32.szModule, moduleName) == 0) {
                                pid = pe32.th32ProcessID;
                                pInput->pBase = (uintptr_t)me32.modBaseAddr;
                                CloseHandle(moduleSnapshot);
                                break;
                            }
                        } while (Module32Next(moduleSnapshot, &me32));
                    }
                    CloseHandle(moduleSnapshot);
                }
                if (pid != 0) break;
            } while (Process32Next(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }

    if (pid == 0) {
        printf("[ERROR] Module '%s' not found!\n", moduleName);
        pInput->pStart = NULL;
        pInput->pEnd = NULL;
        pInput->nMaxJunkSteps = 0;
        return;
    }

    printf("[SUCCESS] Found module! PID: %d, Base address: 0x%p\n", pid, pInput->pBase);

    printf("Enter pStart offset (format: 0x123456 or decimal): ");
    scanf("%s", startAddrStr);
    pInput->pStart = (uintptr_t)Transpose((void*)pInput->pBase, strtoul(startAddrStr, NULL, 0));

    printf("Enter pEnd offset (ptr to after array/1st invalid byte) (format: 0x123456 or decimal): ");
    scanf("%s", endAddrStr);
    pInput->pEnd = (uintptr_t)Transpose((void*)pInput->pBase, strtoul(endAddrStr, NULL, 0));
    pInput->nSize = (pInput->pEnd - pInput->pStart) / sizeof(uintptr_t);

    printf("Enter max steps exit (example: 3000): ");
    scanf("%s", maxStepsStr);
    pInput->nMaxJunkSteps = atoi(maxStepsStr);

    printf("Enter IDA IDB Base Offset (format: 0x123456 or decimal): ");
    scanf("%s", idaBaseStr);
    pInput->pIDBBase = strtoul(idaBaseStr, NULL, 0);

    printf("\n========================================\n");
    printf("[RESULT] Configuration complete:\n");
    printf("  Module: %s (PID: %d)\n", moduleName, pid);
    printf("  Base address: 0x%p\n", (void*)pInput->pBase);
    printf("  Start address: 0x%p\n", (void*)pInput->pStart);
    printf("  End address: 0x%p\n", (void*)pInput->pEnd);
    printf("  Size: %d\n", pInput->nSize);
    printf("  Max steps: %d\n", pInput->nMaxJunkSteps);
    printf("  Ida Base Offset: 0x%p\n", (void*)pInput->pIDBBase);
    printf("========================================\n\n");
}

//static std::mutex g_workerMutex;
std::atomic<bool> g_veh_inited{ false };
std::atomic<bool> g_veh_completed{ false };
std::atomic<int> g_veh_slot{ -1 };
std::atomic<uintptr_t> g_veh_result{ NULL };
std::atomic<HANDLE> g_hThread{ NULL };
std::atomic<HANDLE> g_hWorkerThread{ NULL };

DWORD CALLBACK WorkerEntry(LPVOID lpParam)
{
    uintptr_t* pIATEntry = (uintptr_t*)lpParam;
    assert(pIATEntry);
    printf("pIATEntry: 0x%p\n", pIATEntry);

    // Блокируем мьютекс - поток остановится здесь до получения блокировки
    //std::unique_lock<std::mutex> lock(g_workerMutex);
    //lock.unlock();

    while (!g_veh_inited.load(std::memory_order_acquire)) {
        Sleep(1);
    }

    printf("pIATEntry: 0x%p\n", pIATEntry);


#if 1
    ((void(__stdcall*)())pIATEntry)();
#else
    __asm {
        mov eax, pIATEntry
        jmp eax
    }
#endif

    return TRUE;
}

//void OnVeh(void* p, CONTEXT* ctx, VEHContext* vctx)
//{
//    // esp todo prologue offset, allways 6b? sub esp, 2A8h 
////#define ESP(o) ((int*)(((char*)ctx->Esp) + o)) // вершина стека (адрес меньше, стремится к 0) // для push pop указывает на конец выделенной области
//#define EBP(o) ((int*)(((char*)ctx->Ebp) + o)) // база стека (адрес больше) ставится в прологе, используй FUNC_PROLOGUE_OFFSET
//
//    //int size = *EBP(0x10);
//    printf("OnVeh %p", p);
//    printf("OnVeh %p", p);
//    printf("OnVeh %p", p);
//    printf("OnVeh %p", p);
//
//    g_veh_completed.store(true, std::memory_order_release);
//
//    while (true)
//    {
//        printf("OnVeh %p", p);
//        Sleep(1000);
//    }
//}

__declspec(naked) void NakedFunc()
{
    __asm
    {
        // Your assembly code here
        ret
    }
}

 void OnVehNew(void* p, CONTEXT* ctx, const vehdbg::HitInfo& hit)
 {
     //#define ESP(o) ((int*)(((char*)ctx->Esp) + o)) // вершина стека (адрес меньше, стремится к 0) // для push pop указывает на конец выделенной области
#define EBP(o) ((int*)(((char*)ctx->Ebp) + o)) // база стека (адрес больше) ставится в прологе, используй FUNC_PROLOGUE_OFFSET

    //int size = *EBP(0x10);
     printf("VEH hit slot=%d addr=%p\n", hit.slot, (void*)hit.address);

     g_veh_result.store(*(uintptr_t*)ctx->Esp, std::memory_order_release);

     HANDLE h = g_hWorkerThread.load(std::memory_order_acquire);
     if (h != NULL)
     {
         vehdbg::RemoveBreakpoint(g_veh_slot.load(std::memory_order_acquire));
         ////UninstallForSingleThread(g_hWorkerThread, current_dr_index);
         //DWORD waitResult = WaitForSingleObject(h, 1000);
         //if (waitResult == WAIT_TIMEOUT) {
         //    printf("[OnVehNew] Worker thread terminating\n");
         //    TerminateThread(h, 0);
         //}
         g_veh_completed.store(true, std::memory_order_release);
         TerminateThread(h, 0);
         CloseHandle(h);
        // g_hWorkerThread.store(NULL, std::memory_order_release);
     }
     g_veh_completed.store(true, std::memory_order_release); // huh?

     //while (true)
     //{
     //    printf("OnVeh %p", p);
     //    Sleep(1000);
     //}

     // Don't block here.
 }

 // anti ASLR for dumped idb "used_only_iat_sections_dummy.txt"
 uintptr_t TransposeLibBase(uintptr_t p)
 {
     struct tASLRNode {
         uintptr_t pIdbIATFunc;
         const char* pFuncName;
         const char* pLibName;
     };
     std::vector<tASLRNode> idbUnwrap =
     { // резольвнул по порядку в рантайме, фиксанул имена, нашёл уникальные неврапнутые либы, слинковал их тут, теперь для генерации seg найдём базу либы в idb
        // unique unwrapped dll funcs in idb for gen sig
        { 0x76670B10, "CloseServiceHandle", "advapi32.dll" },
        { 0x76BE7280, "CertGetNameStringW", "CRYPT32.dll" },
        { 0x77934F10, "GetLastError", "KERNEL32.DLL" },
        { 0x77BAA210, "RtlEnterCriticalSection", "ntdll.dll" },
        { 0x7771A870, "SysAllocString", "OLEAUT32.dll" },
        { 0x76AAFCB0, "MessageBoxW", "USER32.dll" },
        { 0x63A13880, "WinHttpReadData", "WINHTTP.dll" },
        { 0x76860C30, "WinVerifyTrust", "WINTRUST.dll" },
        { 0x77800370, "bind", "WS2_32.dll" },
     };

     printf("TransposeLibBase(0x%p) => ", p);
     for (const auto& node : idbUnwrap) {
         HMODULE hLib = GetModuleHandleA(node.pLibName);
         if (!hLib) continue;
         if (reinterpret_cast<uintptr_t>(hLib) == p) {
             FARPROC pFunc = GetProcAddress(hLib, node.pFuncName);
             if (pFunc)
             {
                 // idbBase = pIdbIATFunc - (pFunc - hLib)
                 // idbBase = pIdbIATFunc - pFunc + p
                 uintptr_t idbBase = (node.pIdbIATFunc - reinterpret_cast<uintptr_t>(pFunc) + p);
                 printf("Rebased 0x%p\n", idbBase);
                 return idbBase;
             }
         }
     }

     printf("Orig 0x%p (%s)\n", (void*)p, GetModuleName((HMODULE)p).c_str());
     return p;
 }

void PerformFix(tInputData* pInput)
{
    enum eErr {
        API_RESOLVED = 0,
        NULL_POINTER, // probably dynamic load?
        ALREADY_RESOLVED,
        JUNK_RESOLVED_STEPS_LIMIT,
        RET_ADDR_NOT_EXISTS_IN_EXPORTS,
    };

    struct tLazyImportNode {
        uintptr_t pApi; // resolved
        uintptr_t pIAT; // iat
        uintptr_t pIATWrapper; // iat wrapper
        uint32_t nErr; // eErr
    };
    std::vector<tLazyImportNode> db;

    assert(pInput);
    // IAT: can be NULL
    uintptr_t* pIAT = (uintptr_t*)pInput->pStart; // 0x47B000
    uintptr_t* pIATInvalid = (uintptr_t*)pInput->pEnd; // 0x47B508 // dt 0x508 sz 0x142 = 322

    std::unordered_map<uintptr_t, ExportInfo> exports; // <funcPtr, Info>
    CollectAllExports(exports);
    printf("Total exports: %d\n", exports.size());

    vehdbg::Initialize();

    //DWORD suspendCount = SuspendThread((HANDLE));
    //if (suspendCount == (DWORD)-1) {
    //    printf("SuspendThread Error\n");
    //    return;
    //}

    // runtime reslove link + pic
    for (uint32_t i = 0; i < pInput->nSize; ++i) {
        SetConsoleColor(3);
        printf("[PerformFix]: fix %d / %d  pp 0x%p p 0x%p ", i, pInput->nSize, &pIAT[i], pIAT[i]);
        SetConsoleColor(1);
        if (pIAT[i] == 0x0) {
            printf("[SKIP NULL IMPORT]\n");
            db.push_back({0, (uintptr_t)&pIAT[i], 0, NULL_POINTER});
            continue;
        }
        auto it = exports.find(pIAT[i]);
        if (it != exports.end()) {
            db.push_back({ pIAT[i], (uintptr_t)&pIAT[i], /*pIAT[i]*/0, ALREADY_RESOLVED });
            const ExportInfo& exp = it->second;
            printf("[ALREADY IN EXPORTS] %s!%s (base:0x%p rva:0x%X) - SKIP\n",
                exp.moduleName.c_str(),
                exp.funcName.c_str(),
                (void*)exp.moduleBase,
                exp.funcRva);
            continue;
        }

        AsmRunner jit;
        jit.Run((void*)pIAT[i], pInput->nMaxJunkSteps, false);

        g_veh_slot.store(-1, std::memory_order_release);

        if (jit.bFindRet) {
            printf("[SUCCESS: steps %d, ret ip 0x%p, RVA 0x%p]\n", jit.nStepCount, jit.m_ip, (jit.m_ip - ((uint8_t*)pInput->pBase)));

            //std::unique_lock<std::mutex> lock(g_workerMutex);
            g_veh_completed.store(false, std::memory_order_release);
            g_veh_inited.store(false, std::memory_order_release);
            g_veh_result.store(NULL, std::memory_order_release);
            g_hWorkerThread.store(NULL, std::memory_order_release);

            int tid = -1;
            g_hWorkerThread.store(CreateThread(NULL, 0, WorkerEntry, (void*)pIAT[i], 0, (LPDWORD)&tid), std::memory_order_release);
            Sleep(10);
            //assert(g_hWorkerThread != NULL);
            printf("0x%X 0x%X\n", g_hWorkerThread.load(std::memory_order_acquire), tid);

            //SetThreadPriority(g_hWorkerThread.load(std::memory_order_acquire) , THREAD_PRIORITY_NORMAL);
            //int current_dr_index = 0;
            //bool bInstalled = InstallForSingleThread(g_hWorkerThread.load(std::memory_order_acquire) , (void*)jit.m_ip, OnVeh, current_dr_index);

            // no VEH method
            // todo read 5 bytes
            //InsertJump(jit.m_ip, NakedFunc); // in nacked write 5 bytes back

            g_veh_slot.store(vehdbg::AddBreakpoint(jit.m_ip, OnVehNew, nullptr, vehdbg::BreakType::Execute, vehdbg::BreakSize::Size1, true, true));
             if (g_veh_slot.load(std::memory_order_acquire) < 0) {
                 printf("[ERROR] Failed to install VEH breakpoint %d\n", GetLastError());
                 CloseHandle(g_hWorkerThread.load(std::memory_order_acquire));
                 g_hWorkerThread.store(NULL, std::memory_order_release);
                 jit.Reset();
                 continue;
             }


            //DumpThreadDebugRegisters(g_hWorkerThread);
            ////bool bInstalled = InstallForSingleThread(g_hWorkerThread, tmp, OnVeh, -1);
            //bool bInstalled = InstallForAllThreads(tmp, OnVeh, -1);
            //DumpThreadDebugRegisters(g_hWorkerThread);

            //if (!bInstalled) {
            //    printf("[ERROR] Failed to install VEH breakpoint %d\n", GetLastError());
            //    CloseHandle(g_hWorkerThread);
            //    g_hWorkerThread = NULL;
            //    jit.Reset();
            //    continue;
            //}

            //lock.unlock(); // start run
            g_veh_inited.store(true, std::memory_order_release);

            while (!g_veh_completed.load(std::memory_order_acquire)) {
                Sleep(1);
            }

            printf("Got iat return 0x%p\n", (void*)g_veh_result.load(std::memory_order_acquire)); // real iat from realtime PIC
            //assert(exports.find(g_veh_result.load()) != exports.end()); // 114 0x60F00000+0x01B985A2 themida jmp?
            if(exports.find(g_veh_result.load()) != exports.end())
                db.push_back({ g_veh_result.load(), (uintptr_t)&pIAT[i], pIAT[i], API_RESOLVED });
            else
                db.push_back({ g_veh_result.load(), (uintptr_t)&pIAT[i], pIAT[i], RET_ADDR_NOT_EXISTS_IN_EXPORTS });

            Sleep(1000);

            //if (g_hWorkerThread != NULL) { // mostly in VEH
            //    vehdbg::RemoveBreakpoint(g_veh_slot.load(std::memory_order_acquire));
            //    //UninstallForSingleThread(g_hWorkerThread, current_dr_index);
            //    DWORD waitResult = WaitForSingleObject(g_hWorkerThread, 1000);
            //    if (waitResult == WAIT_TIMEOUT) {
            //        printf("[WARNING] Worker thread timeout, terminating\n");
            //        TerminateThread(g_hWorkerThread, 0);
            //    }
            //    CloseHandle(g_hWorkerThread);
            //    g_hWorkerThread = NULL;
            //}
        }
        else {
            printf("[SKIP MAX JUNK STEPS NO RETURN]\n");
            db.push_back({ 0, (uintptr_t)&pIAT[i], pIAT[i], JUNK_RESOLVED_STEPS_LIMIT });
        }

        jit.Reset();
    }

    vehdbg::Shutdown();

    //suspendCount = ResumeThread((HANDLE));

    // DUMP:
    //1. rename idc самой таблицы и враперов // fix_idc.txt [idc fix iat + wrappers]
    //2. дамп маппинга системных dll которые используются в importtable + дамп функций из dll которые прописаны в iat // iat.txt [iat review]
    //3. gen segments заглушки системных dll которые используются в iat + заглушки на функции, так меньше памяти весить будет база // iat_sections_dummy.txt [idc gen seg for dll+funcs] // MEMORY[0x1234] fixer
    //4. all export table

    // gen fix idc code
    FILE* file = fopen("fix_idc.txt", "w");
    if (file == nullptr) {
        printf("File Error\n");
        return;
    }

    for (uint32_t i = 0; i < db.size(); ++i)
    {
        uintptr_t pIATRVA = (db[i].pIAT - pInput->pBase);
        std::string name = "iat_unknown_" + std::to_string(i);
        uintptr_t pIATRVAWrapper = (db[i].pIATWrapper - pInput->pBase);
        std::string nameWrapper = "iat_unknown_wrapper_" + std::to_string(i);
        bool bFixFrapper = false;

        switch (db[i].nErr)
        {
            case API_RESOLVED:
            case ALREADY_RESOLVED:
            {
                auto it = exports.find(db[i].pApi);
                assert(it != exports.end());
                const ExportInfo& exp = it->second;
                name = SanitizeIdaName(exp.funcName + "__" + exp.moduleName);
                if (db[i].nErr == API_RESOLVED) {
                    nameWrapper = SanitizeIdaName(exp.funcName + "_Wrapper_" + exp.moduleName);
                    bFixFrapper = true;
                }
                break;
            }
            case NULL_POINTER:
            {
                name = "IAT_NULL_" + std::to_string(i);
                break;
            }
            case JUNK_RESOLVED_STEPS_LIMIT:
            {
                name = "IAT_JUNK_LIMIT_" + std::to_string(i);
                nameWrapper = "IAT_JUNK_LIMIT_WRAPPER_" + std::to_string(i);
                bFixFrapper = true;
                break;
            }
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                char addrBuffer[32];
                //sprintf_s(addrBuffer, "_0x%p", db[i].pApi); // raw esp
                sprintf_s(addrBuffer, "_0x%p", (db[i].pApi - pInput->pBase) + pInput->pIDBBase); // todo recheck pApi is in module + size
                name = "IAT_TODO_NOT_IN_EXPORTS_" + std::to_string(i) + std::string(addrBuffer);
                nameWrapper = "IAT_TODO_NOT_IN_EXPORTS_WRAPPER_" + std::to_string(i) + std::string(addrBuffer);
                bFixFrapper = true;
                break;
            }
        }

        fprintf(file, "set_name(0x%p, \"%s\", SN_AUTO);\n", (void*)(pIATRVA + pInput->pIDBBase), name.c_str()); // 0x60F00000
        if (bFixFrapper) {
            fprintf(file, "set_name(0x%p, \"%s\", SN_AUTO);\n", (void*)(pIATRVAWrapper + pInput->pIDBBase), nameWrapper.c_str());
            //fprintf(file, "SetColor(0x%p, CIC_FUNC, 0x685328);\n", (void*)(pIATRVAWrapper + pInput->pIDBBase)); // BGR
            fprintf(file, "SetColor(0x%p, CIC_FUNC, 0x734500);\n", (void*)(pIATRVAWrapper + pInput->pIDBBase)); // BGR, non native import color
            fprintf(file, "SetType(0x%p, \"int F(int a1, int a2, int a3, int a4, int a5, int a6, int a7)\");\n", (void*)(pIATRVAWrapper + pInput->pIDBBase));
        }
    }

    fclose(file);
    file = nullptr;

    // gen import
    file = fopen("iat.txt", "w");
    if (file == nullptr) {
        printf("File Error\n");
        return;
    }

    // lib mapping
    std::unordered_map<uintptr_t, std::string> uniqueLibs;
    fprintf(file, "#libs\n");

    for (uint32_t i = 0; i < db.size(); ++i)
    {
        switch (db[i].nErr)
        {
            case API_RESOLVED:
            case ALREADY_RESOLVED:
            {
                auto it = exports.find(db[i].pApi);
                assert(it != exports.end());
                const ExportInfo& exp = it->second;
                if (uniqueLibs.find(exp.moduleBase) == uniqueLibs.end())
                {
                    uniqueLibs[exp.moduleBase] = exp.moduleName;
                    fprintf(file, "0x%p   \"%s\"\n", (void*)exp.moduleBase, exp.moduleName.c_str());
                }
                break;
            }
            case NULL_POINTER:
            case JUNK_RESOLVED_STEPS_LIMIT:
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                break;
            }
        }
    }
    uniqueLibs.clear();

    fprintf(file, "\n#iat\n");

    for (uint32_t i = 0; i < db.size(); ++i)
    {
        switch (db[i].nErr)
        {
            case API_RESOLVED:
            case ALREADY_RESOLVED:
            {
                auto it = exports.find(db[i].pApi);
                assert(it != exports.end());
                const ExportInfo& exp = it->second;
                uintptr_t f = exp.moduleBase + exp.funcRva;
                fprintf(file, "%d   0x%p   \"%s\"   \"%s\"\n", i, (void*)f, exp.funcName.c_str(), exp.moduleName.c_str());
                break;
            }
            case NULL_POINTER:
            case JUNK_RESOLVED_STEPS_LIMIT:
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                break;
            }
        }
    }

    fclose(file);
    file = nullptr;

    // make dummy sections
    file = fopen("iat_sections_dummy.txt", "w");
    if (file == nullptr) {
        printf("File Error\n");
        return;
    }

    FILE* fileR = fopen("ALREADY_RESOLVED.txt", "w");
    if (fileR == nullptr) {
        printf("File Error\n");
        return;
    }

    fprintf(file, "#idc_func_dummy\n"); // можно и замаппить dll но база станет много весить
    fprintf(fileR, "#funcs\n");
    for (uint32_t i = 0; i < db.size(); ++i) // сегменты функций заглушек
    {
        switch (db[i].nErr)
        {
            case ALREADY_RESOLVED:
            {
                auto it = exports.find(db[i].pApi);
                assert(it != exports.end());
                const ExportInfo& exp = it->second;
                std::string nameS = SanitizeIdaName(exp.funcName + "__" + exp.moduleName);
                std::string nameF = "IAT_" + SanitizeIdaName(exp.funcName);
                uintptr_t pStart = TransposeLibBase(exp.moduleBase) + exp.funcRva;
                uintptr_t pEnd = pStart + 4; // dummy

                // dummy small seg
                fprintf(file, "AddSegEx(0x%p, 0x%p, 0, 1, 3, 2, ADDSEG_QUIET);\n", (void*)pStart, (void*)pEnd);
                fprintf(file, "SetSegmentAttr(0x%p, SEGATTR_PERM, 7);\n", (void*)pStart);
                fprintf(file, "SegClass(0x%p, \"CODE\");\n", (void*)pStart);
                fprintf(file, "RenameSeg(0x%p, \"API_SEG_%s\");\n", (void*)pStart, nameS.c_str());

                //SetType(addr, "CObject");
                //set_cmt(0x0938D400, "abc", 0);

                // create dummy function as in psp nid import
                fprintf(file, "PatchByte(0x%p, 0xC3);\n", (void*)pStart);
                fprintf(file, "MakeCode(0x%p);\n", (void*)pStart);
                fprintf(file, "add_func(0x%p, BADADDR);\n", (void*)pStart);
                fprintf(file, "set_name(0x%p, \"%s\", SN_AUTO);\n", (void*)pStart, nameF.c_str());
                fprintf(file, "SetColor(0x%p, CIC_FUNC, 0x685328);\n", (void*)pStart); // BGR
                fprintf(file, "SetType(0x%p, \"int F(int a1, int a2, int a3, int a4, int a5, int a6, int a7)\");\n", (void*)pStart);
                
                fprintf(fileR, "0x%p   \"%s\"   \"%s\"\n", (void*)pStart, exp.funcName.c_str(), exp.moduleName.c_str());
                break;
            }
            case API_RESOLVED:
            case NULL_POINTER:
            case JUNK_RESOLVED_STEPS_LIMIT:
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                break;
            }
        }
    }

    fclose(fileR);
    fileR = nullptr;

    // lib segment mapping
    fprintf(file, "\n\n\n\n\n");
    fprintf(file, "#idc_libs_dummy\n");

    for (uint32_t i = 0; i < db.size(); ++i) // сегменты dll base
    {
        switch (db[i].nErr)
        {
            case API_RESOLVED:
            case ALREADY_RESOLVED:
            {
                auto it = exports.find(db[i].pApi);
                assert(it != exports.end());
                const ExportInfo& exp = it->second;
                if (uniqueLibs.find(exp.moduleBase) == uniqueLibs.end())
                {
                    uniqueLibs[exp.moduleBase] = exp.moduleName;

                    std::string nameS = SanitizeIdaName(exp.moduleName);
                    nameS = exp.moduleName;
                    uintptr_t pStart = TransposeLibBase(exp.moduleBase);
                    uintptr_t pEnd = pStart + 4; // dummy

                    // dummy small seg
                    fprintf(file, "AddSegEx(0x%p, 0x%p, 0, 1, 3, 2, ADDSEG_QUIET);\n", (void*)pStart, (void*)pEnd);
                    fprintf(file, "SetSegmentAttr(0x%p, SEGATTR_PERM, 7);\n", (void*)pStart);
                    fprintf(file, "SegClass(0x%p, \"CODE\");\n", (void*)pStart);
                    fprintf(file, "RenameSeg(0x%p, \".%s\");\n", (void*)pStart, nameS.c_str());
                }
                break;
            }
            case NULL_POINTER:
            case JUNK_RESOLVED_STEPS_LIMIT:
            case RET_ADDR_NOT_EXISTS_IN_EXPORTS:
            {
                break;
            }
        }
    }
    uniqueLibs.clear();

    fclose(file);
    file = nullptr;


    // export
    file = fopen("export.txt", "w");
    if (file == nullptr) {
        printf("File Error\n");
        return;
    }

    for (auto it = exports.begin(); it != exports.end(); ++it) {
        const ExportInfo& exp = it->second;
        fprintf(file, "0x%p \"%s\" \"%s\"\n",
            (void*)(exp.moduleBase + exp.funcRva),
            exp.funcName.c_str(),
            exp.moduleName.c_str());
    }

    fclose(file);
    file = nullptr;
}

DWORD CALLBACK ThreadEntry(LPVOID lpParam)
{
    tInputData data;
    printf("Import Fixer By MaZaHaKa\n");
    printf("WorkerEntry: 0x%p\n", WorkerEntry);

    GetInputData(&data);
    if (data.pStart == NULL || data.pEnd == NULL || data.pStart == data.pEnd || (uintptr_t)data.pStart > (uintptr_t)data.pEnd ||
        ((uintptr_t)data.pEnd - (uintptr_t)data.pStart) % sizeof(uintptr_t) != 0 || data.nMaxJunkSteps <= 0) {
        printf("[ERROR] Invalid input data!\n");
        system("pause");
        return TRUE;
    }

    PerformFix(&data);

    printf("Import Fixer Done!\n");
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            InitConsole();
            DisableThreadLibraryCalls(hModule);
            GetModuleFileName(hModule, g_dllPath, MAX_PATH);

            g_hThread = CreateThread(NULL, 0, ThreadEntry, g_dllPath, 0, NULL);
            if (g_hThread == NULL) {
                MessageBox(NULL, "Failed to create thread!", "Error", MB_OK | MB_ICONERROR);
            }
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            break;

        case DLL_PROCESS_DETACH:
            if (g_hThread != NULL) {
                WaitForSingleObject(g_hThread, 5000);
                CloseHandle(g_hThread);
                g_hThread = NULL;
            }
            break;
    }
    return TRUE;
}