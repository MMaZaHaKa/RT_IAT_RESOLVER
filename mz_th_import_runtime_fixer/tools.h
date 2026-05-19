#define _CRT_SECURE_NO_WARNINGS
#include "Windows.h"
#include <winnt.h>
#include <cstdint>
#include <iostream>
#include <string>
#include <map>
#include <unordered_map>

void* SearchPointerByPattern(void* ptrStart, int block_size, std::string pattern);

HANDLE InitConsole();
void SetConsoleColor(int32_t mode);

class AsmRunner {
public:
    uint8_t* m_ip = nullptr;
    uint32_t nStepCount = 0;
    bool bFindRet = false;

private:
    std::vector<uint64_t> m_visited;
    std::map<uint64_t, int> m_jumpCount;
    bool bLog = true;

    struct Instruction {
        uint32_t length = 0;
        uint8_t opcode = 0;
        bool isJump = false;
        bool isCall = false;
        bool isConditional = false;
        bool isRet = false;
        bool isRelative = false;
        int32_t displacement = 0;
    };

    void Log(const std::string& message);
    static std::string PtrToStrDec(const void* p);
    static std::string PtrToStr(const void* p);
    static bool IsReadable(const void* addr, size_t len);
    template<typename T>
    static bool SafeRead(const void* addr, T& out);
    static const uint8_t* SkipPrefixes(const uint8_t* pc);
    Instruction DecodeInstruction(uint8_t* pc);
    static uint8_t* CalcRelativeTarget(uint8_t* pc, uint32_t len, int32_t disp);

public:
    AsmRunner() = default;
    void Run(void* startAddress, uint32_t maxJunkSteps, bool log = false);
    void Reset();
};


struct ExportInfo
{
    std::string moduleName;
    std::string funcName;
    uintptr_t moduleBase;
    DWORD funcRva;
};

std::string GetProcessName();
std::string GetModuleName(HMODULE hMod);

void AddExportsFromModule(HMODULE hMod, std::unordered_map<uintptr_t, ExportInfo>& addrToInfo);
void CollectAllExports(std::unordered_map<uintptr_t, ExportInfo>& addrToInfo);


//enum class eVEH : uint8_t {
//    BREAK_ON_EXECUTE = 0b00,
//    BREAK_ON_WRITE = 0b01,
//    BREAK_ON_ACCESS = 0b11
//};
//
//enum class eBREAK_SIZE : uint8_t {
//    SIZE_1_BYTE = 0b00,
//    SIZE_2_BYTES = 0b01,
//    SIZE_4_BYTES = 0b11,
//    SIZE_8_BYTES = 0b10
//};
//
//#define FUNC_PROLOGUE_EBP_OFFSET(p) (((char*)p) + 1 + 2) // push ebp, mov ebp, esp // for bp when ebp is ready for new frame
////#define FUNC_PROLOGUE_ESP_OFFSET(p) (((char*)p) + 6) // sub esp, 2A8h // recheck allways 6 b? // если нет локальных переменных инструкции вообще нет
//#define FUNC_PROLOGUE_OFFSET(p) FUNC_PROLOGUE_EBP_OFFSET(p) // FUNC_PROLOGUE_ESP_OFFSET(FUNC_PROLOGUE_EBP_OFFSET(p))
//
//struct VEHContext;
//typedef void (*VEH_CALLBACK)(void* p, CONTEXT* ctx, VEHContext* vctx);
////typedef LONG(WINAPI* VEH_HANDLER)(PEXCEPTION_POINTERS ExceptionInfo);
//
//struct VEHContext {
//    void* callback_param = nullptr;
//    uintptr_t break_address = 0;
//    int dr_index = -1;
//    uint64_t fake_value = 0;
//    eVEH break_type = eVEH::BREAK_ON_EXECUTE;
//    eBREAK_SIZE break_size = eBREAK_SIZE::SIZE_1_BYTE;
//    VEH_CALLBACK user_callback = nullptr;
//    bool bSingle = true;
//    bool bMultiThread = false;
//    bool active = false;
//#if 1
//};
//extern std::vector<VEHContext> g_veh_ctx; // max 4
//
//bool InstallForSingleThread(HANDLE hThread, void* p, VEH_CALLBACK cb, int dr_index = -1, bool bSingle = true, eVEH breakType = eVEH::BREAK_ON_EXECUTE, eBREAK_SIZE breakSize = eBREAK_SIZE::SIZE_1_BYTE);
//bool UninstallForSingleThread(HANDLE hThread, int drIndex);
//bool InstallForAllThreads(void* p, VEH_CALLBACK cb, int drIndex = -1, bool bSingle = true, eVEH breakType = eVEH::BREAK_ON_EXECUTE, eBREAK_SIZE breakSize = eBREAK_SIZE::SIZE_1_BYTE);
//void UninstallForAllThreads();
//void UpdateVeh(void); // when new thread
//void DumpThreadDebugRegisters(HANDLE hThread);
//
//LONG WINAPI MyVEH(PEXCEPTION_POINTERS ExceptionInfo);
//#else
//};
//
//extern VEHContext g_veh_ctx;
//bool InstallVehOnAllThreads(void* p, int drIndex = -1, eVEH breakType = eVEH::BREAK_ON_EXECUTE, eBREAK_SIZE breakSize = eBREAK_SIZE::SIZE_1_BYTE);
//void UpdateVeh(void); // when new thread
//#endif