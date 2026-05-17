#define WIN32_LEAN_AND_MEAN
#include "tools.h"

#include <psapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <vector>

#include "hdeminhook/hde32.h" // https://github.com/TsudaKageyu/minhook/tree/master/src/hde

void* SearchPointerByPattern(void* ptrStart, int block_size, std::string pattern)
{
#define INRANGE(x, a, b) (x >= a && x <= b)
#define getBits(x) (INRANGE((x & (~0x20)), 'A', 'F') ? ((x & (~0x20)) - 'A' + 0xa) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x) (getBits(x[0]) << 4 | getBits(x[1]))
	const char* buffptr_pattern = pattern.c_str();
	uintptr_t pMatch = 0;
	for (uintptr_t MemPtr = (uintptr_t)ptrStart; MemPtr < ((uintptr_t)ptrStart + block_size); MemPtr++)
	{
		if (!*buffptr_pattern) { break; }
		if (*(PBYTE)buffptr_pattern == '\?' || *(BYTE*)MemPtr == getByte(buffptr_pattern))
		{
			if (!pMatch) { pMatch = MemPtr; }
			if (!buffptr_pattern[2]) { break; } // паттерн закончился
			//PWORD первых 2 символа из паттерна, PBYTE первый символ
			if (*(PWORD)buffptr_pattern == '\?\?' || *(PBYTE)buffptr_pattern != '\?') { buffptr_pattern += 3; }
			else { buffptr_pattern += 2; } //one ?
		}
		else
		{ // срыв совпадения
			buffptr_pattern = pattern.c_str();
			if (pMatch) { MemPtr = pMatch; }
			pMatch = 0;
		}
	}
	//free((void*)buffptr_pattern); // GetProcAddressNoExternCExport
	if (!pMatch) { return NULL; }
	//printf("found str: 0x%p\n", (char*)pMatch);
	return (void*)pMatch;
#undef getByte;
#undef getByte;
#undef INRANGE;
}


HANDLE InitConsole() // with proto
{
	AllocConsole();

	//SetConsoleOutputCP(866);
	//setlocale(LC_ALL, "Russian");
	SetConsoleOutputCP(1251);
	SetConsoleCP(1251);


	freopen("CONIN$", "r", stdin);
	freopen("CONOUT$", "w", stdout);

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);

	return hConsole;
}

void SetConsoleColor(int32_t mode)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (mode == 0)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
	else if (mode == 1)
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
	else if (mode == 2)
		SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE);
	else if (mode == 3)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN);
	else if (mode == 4)
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE);
	else if (mode == 5)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_BLUE);
	else if (mode == 6)
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	else if (mode == 7)
		SetConsoleTextAttribute(hConsole, 0);
}


inline unsigned int oplen(unsigned char* pc)
{ // old usage common/opcode_len_calc.h, but not enought op cases
	hde32s hs{};
	unsigned int len = hde32_disasm(pc, &hs);
	return len ? len : 1; // 0 = ошибка/неизвестная инструкция
}

//======================================
//		ASM Fake Runner
//======================================
#if 0 // cpp
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

	void Log(const std::string& message) {
		if(bLog)
			std::cout << message << std::endl;
	}

	static std::string PtrToStrDec(const void* p) {
		return std::to_string(reinterpret_cast<uint64_t>(p));
	}

	static std::string PtrToStr(const void* p) {
		std::stringstream ss;
		ss << "0x" << std::hex << std::setw(16) << std::setfill('0')
			<< reinterpret_cast<uint64_t>(p);
		return ss.str();
	}

	static bool IsReadable(const void* addr, size_t len) {
		const uint8_t* p = static_cast<const uint8_t*>(addr);
		const uint8_t* end = p + len;

		while (p < end) {
			MEMORY_BASIC_INFORMATION mbi{};
			if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
			if (mbi.State != MEM_COMMIT) return false;

			const DWORD prot = mbi.Protect & 0xFF;
			if (prot == PAGE_NOACCESS || prot == PAGE_GUARD) return false;

			uint8_t* regionEnd = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
			if (regionEnd <= p) return false;
			p = (regionEnd < end) ? regionEnd : end;
		}
		return true;
	}

	template<typename T>
	static bool SafeRead(const void* addr, T& out) {
		if (!IsReadable(addr, sizeof(T))) return false;
		std::memcpy(&out, addr, sizeof(T));
		return true;
	}

	static const uint8_t* SkipPrefixes(const uint8_t* pc) {
		const uint8_t* p = pc;
		while (true) {
			uint8_t op = *p;
			switch (op) {
			case 0x64: case 0x65:
			case 0x36:
			case 0x66: case 0x67:
			case 0xF0: case 0xF2: case 0xF3:
			case 0x2E: case 0x3E:
				++p;
				break;
			default:
				return p;
			}
		}
	}

	Instruction DecodeInstruction(uint8_t* pc) {
		Instruction inst{};
		if (!IsReadable(pc, 1)) return inst;

		unsigned int len = oplen(pc);
		if (len == 0) return inst;
		if (!IsReadable(pc, len)) return inst;

		inst.length = len;

		const uint8_t* p = SkipPrefixes(pc);
		inst.opcode = *p;

		// RET variants
		if (inst.opcode == 0xC3 || inst.opcode == 0xC2 ||
			inst.opcode == 0xCB || inst.opcode == 0xCA) {
			inst.isRet = true;
			return inst;
		}

		// short Jcc
		if (inst.opcode >= 0x70 && inst.opcode <= 0x7F) {
			int8_t disp = 0;
			if (!SafeRead(p + 1, disp)) return {};
			inst.isJump = true;
			inst.isConditional = true;
			inst.isRelative = true;
			inst.displacement = disp;
			return inst;
		}

		// short JMP
		if (inst.opcode == 0xEB) {
			int8_t disp = 0;
			if (!SafeRead(p + 1, disp)) return {};
			inst.isJump = true;
			inst.isRelative = true;
			inst.displacement = disp;
			return inst;
		}

		// near CALL/JMP
		if (inst.opcode == 0xE8 || inst.opcode == 0xE9) {
			int32_t disp = 0;
			if (!SafeRead(p + 1, disp)) return {};
			inst.isRelative = true;
			inst.displacement = disp;
			if (inst.opcode == 0xE8) inst.isCall = true;
			else inst.isJump = true;
			return inst;
		}

		// near Jcc: 0F 80..8F rel32
		if (p[0] == 0x0F && p[1] >= 0x80 && p[1] <= 0x8F) {
			int32_t disp = 0;
			if (!SafeRead(p + 2, disp)) return {};
			inst.isJump = true;
			inst.isConditional = true;
			inst.isRelative = true;
			inst.displacement = disp;
			return inst;
		}

		// остальные инструкции просто идут по длине
		return inst;
	}

	static uint8_t* CalcRelativeTarget(uint8_t* pc, uint32_t len, int32_t disp) {
		return pc + len + disp;
	}

public:
	AsmRunner() = default;

	void Run(void* startAddress, uint32_t maxJunkSteps, bool log = false) {
		m_ip = static_cast<uint8_t*>(startAddress);
		bLog = log;
		nStepCount = 0;

		Log("=== Starting ASM Runner ===");

		while (m_ip && nStepCount < maxJunkSteps) {
			if (!IsReadable(m_ip, 1)) {
				Log("Unreadable IP: " + PtrToStr(m_ip));
				break;
			}

			++nStepCount;

			uint64_t currentAddr = reinterpret_cast<uint64_t>(m_ip);
			if (std::find(m_visited.begin(), m_visited.end(), currentAddr) != m_visited.end()) {
				Log("Already visited address " + PtrToStr(m_ip) + " - loop detected");
				break;
			}
			m_visited.push_back(currentAddr);

			Instruction inst = DecodeInstruction(m_ip);
			if (inst.length == 0) {
				Log("Decode failed at " + PtrToStr(m_ip));
				break;
			}

			Log("IP: " + PtrToStr(m_ip) + " len=" + std::to_string(inst.length));

			if (inst.isRet) {
				Log("RET found at " + PtrToStr(m_ip));
				bFindRet = true;
				break;
			}

			if (inst.isCall) {
				uint8_t* target = CalcRelativeTarget(m_ip, inst.length, inst.displacement);
				Log("CALL to " + PtrToStr(target));
				// линейный режим: call не проваливаем, просто идём дальше
				m_ip += inst.length;
				continue;
			}

			if (inst.isJump) {
				uint8_t* target = CalcRelativeTarget(m_ip, inst.length, inst.displacement);
				if (inst.isConditional) {
					Log("JCC to " + PtrToStr(target));
					// линейный режим: для поиска любого ret обычно удобнее
					// идти дальше по fallthrough, а не прыгать.
					m_ip += inst.length;
				}
				else {
					Log("JMP to " + PtrToStr(target));
					m_ip = target;
				}
				continue;
			}

			m_ip += inst.length;
		}

		if (nStepCount >= maxJunkSteps) {
			Log("Max steps reached (" + std::to_string(maxJunkSteps) + ")");
		}

		Log("=== Execution finished ===");
		Log("Total steps: " + std::to_string(nStepCount));
		Log("Jump count: " + std::to_string(m_jumpCount.size()));
	}

	void Reset() {
		m_ip = nullptr;
		bFindRet = false;
		bLog = true;
		nStepCount = 0;
		m_visited.clear();
		m_jumpCount.clear();
	}
};
#else // cpp/h format
void AsmRunner::Log(const std::string& message) {
	if (bLog)
		std::cout << message << std::endl;
}

std::string AsmRunner::PtrToStrDec(const void* p) {
	return std::to_string(reinterpret_cast<uint64_t>(p));
}

std::string AsmRunner::PtrToStr(const void* p) {
	std::stringstream ss;
	ss << "0x" << std::hex << std::setw(16) << std::setfill('0')
		<< reinterpret_cast<uint64_t>(p);
	return ss.str();
}

bool AsmRunner::IsReadable(const void* addr, size_t len) {
	const uint8_t* p = static_cast<const uint8_t*>(addr);
	const uint8_t* end = p + len;

	while (p < end) {
		MEMORY_BASIC_INFORMATION mbi{};
		if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
		if (mbi.State != MEM_COMMIT) return false;

		const DWORD prot = mbi.Protect & 0xFF;
		if (prot == PAGE_NOACCESS || prot == PAGE_GUARD) return false;

		uint8_t* regionEnd = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
		if (regionEnd <= p) return false;
		p = (regionEnd < end) ? regionEnd : end;
	}
	return true;
}

template<typename T>
bool AsmRunner::SafeRead(const void* addr, T& out) {
	if (!IsReadable(addr, sizeof(T))) return false;
	std::memcpy(&out, addr, sizeof(T));
	return true;
}

const uint8_t* AsmRunner::SkipPrefixes(const uint8_t* pc) {
	const uint8_t* p = pc;
	while (true) {
		uint8_t op = *p;
		switch (op) {
		case 0x64: case 0x65:
		case 0x36:
		case 0x66: case 0x67:
		case 0xF0: case 0xF2: case 0xF3:
		case 0x2E: case 0x3E:
			++p;
			break;
		default:
			return p;
		}
	}
}

AsmRunner::Instruction AsmRunner::DecodeInstruction(uint8_t* pc) {
	Instruction inst{};
	if (!IsReadable(pc, 1)) return inst;

	unsigned int len = oplen(pc);
	if (len == 0) return inst;
	if (!IsReadable(pc, len)) return inst;

	inst.length = len;

	const uint8_t* p = SkipPrefixes(pc);
	inst.opcode = *p;

	if (inst.opcode == 0xC3 || inst.opcode == 0xC2 ||
		inst.opcode == 0xCB || inst.opcode == 0xCA) {
		inst.isRet = true;
		return inst;
	}

	if (inst.opcode >= 0x70 && inst.opcode <= 0x7F) {
		int8_t disp = 0;
		if (!SafeRead(p + 1, disp)) return {};
		inst.isJump = true;
		inst.isConditional = true;
		inst.isRelative = true;
		inst.displacement = disp;
		return inst;
	}

	if (inst.opcode == 0xEB) {
		int8_t disp = 0;
		if (!SafeRead(p + 1, disp)) return {};
		inst.isJump = true;
		inst.isRelative = true;
		inst.displacement = disp;
		return inst;
	}

	if (inst.opcode == 0xE8 || inst.opcode == 0xE9) {
		int32_t disp = 0;
		if (!SafeRead(p + 1, disp)) return {};
		inst.isRelative = true;
		inst.displacement = disp;
		if (inst.opcode == 0xE8) inst.isCall = true;
		else inst.isJump = true;
		return inst;
	}

	if (p[0] == 0x0F && p[1] >= 0x80 && p[1] <= 0x8F) {
		int32_t disp = 0;
		if (!SafeRead(p + 2, disp)) return {};
		inst.isJump = true;
		inst.isConditional = true;
		inst.isRelative = true;
		inst.displacement = disp;
		return inst;
	}

	return inst;
}

uint8_t* AsmRunner::CalcRelativeTarget(uint8_t* pc, uint32_t len, int32_t disp) {
	return pc + len + disp;
}

void AsmRunner::Run(void* startAddress, uint32_t maxJunkSteps, bool log) {
	m_ip = static_cast<uint8_t*>(startAddress);
	bLog = log;
	nStepCount = 0;

	Log("=== Starting ASM Runner ===");

	while (m_ip && nStepCount < maxJunkSteps) {
		if (!IsReadable(m_ip, 1)) {
			Log("Unreadable IP: " + PtrToStr(m_ip));
			break;
		}

		++nStepCount;

		uint64_t currentAddr = reinterpret_cast<uint64_t>(m_ip);
		if (std::find(m_visited.begin(), m_visited.end(), currentAddr) != m_visited.end()) {
			Log("Already visited address " + PtrToStr(m_ip) + " - loop detected");
			break;
		}
		m_visited.push_back(currentAddr);

		Instruction inst = DecodeInstruction(m_ip);
		if (inst.length == 0) {
			Log("Decode failed at " + PtrToStr(m_ip));
			break;
		}

		Log("IP: " + PtrToStr(m_ip) + " len=" + std::to_string(inst.length));

		if (inst.isRet) {
			Log("RET found at " + PtrToStr(m_ip));
			bFindRet = true;
			break;
		}

		if (inst.isCall) {
			uint8_t* target = CalcRelativeTarget(m_ip, inst.length, inst.displacement);
			Log("CALL to " + PtrToStr(target));
			m_ip += inst.length;
			continue;
		}

		if (inst.isJump) {
			uint8_t* target = CalcRelativeTarget(m_ip, inst.length, inst.displacement);
			if (inst.isConditional) {
				Log("JCC to " + PtrToStr(target));
				m_ip += inst.length;
			}
			else {
				Log("JMP to " + PtrToStr(target));
				m_ip = target;
			}
			continue;
		}

		m_ip += inst.length;
	}

	if (nStepCount >= maxJunkSteps) {
		Log("Max steps reached (" + std::to_string(maxJunkSteps) + ")");
	}

	Log("=== Execution finished ===");
	Log("Total steps: " + std::to_string(nStepCount));
	Log("Jump count: " + std::to_string(m_jumpCount.size()));
}

void AsmRunner::Reset() {
	m_ip = nullptr;
	bFindRet = false;
	bLog = true;
	nStepCount = 0;
	m_visited.clear();
	m_jumpCount.clear();
}
#endif


//======================================
//		Export Info
//======================================
std::string GetProcessName()
{
	char path[MAX_PATH] = { 0 };
	GetModuleBaseNameA(GetCurrentProcess(), NULL, path, MAX_PATH);
	return std::string(path);
}

std::string GetModuleName(HMODULE hMod)
{
	char path[MAX_PATH] = { 0 };
	GetModuleBaseNameA(GetCurrentProcess(), hMod, path, MAX_PATH);
	return std::string(path);
}

void AddExportsFromModule(HMODULE hMod, std::unordered_map<uintptr_t, ExportInfo>& addrToInfo)
{
	MODULEINFO mi = { 0 };
	if (!GetModuleInformation(GetCurrentProcess(), hMod, &mi, sizeof(mi)))
		return;

	BYTE* base = reinterpret_cast<BYTE*>(mi.lpBaseOfDll);
	std::string moduleName = GetModuleName(hMod);
	uintptr_t moduleBase = reinterpret_cast<uintptr_t>(base);

	IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
	if (!nt || nt->Signature != IMAGE_NT_SIGNATURE)
		return;

	const auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dir.VirtualAddress || !dir.Size)
		return;

	IMAGE_EXPORT_DIRECTORY* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + dir.VirtualAddress);
	if (!exp)
		return;

	DWORD* funcs = reinterpret_cast<DWORD*>(base + exp->AddressOfFunctions);
	DWORD* names = reinterpret_cast<DWORD*>(base + exp->AddressOfNames);
	WORD* ords = reinterpret_cast<WORD*>(base + exp->AddressOfNameOrdinals);

	std::vector<std::string> perIndex(exp->NumberOfFunctions);

	for (DWORD i = 0; i < exp->NumberOfNames; ++i)
	{
		DWORD idx = ords[i];
		if (idx < exp->NumberOfFunctions)
		{
			const char* nm = reinterpret_cast<const char*>(base + names[i]);
			if (nm && *nm)
				perIndex[idx] = nm;
		}
	}

	DWORD expStart = dir.VirtualAddress;
	DWORD expEnd = dir.VirtualAddress + dir.Size;

	for (DWORD i = 0; i < exp->NumberOfFunctions; ++i)
	{
		DWORD rva = funcs[i];
		if (!rva)
			continue;

		if (rva >= expStart && rva < expEnd)
			continue;

		uintptr_t addr = reinterpret_cast<uintptr_t>(base + rva);

		std::string funcName = perIndex[i];
		if (funcName.empty())
		{
			char tmp[64];
			sprintf_s(tmp, "ord%u", exp->Base + i);
			funcName = tmp;
		}

		if (addrToInfo.find(addr) == addrToInfo.end())
		{
			addrToInfo[addr] = { moduleName, funcName, moduleBase, rva };
		}
	}
}

void CollectAllExports(std::unordered_map<uintptr_t, ExportInfo>& addrToInfo)
{
	HMODULE mods[1024] = { 0 };
	DWORD needed = 0;

	if (!EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods), &needed))
		return;

	size_t count = needed / sizeof(HMODULE);
	for (size_t i = 0; i < count; ++i)
		AddExportsFromModule(mods[i], addrToInfo);
}

#if 1

// TODO: figure out why not work
/*std::vector<VEHContext> g_veh_ctx(4); // max 4

// Глобальная синхронизация
CRITICAL_SECTION g_cs;
bool g_initialized = false;

static inline bool IsValidDrIndex(int drIndex) {
	return drIndex >= 0 && drIndex < 4;
}

static inline void ClearVehContext(int drIndex) {
	if (!IsValidDrIndex(drIndex)) return;
	g_veh_ctx[drIndex] = VEHContext{};
	g_veh_ctx[drIndex].dr_index = -1;
}

static inline VEHContext* GetVehContextByDr(int drIndex) {
	if (!IsValidDrIndex(drIndex)) return nullptr;
	return &g_veh_ctx[drIndex];
}

// Настройка DR7 для конкретного контекста
void SetupDr7(CONTEXT& ctx, int dr_index, eVEH type, eBREAK_SIZE size) {
	int bit_pos = dr_index * 2;
	int type_shift = 16 + (dr_index * 4);
	int len_shift = 18 + (dr_index * 4);

	ctx.Dr7 &= ~(0b11 << type_shift);
	ctx.Dr7 |= (static_cast<uint8_t>(type) << type_shift);

	ctx.Dr7 &= ~(0b11 << len_shift);
	ctx.Dr7 |= (static_cast<uint8_t>(size) << len_shift);

	ctx.Dr7 |= (1 << bit_pos);
}

// Поиск свободного DR регистра для конкретного потока
int FindFreeDrForThread(HANDLE hThread) {
	SuspendThread(hThread);
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		ResumeThread(hThread);
		return -1;
	}
	ResumeThread(hThread);

	for (int i = 0; i < 4; i++) {
		uintptr_t value = 0;
		switch (i) {
		case 0: value = ctx.Dr0; break;
		case 1: value = ctx.Dr1; break;
		case 2: value = ctx.Dr2; break;
		case 3: value = ctx.Dr3; break;
		}
		if (value == 0) return i;
	}

	return -1;
}

// Установка брейкпоинта для одного потока
bool InstallForSingleThread(HANDLE hThread, void* p, VEH_CALLBACK cb, int dr_index, bool bSingle, eVEH breakType, eBREAK_SIZE breakSize)
{
	if (!hThread || !p) {
		printf("hThread 0x%X, p 0x%X\n", hThread, p);
		return false;
	}

	if (!g_initialized) {
		InitializeCriticalSection(&g_cs);
		AddVectoredExceptionHandler(1, MyVEH);
		g_initialized = true;
	}

	uintptr_t break_address = (uintptr_t)p;

	if (dr_index == -1) {
		dr_index = FindFreeDrForThread(hThread);
	}

	if (!IsValidDrIndex(dr_index)) {
		printf("!IsValidDrIndex(%d)\n", dr_index);
		return false;
	}

	SuspendThread(hThread);

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		printf("!GetThreadContext(%d)\n", hThread);
		return false;
	}

	switch (dr_index) {
	case 0: ctx.Dr0 = break_address; break;
	case 1: ctx.Dr1 = break_address; break;
	case 2: ctx.Dr2 = break_address; break;
	case 3: ctx.Dr3 = break_address; break;
	default:
		printf("default\n");
		return false;
	}

	SetupDr7(ctx, dr_index, breakType, breakSize);

	bool res = SetThreadContext(hThread, &ctx) != FALSE;
	if (!res) {
		printf("!SetThreadContext()\n");
		ResumeThread(hThread);
		return false;
	}
	ResumeThread(hThread);

	// Сохраняем глобально
	VEHContext* veh = GetVehContextByDr(dr_index);
	if (veh) {
		veh->user_callback = cb;
		veh->callback_param = p;
		veh->break_address = break_address;
		veh->dr_index = dr_index;
		veh->break_type = breakType;
		veh->break_size = breakSize;
		veh->bSingle = bSingle;
		veh->active = true;
		veh->bMultiThread = false;
	}

	return true;
}

// Очистка брейкпоинта для одного потока
bool UninstallForSingleThread(HANDLE hThread, int drIndex) {
	if (!IsValidDrIndex(drIndex))
		return false;

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		return false;
	}

	// Очищаем DR регистр
	switch (drIndex) {
	case 0: ctx.Dr0 = 0; break;
	case 1: ctx.Dr1 = 0; break;
	case 2: ctx.Dr2 = 0; break;
	case 3: ctx.Dr3 = 0; break;
	}

	// Отключаем биты в Dr7
	int bit_pos = drIndex * 2;
	ctx.Dr7 &= ~(1 << bit_pos);
	ctx.Dr7 &= ~(1 << (bit_pos + 1));

	bool res = SetThreadContext(hThread, &ctx) != FALSE;
	return res;
}


// Получить все потоки процесса
std::vector<DWORD> GetAllThreadIds() {
	std::vector<DWORD> threadIds;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return threadIds;
	}

	THREADENTRY32 te = {};
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {
				threadIds.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);
	return threadIds;
}

// Открыть HANDLE потока с нужными правами
HANDLE OpenThreadWithDebugRights(DWORD threadId) {
	return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
		FALSE, threadId);
}

// Установка брейкпоинта на все потоки
bool InstallForAllThreads(void* p, VEH_CALLBACK cb, int drIndex, bool bSingle, eVEH breakType, eBREAK_SIZE breakSize)
{
	if (!p) return false;

	// Инициализация (один раз)
	if (!g_initialized) {
		InitializeCriticalSection(&g_cs);
		AddVectoredExceptionHandler(1, MyVEH);
		g_initialized = true;
	}

	EnterCriticalSection(&g_cs);

	uintptr_t break_address = reinterpret_cast<uintptr_t>(p);

	// Получаем все потоки
	std::vector<DWORD> threads = GetAllThreadIds();
	if (threads.empty()) {
		LeaveCriticalSection(&g_cs);
		return false;
	}

	int selected_dr = drIndex;
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки (кроме текущего)
	DWORD currentThreadId = GetCurrentThreadId();

	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	bool success = true;

	// Находим свободный DR (из текущего потока)
	if (selected_dr == -1) {
		HANDLE hTempThread = OpenThreadWithDebugRights(currentThreadId);
		if (hTempThread) {
			selected_dr = FindFreeDrForThread(hTempThread);
			CloseHandle(hTempThread);
		}
		if (selected_dr == -1) {
			success = false;
		}
	}

	if (success && IsValidDrIndex(selected_dr)) {
		// Сохраняем контекст глобально
		VEHContext* veh = GetVehContextByDr(selected_dr);
		if (veh) {
			veh->user_callback = cb;
			veh->callback_param = p;
			veh->break_address = break_address;
			veh->dr_index = selected_dr;
			veh->break_type = breakType;
			veh->break_size = breakSize;
			veh->bSingle = bSingle;
			veh->bMultiThread = true;
			veh->active = true;
		}

		// Устанавливаем брейкпоинт на все потоки
		for (DWORD tid : threads) {
			HANDLE hThread = OpenThreadWithDebugRights(tid);
			if (hThread) {
				if (!InstallForSingleThread(hThread, p, cb, selected_dr, bSingle, breakType, breakSize)) {
					success = false;
				}
				CloseHandle(hThread);
			}
		}
	}
	else {
		success = false;
	}

	// Возобновляем все потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	LeaveCriticalSection(&g_cs);
	return success;
}

// Очистка брейкпоинта со всех потоков
void UninstallForAllThreads() {
	EnterCriticalSection(&g_cs);

	std::vector<DWORD> threads = GetAllThreadIds();
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки
	DWORD currentThreadId = GetCurrentThreadId();
	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	// Очищаем на всех потоках
	for (int dr = 0; dr < 4; dr++) {
		if (!g_veh_ctx[dr].active)
			continue;

		for (DWORD tid : threads) {
			HANDLE hThread = OpenThreadWithDebugRights(tid);
			if (hThread) {
				UninstallForSingleThread(hThread, dr);
				CloseHandle(hThread);
			}
		}

		ClearVehContext(dr);
	}

	// Возобновляем потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	LeaveCriticalSection(&g_cs);
}

// VEH обработчик
LONG WINAPI MyVEH(PEXCEPTION_POINTERS ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CONTEXT* ctx = ExceptionInfo->ContextRecord;

	// Проверяем DR6
	int triggered_dr = -1;
	if (ctx->Dr6 & 0x01) triggered_dr = 0;
	else if (ctx->Dr6 & 0x02) triggered_dr = 1;
	else if (ctx->Dr6 & 0x04) triggered_dr = 2;
	else if (ctx->Dr6 & 0x08) triggered_dr = 3;

	if (IsValidDrIndex(triggered_dr) && g_veh_ctx[triggered_dr].active) {
		VEHContext& veh = g_veh_ctx[triggered_dr];

		// Проверка адреса для EXECUTE
		if (veh.break_type == eVEH::BREAK_ON_EXECUTE) {
			if (ExceptionInfo->ExceptionRecord->ExceptionAddress != (PVOID)veh.break_address) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
		}

		ctx->Dr6 = 0;

		// Вызываем обработчик
		if (veh.user_callback) {
			veh.user_callback(veh.callback_param, ctx, &g_veh_ctx[triggered_dr]);
		}

		// TODO: без этого OnVeh циклится??
		// Для одноразового брейкпоинта
		if (veh.bSingle) {
			ctx->Dr7 &= ~(1 << (veh.dr_index * 2));
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void UpdateVeh(void) {
	EnterCriticalSection(&g_cs);

	std::vector<VEHContext> activeCtx;
	for (int dr = 0; dr < 4; dr++) {
		if (g_veh_ctx[dr].active) {
			activeCtx.push_back(g_veh_ctx[dr]);
		}
	}

	LeaveCriticalSection(&g_cs);

	if (activeCtx.empty()) {
		return;
	}

	std::vector<DWORD> threads = GetAllThreadIds();
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки (кроме текущего)
	DWORD currentThreadId = GetCurrentThreadId();
	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	// Переустанавливаем брейкпоинты на все потоки
	for (DWORD tid : threads) {
		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			for (const auto& veh : activeCtx) {
				// Сначала очищаем старый брейкпоинт
				UninstallForSingleThread(hThread, veh.dr_index);
				// Затем устанавливаем заново
				InstallForSingleThread(hThread,
					(void*)veh.break_address,
					veh.user_callback,
					veh.dr_index,
					veh.bSingle,
					veh.break_type,
					veh.break_size);
			}
			CloseHandle(hThread);
		}
	}

	// Возобновляем все потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}
}

void DumpThreadDebugRegisters(HANDLE hThread)
{
	if (!hThread) {
		printf("[ERROR] Invalid thread handle\n");
		return;
	}

	// Приостанавливаем поток
	DWORD suspendCount = SuspendThread(hThread);
	if (suspendCount == (DWORD)-1) {
		printf("[ERROR] Failed to suspend thread: %d\n", GetLastError());
		return;
	}

	printf("Thread handle: 0x%p, Suspend count: %d\n", hThread, suspendCount);

	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		printf("[ERROR] Failed to get thread context: %d\n", GetLastError());
		ResumeThread(hThread);
		return;
	}

	// Дамп DR0-DR3
	printf("DR0: 0x%016llX (0x%p)\n", ctx.Dr0, (void*)ctx.Dr0);
	printf("DR1: 0x%016llX (0x%p)\n", ctx.Dr1, (void*)ctx.Dr1);
	printf("DR2: 0x%016llX (0x%p)\n", ctx.Dr2, (void*)ctx.Dr2);
	printf("DR3: 0x%016llX (0x%p)\n", ctx.Dr3, (void*)ctx.Dr3);

	// Дамп DR6 (статус)
	printf("DR6: 0x%08X\n", ctx.Dr6);

	// Дамп DR7 с расшифровкой
	printf("DR7: 0x%08X\n", ctx.Dr7);

	// Расшифровка DR7
	for (int i = 0; i < 4; i++) {
		int bit_pos = i * 2;
		bool local_enabled = (ctx.Dr7 >> bit_pos) & 1;
		bool global_enabled = (ctx.Dr7 >> (bit_pos + 1)) & 1;

		if (local_enabled || global_enabled) {
			int type_shift = 16 + (i * 4);
			int len_shift = 18 + (i * 4);

			uint8_t type = (ctx.Dr7 >> type_shift) & 0b11;
			uint8_t len = (ctx.Dr7 >> len_shift) & 0b11;

			const char* type_str = "";
			switch (type) {
			case 0: type_str = "EXECUTE"; break;
			case 1: type_str = "WRITE"; break;
			case 2: type_str = "IO"; break;
			case 3: type_str = "READ/WRITE"; break;
			}

			const char* len_str = "";
			int size = 0;
			switch (len) {
			case 0: len_str = "1 byte"; size = 1; break;
			case 1: len_str = "2 bytes"; size = 2; break;
			case 2: len_str = "8 bytes"; size = 8; break;
			case 3: len_str = "4 bytes"; size = 4; break;
			}

			printf("  DR%d: %s %s, %s (L=%d, G=%d)\n",
				i,
				local_enabled ? "ENABLED" : "DISABLED",
				type_str,
				len_str,
				local_enabled,
				global_enabled);
		}
	}

	printf("=================================\n\n");

	// Возобновляем поток
	ResumeThread(hThread);
}*/
#else
VEHContext g_veh_ctx;

// Глобальная синхронизация
CRITICAL_SECTION g_cs;
bool g_initialized = false;

LONG WINAPI MyVEH(PEXCEPTION_POINTERS ExceptionInfo);

// Настройка DR7 для конкретного контекста
void SetupDr7(CONTEXT& ctx, int dr_index, eVEH type, eBREAK_SIZE size) {
	int bit_pos = dr_index * 2;
	int type_shift = 16 + (dr_index * 4);
	int len_shift = 18 + (dr_index * 4);

	ctx.Dr7 &= ~(0b11 << type_shift);
	ctx.Dr7 |= (static_cast<uint8_t>(type) << type_shift);

	ctx.Dr7 &= ~(0b11 << len_shift);
	ctx.Dr7 |= (static_cast<uint8_t>(size) << len_shift);

	ctx.Dr7 |= (1 << bit_pos);
}

// Установка брейкпоинта для одного потока
bool InstallForSingleThread(HANDLE hThread, uintptr_t break_address, int dr_index, eVEH breakType, eBREAK_SIZE breakSize) {
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		return false;
	}

	// Устанавливаем адрес
	switch (dr_index) {
	case 0: ctx.Dr0 = break_address; break;
	case 1: ctx.Dr1 = break_address; break;
	case 2: ctx.Dr2 = break_address; break;
	case 3: ctx.Dr3 = break_address; break;
	}

	SetupDr7(ctx, dr_index, breakType, breakSize);

	return SetThreadContext(hThread, &ctx) != FALSE;
}

// Поиск свободного DR регистра для конкретного потока
int FindFreeDrForThread(HANDLE hThread) {
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		return -1;
	}

	for (int i = 0; i < 4; i++) {
		uintptr_t value = 0;
		switch (i) {
		case 0: value = ctx.Dr0; break;
		case 1: value = ctx.Dr1; break;
		case 2: value = ctx.Dr2; break;
		case 3: value = ctx.Dr3; break;
		}
		if (value == 0) return i;
	}

	return -1;
}

// Получить все потоки процесса
std::vector<DWORD> GetAllThreadIds() {
	std::vector<DWORD> threadIds;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return threadIds;
	}

	THREADENTRY32 te = {};
	te.dwSize = sizeof(THREADENTRY32);

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID == GetCurrentProcessId()) {
				threadIds.push_back(te.th32ThreadID);
			}
		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);
	return threadIds;
}

// Открыть HANDLE потока с нужными правами
HANDLE OpenThreadWithDebugRights(DWORD threadId) {
	return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
		FALSE, threadId);
}

// Установка брейкпоинта на все потоки
#define FUNC_PROLOGUE_EBP_OFFSET(p) (((char*)p) + 1 + 2) // push ebp, mov ebp, esp // for bp when ebp is ready for new frame
//#define FUNC_PROLOGUE_ESP_OFFSET(p) (((char*)p) + 6) // sub esp, 2A8h // recheck allways 6 b? // если нет локальных переменных инструкции вообще нет
#define FUNC_PROLOGUE_OFFSET(p) FUNC_PROLOGUE_EBP_OFFSET(p) // FUNC_PROLOGUE_ESP_OFFSET(FUNC_PROLOGUE_EBP_OFFSET(p))
bool InstallVehOnAllThreads(void* p, int drIndex, eVEH breakType, eBREAK_SIZE breakSize)
{
	if (!p) return false;

	// Инициализация (один раз)
	if (!g_initialized) {
		InitializeCriticalSection(&g_cs);
		AddVectoredExceptionHandler(1, MyVEH);
		g_initialized = true;
	}

	EnterCriticalSection(&g_cs);

	uintptr_t break_address = reinterpret_cast<uintptr_t>(p);

	// Получаем все потоки
	std::vector<DWORD> threads = GetAllThreadIds();
	if (threads.empty()) {
		LeaveCriticalSection(&g_cs);
		return false;
	}

	int selected_dr = drIndex;
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки (кроме текущего)
	HANDLE hCurrentThread = GetCurrentThread();
	DWORD currentThreadId = GetCurrentThreadId();

	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	bool success = true;

	// Находим свободный DR (из текущего потока)
	if (selected_dr == -1) {
		HANDLE hTempThread = OpenThreadWithDebugRights(currentThreadId);
		if (hTempThread) {
			selected_dr = FindFreeDrForThread(hTempThread);
			CloseHandle(hTempThread);
		}
		if (selected_dr == -1) {
			success = false;
		}
	}

	if (success && (selected_dr >= 0 && selected_dr <= 3)) {
		// Сохраняем контекст глобально
		g_veh_ctx.callback_param = p;
		g_veh_ctx.break_address = break_address;
		g_veh_ctx.dr_index = selected_dr;
		g_veh_ctx.break_type = breakType;
		g_veh_ctx.break_size = breakSize;

		// Устанавливаем брейкпоинт на все потоки
		for (DWORD tid : threads) {
			HANDLE hThread = OpenThreadWithDebugRights(tid);
			if (hThread) {
				if (!InstallForSingleThread(hThread, break_address, selected_dr,
					breakType, breakSize)) {
					success = false;
				}
				CloseHandle(hThread);
			}
		}
	}
	else {
		success = false;
	}

	// Возобновляем все потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	LeaveCriticalSection(&g_cs);
	return success;
}

// Очистка брейкпоинта для одного потока
bool UninstallForSingleThread(HANDLE hThread, int drIndex) {
	CONTEXT ctx = {};
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	if (!GetThreadContext(hThread, &ctx)) {
		return false;
	}

	// Очищаем DR регистр
	switch (drIndex) {
	case 0: ctx.Dr0 = 0; break;
	case 1: ctx.Dr1 = 0; break;
	case 2: ctx.Dr2 = 0; break;
	case 3: ctx.Dr3 = 0; break;
	}

	// Отключаем биты в Dr7
	int bit_pos = drIndex * 2;
	ctx.Dr7 &= ~(1 << bit_pos);
	ctx.Dr7 &= ~(1 << (bit_pos + 1));

	return SetThreadContext(hThread, &ctx) != FALSE;
}

// Очистка брейкпоинта со всех потоков
void UninstallVehFromAllThreads() {
	if (g_veh_ctx.dr_index == -1) return;

	EnterCriticalSection(&g_cs);

	std::vector<DWORD> threads = GetAllThreadIds();
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки
	DWORD currentThreadId = GetCurrentThreadId();
	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	// Очищаем на всех потоках
	for (DWORD tid : threads) {
		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			UninstallForSingleThread(hThread, g_veh_ctx.dr_index);
			CloseHandle(hThread);
		}
	}

	// Возобновляем потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}

	g_veh_ctx.dr_index = -1;
	g_veh_ctx.break_address = 0;
	g_veh_ctx.callback_param = nullptr;

	LeaveCriticalSection(&g_cs);
}

// VEH обработчик
LONG WINAPI MyVEH(PEXCEPTION_POINTERS ExceptionInfo) {
	printf("MyVEH!!!!!!!!!!!!\n");
	if (ExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
		return EXCEPTION_CONTINUE_SEARCH;
	}

	CONTEXT* ctx = ExceptionInfo->ContextRecord;

	// Проверяем DR6
	int triggered_dr = -1;
	if (ctx->Dr6 & 0x01) triggered_dr = 0;
	else if (ctx->Dr6 & 0x02) triggered_dr = 1;
	else if (ctx->Dr6 & 0x04) triggered_dr = 2;
	else if (ctx->Dr6 & 0x08) triggered_dr = 3;

	if (triggered_dr == g_veh_ctx.dr_index) {
		// Проверка адреса для EXECUTE
		if (g_veh_ctx.break_type == eVEH::BREAK_ON_EXECUTE) {
			if (ExceptionInfo->ExceptionRecord->ExceptionAddress != (PVOID)g_veh_ctx.break_address) {
				return EXCEPTION_CONTINUE_SEARCH;
			}
		}

		ctx->Dr6 = 0;

		// Вызываем обработчик
		if (g_veh_ctx.user_callback) {
			g_veh_ctx.user_callback(g_veh_ctx.callback_param, ctx, &g_veh_ctx);
		}

		// TODO: без этого OnVeh циклится??
		// Для одноразового брейкпоинта
		if (true) { // Если нужно одноразовый - раскомментировать, иначе убрать
			ctx->Dr7 &= ~(1 << (g_veh_ctx.dr_index * 2));
		}

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

void UpdateVeh(void) {
	if (g_veh_ctx.dr_index == -1 /*|| !g_veh_ctx.is_active*/) {
		return;
	}

	std::vector<DWORD> threads = GetAllThreadIds();
	std::vector<HANDLE> suspendedThreads;

	// Приостанавливаем все потоки (кроме текущего)
	DWORD currentThreadId = GetCurrentThreadId();
	for (DWORD tid : threads) {
		if (tid == currentThreadId) continue;

		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			SuspendThread(hThread);
			suspendedThreads.push_back(hThread);
		}
	}

	// Переустанавливаем брейкпоинт на все потоки
	for (DWORD tid : threads) {
		HANDLE hThread = OpenThreadWithDebugRights(tid);
		if (hThread) {
			// Сначала очищаем старый брейкпоинт
			UninstallForSingleThread(hThread, g_veh_ctx.dr_index);
			// Затем устанавливаем заново
			InstallForSingleThread(hThread,
				g_veh_ctx.break_address,
				g_veh_ctx.dr_index,
				g_veh_ctx.break_type,
				g_veh_ctx.break_size);
			CloseHandle(hThread);
		}
	}

	// Возобновляем все потоки
	for (HANDLE hThread : suspendedThreads) {
		ResumeThread(hThread);
		CloseHandle(hThread);
	}
}
#endif