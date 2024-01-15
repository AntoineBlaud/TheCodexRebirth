// dllmain.cpp : D�finit le point d'entr�e de l'application DLL.
#include "pch.h"
#include <windows.h>
#include <imagehlp.h>
#include <wdbgexts.h>
#include <DbgEng.h>
#include <stdio.h>
#include <stdlib.h>
#include <capstone.h>
#include <iostream>
#include <iostream>
#include <string>
#include <codecvt>
#include <filesystem>
# include <vector>


struct GString {
	char* str;
	int len;
	int allocated_len;
};


struct GString* g_string_new(void)
{
	GString* string = (GString*)malloc(sizeof(GString));
	string->str = (char*)malloc(100);
	string->len = 0;
	string->allocated_len = 100;
	return string;
}

void g_string_append_printf(GString* string, const char* format, ...)
{
	va_list args;
	va_start(args, format);
	int len = vsnprintf(NULL, 0, format, args);
	va_end(args);
	if (string->len + len > string->allocated_len)
	{
		string->allocated_len = 2*string->len + len;
		string->str = (char*)realloc(string->str, string->allocated_len);
	}
	va_start(args, format);
	vsnprintf(string->str + string->len, len + 1, format, args);
	va_end(args);
	string->len += len;
}

void g_string_free(GString* string, bool free_segment)
{
	if (free_segment)
	{
		free(string->str);
	}
	free(string);
}

struct bp {
	ULONG64 address;
	WCHAR* function_name;
	ULONG64 hit_count;
	IDebugBreakpoint* breakpoint;
};

extern "C" {
	_declspec(dllexport) LPEXT_API_VERSION ExtensionApiVersion();
	_declspec(dllexport) VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion);
	_declspec(dllexport) VOID Help(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args);
	_declspec(dllexport) VOID QueryTracerPerformances(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args);
	_declspec(dllexport) VOID AttachModule(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args);
	_declspec(dllexport) VOID Flush(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args);
	_declspec(dllexport) VOID Run(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args);
}

EXT_API_VERSION ApiVersion = { 1, 0, 0, 0 };
WINDBG_EXTENSION_APIS ExtensionApis;
IDebugClient* m_debugClient = nullptr;
IDebugAdvanced* m_ExtAdvanced = nullptr;
IDebugAdvanced2* m_ExtAdvanced2 = nullptr;
IDebugControl* m_ExtControl = nullptr;
IDebugControl4* m_ExtControl4 = nullptr;
IDebugDataSpaces* m_ExtData = nullptr;
IDebugDataSpaces2* m_ExtData2 = nullptr;
IDebugDataSpaces4 * m_ExtData4 = nullptr;
IDebugRegisters* m_ExtRegisters = nullptr;
IDebugRegisters2* m_ExtRegisters2 = nullptr;
IDebugSymbols* m_ExtSymbols = nullptr;
IDebugSymbols2* m_ExtSymbols2 = nullptr;
IDebugSymbols3* m_ExtSymbols3 = nullptr;
IDebugSystemObjects* m_ExtSystem = nullptr;

csh handle;
ULONG64 moduleBase = 0;
ULONG64 moduleEnd = 0;
DEBUG_MODULE_PARAMETERS moduleParameters = { 0 };
struct bp breakpoints[32] = { 0 };


VOID CheckVersion() {
	return;
}

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwReason, PVOID pReserved)
{
	return TRUE;
}


LPEXT_API_VERSION ExtensionApiVersion() {
	return &ApiVersion;
}


VOID Help(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	dprintf("Extension for windbg trace\n");
	dprintf("Important: \n");
	dprintf("	.reload before loading the extension\n");
	dprintf("	keep only **one space** between arguments\n");
	dprintf("	remove all breakpoints before running the extension\n");
	dprintf("Commands:\n");
	dprintf("  !WinDbgStalker.Help\n");
	dprintf("  !WinDbgStalker.QueryTracerPerformances\n");
	dprintf("  !WinDbgStalker.Hook module_name function_def_file_path\n");
	dprintf("  !WinDbgStalker.Run max_running_time max_bp_hit_count\n");
	dprintf("  !WinDbgStalker.Flush\n");
}

HRESULT CreateHelperInterfaces()
{
	HRESULT hr = S_OK;

	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugAdvanced), (void**)&m_ExtAdvanced)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugAdvanced2), (void**)&m_ExtAdvanced2)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugControl2), (void**)&m_ExtControl)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugControl4), (void**)&m_ExtControl4)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugDataSpaces), (void**)&m_ExtData)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugDataSpaces2), (void**)&m_ExtData2)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugRegisters), (void**)&m_ExtRegisters)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugSymbols), (void**)&m_ExtSymbols)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugSymbols2), (void**)&m_ExtSymbols2)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugSymbols3), (void**)&m_ExtSymbols3)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugSystemObjects), (void**)&m_ExtSystem)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugRegisters2), (void**)&m_ExtRegisters2)) != S_OK)
	{
		throw hr;
	}
	if ((hr = m_debugClient->QueryInterface(__uuidof(IDebugDataSpaces4), (void**)&m_ExtData4)) != S_OK)
	{
		throw hr;
	}

	return hr;
}

VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT usMajorVersion, USHORT usMinorVersion)
{
	ExtensionApis = *lpExtensionApis;
	IDebugClient* debugClient = nullptr;
	PDEBUG_CONTROL debugControl = nullptr;
	DebugCreate(__uuidof(IDebugClient), (void**)&debugClient);
	m_debugClient = debugClient;
	CreateHelperInterfaces();
	dprintf("WinDbgStalker loaded\n");
	// Initialize Capstone
	cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // turn ON detail feature with CS_OPT_ON
}


VOID QueryTracerPerformances(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	LARGE_INTEGER frequency;        // ticks per second
	LARGE_INTEGER t1, t2;           // ticks
	double elapsed_time;

	// get ticks per second
	QueryPerformanceFrequency(&frequency);
	// start timer
	QueryPerformanceCounter(&t1);

	int instructionToExecute = 2000;

	for (int i = 0; i < instructionToExecute; i++)
	{
		m_ExtControl4->SetExecutionStatus(DEBUG_STATUS_STEP_INTO);
		m_ExtControl4->WaitForEvent(0, INFINITE);
	}
	QueryPerformanceCounter(&t2);
	elapsed_time = (t2.QuadPart - t1.QuadPart) * 1000.0 / frequency.QuadPart;
	dprintf("%f ms.\n", elapsed_time);
	dprintf("Average time per instruction: %f ms.\n", elapsed_time / instructionToExecute);
}

VOID print_wchar(WCHAR* string, WCHAR endChar)
{
	int i = 0;
	while (string[i] != '\0')
	{
		dprintf("%c", string[i]);
		i++;
	}
	dprintf("%c", endChar);
}


WCHAR* GetArgument(PCSTR args, int argumentNumber)
{
	int i = 0;
	int argumentCount = 0;
	while (args[i] != '\0')
	{
		if (args[i] == ' ')
		{
			argumentCount++;
		}
		if (argumentCount == argumentNumber)
		{
			break;
		}
		i++;
	}
	if (argumentCount < argumentNumber)
	{
		return NULL;
	}
	WCHAR* argument = (WCHAR*)malloc(200);
	int j = 0;
	if (args[i] == ' ')
	{
		i++;
	}
	while (args[i] != ' ' && args[i] != '\0')
	{
		argument[j] = args[i];
		i++;
		j++;
	}
	argument[j] = '\0';
	return argument;
}


VOID add_func_bp(ULONG64 address, WCHAR* functionName)
{
	IDebugBreakpoint* breakpoint = nullptr;
	m_ExtControl4->AddBreakpoint(DEBUG_BREAKPOINT_CODE, DEBUG_ANY_ID, &breakpoint);
	breakpoint->SetOffset(address);
	breakpoint->AddFlags(DEBUG_BREAKPOINT_ENABLED);
	for (int i = 0; i < 32; i++)
	{
		if (breakpoints[i].address == 0)
		{
			breakpoints[i].address = address;
			breakpoints[i].hit_count = 0;
			breakpoints[i].breakpoint = breakpoint;
			breakpoints[i].function_name = (WCHAR *)malloc(100);
			wcscpy_s(breakpoints[i].function_name, 100, functionName);
			break;
		}
	}
}


VOID AttachModule(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	ULONG GetModuleName, GetFunctionDefFilePath, ArgsAddress;

	// Get arguments
	WCHAR* moduleName = GetArgument(args, 0);
	WCHAR* functionDefFilePath = GetArgument(args, 1);
	if (moduleName == NULL || functionDefFilePath == NULL)
	{
		dprintf("Error getting arguments\n");
		return;
	}

	m_ExtSymbols3->GetModuleByModuleNameWide(moduleName, 0, NULL, &moduleBase);

	// show info
	dprintf("Module name: ");
	print_wchar(moduleName, '\n');
	dprintf("Module base: %p\n", moduleBase);
	dprintf("Functions definitions file path: ");
	print_wchar(functionDefFilePath, '\n');
	m_ExtSymbols3->GetModuleParameters(1, NULL, 0, &moduleParameters);
	moduleEnd = moduleBase + moduleParameters.Size;

	// clear breakpoints
	m_ExtControl4->Execute(DEBUG_OUTCTL_IGNORE, "bc *", DEBUG_EXECUTE_NOT_LOGGED);

	// Read functions definitions
	HANDLE hFile = CreateFileW(functionDefFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		dprintf("Error opening file: %s\n", functionDefFilePath);
		return;
	}
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == INVALID_FILE_SIZE)
	{
		dprintf("Error getting file size\n");
		return;
	}
	LPVOID lpFileContent = malloc(dwFileSize);
	if (lpFileContent == NULL)
	{
		dprintf("Error allocating memory\n");
		return;
	}
	DWORD dwBytesRead = 0;
	if (!ReadFile(hFile, lpFileContent, dwFileSize, &dwBytesRead, NULL))
	{
		dprintf("Error reading file\n");
		return;
	}
	// Show File Size
	dprintf("File size: %d\n", dwFileSize);


	// Parse functions definitions
	CHAR* lpFileContentEnd = (CHAR*)((CHAR*)lpFileContent + dwFileSize);
	CHAR* lpCurrentChar = (CHAR*)lpFileContent;

	WCHAR functionAddresss[100];
	WCHAR functionName[100];

	int offset = 0;
	int bp_count = 0;
	while (lpCurrentChar < lpFileContentEnd)
	{
		while (*lpCurrentChar != ' ')
		{
			functionAddresss[offset] = (WCHAR)*lpCurrentChar;
			lpCurrentChar++;
			offset++;
		}
		functionAddresss[offset] = '\0';
		offset = 0;
		lpCurrentChar++;
		while (*lpCurrentChar != '\n')
		{
			functionName[offset] = (WCHAR)*lpCurrentChar;
			lpCurrentChar++;
			offset++;
		}
		functionName[offset] = '\0';
		offset = 0;
		lpCurrentChar++;

		// Show function name and address
		dprintf("Breakpoint on function: ");
		print_wchar(functionName, '\n');
		// Convert function address to ULONG64
		ULONG64 functionAddress = 0;
		swscanf_s(functionAddresss, L"%llx", &functionAddress);
		// add offset to module base
		functionAddress += moduleBase;
		// Add breakpoint
		add_func_bp(functionAddress, functionName);
		bp_count++;
		if (bp_count > 31)
		{
			dprintf("Reached breakpoint limit of 32\n");
			return;
		}
	}

}


#define TRACE_FLUSH_SIZE        (1 << 20)

#define CTX_INSN_REGS_MAX       32
#define CTX_INSN_MEMS_MAX       2

struct ctx_insn_mem {
	x86_op_mem      op;             /* operand */
	cs_ac_type      ac;             /* access type */
	int           size;           /* access size */
	ULONG64 ptr;           /* resolved pointer */
	boolean         stackreg;      /* stack register for push/pop */
};

struct ctx_insn {
	x86_reg                 regs[CTX_INSN_REGS_MAX];
	cs_insn *insn;
	int                   n_regs;
	struct ctx_insn_mem     mems[CTX_INSN_MEMS_MAX];
	int                   n_mems;
	char call_instruction;
	bool enable_regs;
};

struct ctx_trace {
	boolean init;
	int64_t rip;
	struct ctx_insn ctx_insn;
};

struct state {
	struct ctx_insn* last_ctx_insn;
	GString* trace;
};


struct state* state;



void get_register_value(unsigned long index, void* buffer, size_t bufferSize)
{
	HRESULT  hres;
	DEBUG_VALUE  dbgvalue = {};
	hres = m_ExtRegisters->GetValue(index, &dbgvalue);
	if (FAILED(hres)){
		dprintf("Failed to get value of the register\n");
		return;
	}
		

	switch (dbgvalue.Type)
	{
	case DEBUG_VALUE_INT8:
		if (bufferSize < sizeof(unsigned char))
			dprintf("Insufficient buffer size");
		*(unsigned char*)buffer = dbgvalue.I8;
		return;

	case DEBUG_VALUE_INT16:
		if (bufferSize < sizeof(unsigned short))
			dprintf("Insufficient buffer size");
		*(unsigned short*)buffer = dbgvalue.I16;
		return;

	case DEBUG_VALUE_INT32:
		if (bufferSize < sizeof(unsigned long))
			dprintf("Insufficient buffer size");
		*(unsigned long*)buffer = dbgvalue.I32;
		return;

	case DEBUG_VALUE_INT64:
		if (bufferSize < sizeof(unsigned long long))
			dprintf("Insufficient buffer size");
		*(unsigned long long*)buffer = dbgvalue.I64;
		return;

	case DEBUG_VALUE_FLOAT32:
		if (bufferSize < sizeof(float))
			dprintf("Insufficient buffer size");
		*(float*)buffer = dbgvalue.F32;
		return;

	case DEBUG_VALUE_FLOAT64:
		if (bufferSize < sizeof(double))
			dprintf("Insufficient buffer size");
		*(double*)buffer = dbgvalue.F64;
		return;

	case DEBUG_VALUE_FLOAT80:
		if (bufferSize < sizeof(dbgvalue.F80Bytes))
			dprintf("Insufficient buffer size");
		memcpy_s(buffer, bufferSize, dbgvalue.F80Bytes, sizeof(dbgvalue.F80Bytes));
		return;

	case DEBUG_VALUE_FLOAT128:
		if (bufferSize < sizeof(dbgvalue.F128Bytes))
			dprintf("Insufficient buffer size");
		memcpy_s(buffer, bufferSize, dbgvalue.F128Bytes, sizeof(dbgvalue.F128Bytes));
		return;

	case DEBUG_VALUE_VECTOR64:
		if (bufferSize < sizeof(dbgvalue.VI64))
			dprintf("Insufficient buffer size");
		memcpy_s(buffer, bufferSize, dbgvalue.VI64, sizeof(dbgvalue.VI64));
		return;

	case DEBUG_VALUE_VECTOR128:
		if (bufferSize < 2 * sizeof(dbgvalue.VI64))
			dprintf("Insufficient buffer size");
		memcpy_s(buffer, bufferSize, dbgvalue.VI64, 2 * sizeof(dbgvalue.VI64));
		return;
	}

	dprintf("Unknown regsiter type\n");
}

static int
get_register_size(const char* name)
{
	switch (name[0]) {
	case 'r':
		return sizeof(unsigned long long);
	case 'e':
		return sizeof(unsigned long);
	case 'c':
		return sizeof(unsigned short);
	case 'd':
		return sizeof(unsigned char);
	default:
		return 0;
	}
}

static const char*
reg_name(x86_reg reg)
{
	switch (reg) {
	case X86_REG_AL:
	case X86_REG_AH:
	case X86_REG_AX:
	case X86_REG_EAX:
	case X86_REG_RAX:
		return "rax";
	case X86_REG_BL:
	case X86_REG_BH:
	case X86_REG_BX:
	case X86_REG_EBX:
	case X86_REG_RBX:
		return "rbx";
	case X86_REG_CL:
	case X86_REG_CH:
	case X86_REG_CX:
	case X86_REG_ECX:
	case X86_REG_RCX:
		return "rcx";
	case X86_REG_DL:
	case X86_REG_DH:
	case X86_REG_DX:
	case X86_REG_EDX:
	case X86_REG_RDX:
		return "rdx";
	case X86_REG_SPL:
	case X86_REG_SP:
	case X86_REG_ESP:
	case X86_REG_RSP:
		return "rsp";
	case X86_REG_BPL:
	case X86_REG_BP:
	case X86_REG_EBP:
	case X86_REG_RBP:
		return "rbp";
	case X86_REG_SIL:
	case X86_REG_SI:
	case X86_REG_ESI:
	case X86_REG_RSI:
		return "rsi";
	case X86_REG_DIL:
	case X86_REG_DI:
	case X86_REG_EDI:
	case X86_REG_RDI:
		return "rdi";
	case X86_REG_R8B:
	case X86_REG_R8W:
	case X86_REG_R8D:
	case X86_REG_R8:
		return "r8";
	case X86_REG_R9B:
	case X86_REG_R9W:
	case X86_REG_R9D:
	case X86_REG_R9:
		return "r9";
	case X86_REG_R10B:
	case X86_REG_R10W:
	case X86_REG_R10D:
	case X86_REG_R10:
		return "r10";
	case X86_REG_R11B:
	case X86_REG_R11W:
	case X86_REG_R11D:
	case X86_REG_R11:
		return "r11";
	case X86_REG_R12B:
	case X86_REG_R12W:
	case X86_REG_R12D:
	case X86_REG_R12:
		return "r12";
	case X86_REG_R13B:
	case X86_REG_R13W:
	case X86_REG_R13D:
	case X86_REG_R13:
		return "r13";
	case X86_REG_R14B:
	case X86_REG_R14W:
	case X86_REG_R14D:
	case X86_REG_R14:
		return "r14";
	case X86_REG_R15B:
	case X86_REG_R15W:
	case X86_REG_R15D:
	case X86_REG_R15:
		return "r15";
	default:
		return NULL;
	}
}

unsigned long get_register_index(const char* name)
{
	HRESULT  hres;
	ULONG  index;
	// convert to std::wstring
	std::wstring wstr_name = std::wstring_convert<std::codecvt_utf8<wchar_t>>().from_bytes(name);
	hres = m_ExtRegisters2->GetIndexByNameWide(wstr_name.c_str(), &index);
	if (FAILED(hres))
		dprintf("failed to get index of the register\n");
	return index;
}

ULONG64 get_value(const char* name, unsigned long index)
{
	int reint = get_register_size(name);
	std::vector<char> regValue(reint);
	get_register_value(index, &regValue[0], reint);
	ULONG64 value = *reinterpret_cast<ULONG64*>(&regValue[0]);
	return value;
}

ULONG64 get_value_from_reg_name(const char* name)
{
	unsigned long index = get_register_index(name);
	return get_value(name, index);
}

ULONG64 ctx_reg_read(x86_reg reg)
{
	const char* name = reg_name(reg);
	unsigned long index = get_register_index(name);
	return get_value(name, index);
}
ULONG64 ctx_reg_read_2(x86_reg reg)
{
	const char* name = cs_reg_name(handle, reg);
	unsigned long index = get_register_index(name);
	return get_value(name, index);
}

static inline void print_trace_line(x86_reg reg)
{
	const char* r_name = reg_name(reg);
	if (r_name)
	{
		ULONG64 r_val = ctx_reg_read(reg);
		g_string_append_printf(state->trace, ",%s=0x%llx", r_name, r_val);
	}
}

VOID flush()
{
	g_string_free(state->trace, TRUE);
	free(state);
	state->last_ctx_insn = NULL;
}

struct ctx_insn* parse_current_insn() {


	// get current insn str
	wchar_t     insn_str[0x100] = { 0 };
	wchar_t	 buffer[0x100] = { 0 };
	ULONG       disasmSize = 0;
	ULONG64     endOffset = 0;
	ULONG64     nextOffset = 0;


	ULONG64 offset = get_value_from_reg_name("rip");

	int hres = m_ExtControl4->DisassembleWide(
		offset,
		0, //DEBUG_DISASM_EFFECTIVE_ADDRESS,
		insn_str,
		0x100,
		&disasmSize,
		&nextOffset);
	if (FAILED(hres))
		dprintf("Failed to disass instruction\n");

	// get bytes of current insn
	hres = m_ExtData4->ReadVirtual(offset, buffer, nextOffset - offset, &disasmSize);
	if (FAILED(hres))
	  	dprintf("Failed to disass instruction\n");

	cs_insn* insn;
	size_t count = cs_disasm(handle, (const uint8_t*)buffer, disasmSize * sizeof(wchar_t), offset, 0, &insn);
	if (count == 0)
		dprintf("Failed to disass instruction\n");



	struct ctx_insn* ctx_insn = (struct ctx_insn*)malloc(sizeof(struct ctx_insn));
	ctx_insn->n_regs = 0;
	ctx_insn->n_mems = 0;
	ctx_insn->insn = insn;
	struct cs_x86 insn_x86 = (insn->detail->x86);

	if ((insn->id == X86_INS_PUSH) || (insn->id == X86_INS_POP)) {
		cs_x86_op* op = &insn_x86.operands[0];

		ctx_insn->regs[ctx_insn->n_regs++] = X86_REG_RSP;

		/* TODO: push immediate */
		if (op->type == X86_OP_REG) {
			if (op->access & CS_AC_READ)
				ctx_insn->mems[ctx_insn->n_mems].ac = CS_AC_WRITE;
			else
				ctx_insn->mems[ctx_insn->n_mems].ac = CS_AC_READ;
			ctx_insn->mems[ctx_insn->n_mems].size = op->size;
			ctx_insn->mems[ctx_insn->n_mems].stackreg = 1;
			++ctx_insn->n_mems;
		}
	}

	for (int i = 0; i < insn_x86.op_count; ++i) {
		cs_x86_op* op = &insn_x86.operands[i];
		switch (op->type) {
		case X86_OP_REG:
			if (op->access & CS_AC_WRITE)
				ctx_insn->regs[ctx_insn->n_regs++] = op->reg;
			break;
		case X86_OP_MEM:
			/* TODO: lea */
			if (insn->id == X86_INS_LEA)
				break;
			/* ignore awful n-bytes nop */
			if (insn->id == X86_INS_NOP)
				break;
			/* TODO: x86 segments */
			if (op->mem.segment != X86_REG_INVALID)
				break;
			ctx_insn->mems[ctx_insn->n_mems].op = op->mem;
			ctx_insn->mems[ctx_insn->n_mems].ac = static_cast<cs_ac_type>(op->access);
			ctx_insn->mems[ctx_insn->n_mems].size = op->size;
			ctx_insn->mems[ctx_insn->n_mems].stackreg = 0;
			++ctx_insn->n_mems;
			break;
		default:
			break;
		}
	}
	return ctx_insn;
}

VOID save_state() {

	struct ctx_insn* ctx_insn = parse_current_insn();
	struct ctx_insn* last_ctx_insn = state->last_ctx_insn;
	g_string_append_printf(state->trace, "rip=0x%zx", get_value_from_reg_name("rip"));
	print_trace_line(X86_REG_RAX);
	print_trace_line(X86_REG_RBX);
	print_trace_line(X86_REG_RCX);
	print_trace_line(X86_REG_RDX);
	print_trace_line(X86_REG_RSP);
	print_trace_line(X86_REG_RBP);
	print_trace_line(X86_REG_RSI);
	print_trace_line(X86_REG_RDI);
	print_trace_line(X86_REG_R8);
	print_trace_line(X86_REG_R9);
	print_trace_line(X86_REG_R10);
	print_trace_line(X86_REG_R11);
	print_trace_line(X86_REG_R12);
	print_trace_line(X86_REG_R13);
	print_trace_line(X86_REG_R14);
	print_trace_line(X86_REG_R15);



	if (last_ctx_insn == NULL) {
		g_string_append_printf(state->trace, "\n");	
		free(state->last_ctx_insn);
		state->last_ctx_insn = ctx_insn;
		return;
	}

	for (int i = 0; i < last_ctx_insn->n_mems; ++i) {
		const struct ctx_insn_mem* mem = &last_ctx_insn->mems[i];
		/* capstone memory operand read access is wrong */
		g_string_append_printf(state->trace, ",m%s=0x%llx:",
			(mem->ac & CS_AC_WRITE) ? "w" : "r",
			mem->ptr);
		wchar_t buffer[100];
		int hres = m_ExtData4->ReadVirtual(mem->ptr, buffer, 50, NULL); 
		if (FAILED(hres))
			dprintf("Failed to read memory\n");
		for (int j = 0; j < mem->size; ++j)
		{
			g_string_append_printf(state->trace, "%02x",
				buffer[j] & 0xff);
		}
	}
	

	for (int i = 0; i < ctx_insn->n_mems; ++i) {
		struct ctx_insn_mem* mem = &ctx_insn->mems[i];
		const x86_op_mem* mem_op = &mem->op;
		ULONG64 r_val;

		mem->ptr = 0;
		if (mem->stackreg) {
			mem->ptr += ctx_reg_read_2(X86_REG_RSP);
			if (mem->ac & CS_AC_WRITE)
				/* TODO: operand size */
				mem->ptr -= 0x8;
		}
		else {
			if (mem_op->base != X86_REG_INVALID) {
				r_val = ctx_reg_read_2(mem_op->base);
				mem->ptr += r_val;
			}
			if (mem_op->index != X86_REG_INVALID) {
				r_val = ctx_reg_read_2(mem_op->index);
				mem->ptr += mem_op->scale * r_val;

			}
			mem->ptr += mem_op->disp;
		}
	}
	g_string_append_printf(state->trace, "\n");	
	free(state->last_ctx_insn);
	state->last_ctx_insn = ctx_insn;


}

VOID Flush(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	flush();
}

VOID Run(HANDLE hCurrentProcess, HANDLE hCurrentThread, ULONG dwCurrentPc, ULONG dwProcessor, PCSTR args)
{
	if (moduleBase == 0 || moduleEnd == 0)
	{
		dprintf("Error: module not attached\n");
		return;
	}

	int max_running_time = 0;
	int max_bp_hit_count = 0;
	// Get arguments
	WCHAR* max_running_time_arg= GetArgument(args, 0);
	WCHAR *max_bp_hit_count_arg = GetArgument(args, 1);
	// Get max_running_time_arg
	if (max_running_time_arg == NULL || max_bp_hit_count_arg == NULL)
	{
		dprintf("Error getting arguments\n");
		return;
	}
	swscanf_s(max_running_time_arg, L"%d", &max_running_time);
	swscanf_s(max_bp_hit_count_arg, L"%d", &max_bp_hit_count);
	if (max_running_time == 0 || max_bp_hit_count_arg == 0)
	{
		dprintf("Error getting arguments\n");
		return;
	}
	dprintf("Running time set: %d\n", max_running_time);
	dprintf("Breakpoint hit count set: %d\n", max_bp_hit_count);
	LARGE_INTEGER frequency;        // ticks per second
	LARGE_INTEGER t1, t2;           // ticks
	double elapsed_time = 0;

	// get ticks per second
	QueryPerformanceFrequency(&frequency);
	// start timer
	QueryPerformanceCounter(&t1);

	if (state == NULL)
	{
		state = (struct state*)malloc(sizeof(*state));
		state->trace = g_string_new();
		state->last_ctx_insn = NULL;
	}
	int counter = 0;
	// run until breakpoint hit (fn start)
	m_ExtControl4->SetExecutionStatus(DEBUG_STATUS_GO);
	m_ExtControl4->WaitForEvent(0, INFINITE);
	while (elapsed_time / 1000.0 < max_running_time)
	{
		// get rip value
		ULONG64 rip = get_value_from_reg_name("rip");
		// check if rip is in module
		if (rip < moduleBase || rip > moduleEnd)
		{
			m_ExtControl4->SetExecutionStatus(DEBUG_STATUS_GO);
			m_ExtControl4->WaitForEvent(0, INFINITE);
			//control if breakpoint hit count limit reached
			for (int i = 0; i < 32; i++)
			{
				if (breakpoints[i].address == get_value_from_reg_name("rip"))
				{
					breakpoints[i].hit_count++;
					if (breakpoints[i].hit_count >= max_bp_hit_count)
					{
						dprintf("Breakpoint hit count limit reached for function: ");
						print_wchar(breakpoints[i].function_name, '\n');
						m_ExtControl4->RemoveBreakpoint(breakpoints[i].breakpoint);
					}
					break;
				}
			}
			continue;
		}
		save_state();
		struct ctx_insn *ctx_insn = parse_current_insn();
		// show insn string representation
		dprintf("%s %s\n", ctx_insn->insn->mnemonic, ctx_insn->insn->op_str);
		// check if call instruction
		if (ctx_insn->insn->id == X86_INS_CALL || ctx_insn->insn->id == X86_INS_JMP)
		{
			// get function address
			ULONG64 function_address = 0;
			char *function_address_str = ctx_insn->insn->op_str;
			function_address = strtoull(function_address_str, NULL, 16);
			// check if function address is in module
			if (function_address < moduleBase || function_address > moduleEnd)
			{
				// Run command to disable all breakpoints
				m_ExtControl4->Execute(DEBUG_OUTCTL_IGNORE, "bd *", DEBUG_EXECUTE_NOT_LOGGED);
				// step over call instruction
				m_ExtControl4->SetExecutionStatus(DEBUG_STATUS_STEP_OVER);
				m_ExtControl4->WaitForEvent(0, INFINITE);
				// Run command to enable all breakpoints
				m_ExtControl4->Execute(DEBUG_OUTCTL_IGNORE, "be *", DEBUG_EXECUTE_NOT_LOGGED);
			}
		}

		//step to next instruction
		m_ExtControl4->SetExecutionStatus(DEBUG_STATUS_STEP_INTO);
		m_ExtControl4->WaitForEvent(0, INFINITE);
		counter++;
		QueryPerformanceCounter(&t2);
		elapsed_time = (t2.QuadPart - t1.QuadPart) * 1000.0 / frequency.QuadPart;
	}
	dprintf("Time limit of %d seconds reached\n", max_running_time);
	dprintf("Number of instructions executed: %d\n", counter);

	wchar_t temp_path[MAX_PATH];
	GetTempPathW(MAX_PATH, temp_path);
	wchar_t filename[MAX_PATH];
	swprintf_s(filename, L"%s\windbgtrace-%llx.txt", temp_path, t1.QuadPart);

	HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		dprintf("Error opening file: %s\n", filename);
		return;
	}
	DWORD dwBytesWritten = 0;
	if (!WriteFile(hFile, state->trace->str, state->trace->len, &dwBytesWritten, NULL))
	{
		dprintf("Error writing file\n");
		return;
	}
	CloseHandle(hFile);
	dprintf("Written %d bytes\n", dwBytesWritten);
	dprintf("Trace saved to: ");
	print_wchar(filename, '\n');
	
	
}


