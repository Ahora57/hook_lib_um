#ifndef EXCEPTHION_CALLBACK
#define EXCEPTHION_CALLBACK 1
#include "Struct.h"
#include "wow_util.h"
#include "disassembly_util.h"
#include "nt_api.h"
#include "cg_util.h"
#include <asmjit.h>

#ifndef _WIN64
#define RIP_CONTEXT(ctx) ctx->Eip
#else 
#define RIP_CONTEXT(ctx) ctx->Rip 
#endif // !_WIN64

#ifndef TRAP_FLAG
#define TRAP_FLAG 0x100
#endif // !TRAP_FLAG


 

/*

NTSTATUS
NTAPI
NtProtectVirtualMemory
(
     HANDLE ProcessHandle,
     PVOID* BaseAddress,
     PSIZE_T RegionSize,
     ULONG NewProtect,
     PULONG OldProtect
);

#pragma optimize( "", off )
NO_INLINE auto change_callback2() -> BOOLEAN
{
	uint32_t offset = NULL;
	DWORD old_prot = NULL;
	SIZE_T size_prot = NULL;

	uint64_t mod_addr = 0X111111111111111;
	uint64_t nt_protect_mem = 0X2222222222222222;
	uint64_t hook = 0X3333333333333333;
	uint64_t orig_callback = 0X4444444444444;

	uint8_t* sec_addr = NULL;
	uint8_t* targer_addr = NULL;
	PIMAGE_NT_HEADERS headers = NULL;
	PIMAGE_SECTION_HEADER sections = NULL;

	if (reinterpret_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_magic == IMAGE_DOS_SIGNATURE)
	{

		headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<CHAR*>(mod_addr) + reinterpret_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew);
		sections = IMAGE_FIRST_SECTION(headers);

		for (size_t i = 0; i < headers->FileHeader.NumberOfSections; i++)
		{
			sec_addr = reinterpret_cast<uint8_t*>(mod_addr) + sections[i].VirtualAddress;
			if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				if (sections[i].Misc.VirtualSize > 20)
				{
					for (size_t j = 0; j < sections[i].Misc.VirtualSize - 20; j++)
					{
						//Wow64pSetupExceptionDispatch 8b ?? 24 ?? e8 ?? ?? ?? ?? BA 01 00 00 00 8B win 10-11
						//Wow64SetupExceptionDispatch  C7 ?? 02 00 01 00 8B 05 ?? ?? ?? ?? 89 ?? AC 00 00 00 win7-8.1
						if
							(
								(
									*(sec_addr + j) == 0x8B &&
									*(sec_addr + j + 2) == 0x24 &&
									*(sec_addr + j + 4) == 0xE8 &&
									*(sec_addr + j + 9) == 0xBA &&
									*(sec_addr + j + 10) == 0x01 &&
									*(sec_addr + j + 11) == NULL &&
									*(sec_addr + j + 12) == NULL &&
									*(sec_addr + j + 13) == NULL &&
									*(sec_addr + j + 14) == 0x8B
								) ||
								(
									*(sec_addr + j) == 0xC7 &&
									*(sec_addr + j + 2) == 0x02 &&
									*(sec_addr + j + 3) == NULL &&									
									*(sec_addr + j + 4) == 0x01 && 
 									*(sec_addr + j + 5) == NULL && 
									*(sec_addr + j + 6) == 0x8B &&
									*(sec_addr + j + 7) == 0x05 &&
									*(sec_addr + j + 12) == 0x89 &&
									*(sec_addr + j + 14) == 0xAC &&
									*(sec_addr + j + 15) == NULL &&
									*(sec_addr + j + 16) == NULL &&
									*(sec_addr + j + 17) == NULL 

								)
							)
						{
							if(*(sec_addr + j) == 0x8B)
							{
								memcpy(&offset, sec_addr + j + 16, sizeof(uint32_t));
								targer_addr = sec_addr + j + 14 + 6 + offset;
							} 
							else if(*(sec_addr + j) == 0xC7))
							{ 
								memcpy(&offset, sec_addr + j + 8, sizeof(uint32_t));
								targer_addr = sec_addr + j + 6 + 6 + offset;
							}
							size_prot = sizeof(uint32_t);


							//hear some problem
							if (reinterpret_cast<uint64_t>(targer_addr) >= mod_addr && (reinterpret_cast<uint8_t*>(mod_addr) + headers->OptionalHeader.SizeOfImage - sizeof(PVOID)) > targer_addr)
							{
								if (NT_SUCCESS(reinterpret_cast<decltype(&NtProtectVirtualMemory)>(nt_protect_mem)(NtCurrentProcess, reinterpret_cast<PVOID*>(&targer_addr), &size_prot, PAGE_READWRITE, &old_prot)))
								{
									if(*(sec_addr + j) == 0x8B)
									{
										targer_addr = sec_addr + j + 14 + 6 + offset;
									}
									else
									{
										targer_addr = sec_addr + j + 6 + 6 + offset;
									}

									*reinterpret_cast<uint32_t*>(orig_callback) = *reinterpret_cast<uint32_t*>(targer_addr);
									*reinterpret_cast<uint32_t*>(targer_addr) = hook;

									size_prot = sizeof(uint32_t);

									if(*(sec_addr + j) == 0x8B)
									{
										targer_addr = sec_addr + j + 14 + 6 + offset;
									}
									else
									{
										targer_addr = sec_addr + j + 6 + 6 + offset;
									}

									reinterpret_cast<decltype(&NtProtectVirtualMemory)>(nt_protect_mem)(NtCurrentProcess, reinterpret_cast<PVOID*>(&targer_addr), &size_prot, old_prot, &old_prot);
									return TRUE;
								}
							}
						}
					}
				}
			}
		}

	}
	return FALSE;
}
#pragma optimize( "", on )
*/

uint8_t change_callback_wow[] =
{
	0x48, 0x81, 0xEC, 0xA8, 0x00, 0x00, 0x00, 0xC7, 0x44, 0x24, 0x40, 0x00, 0x00, 0x00, 0x00, 0xC7,
	0x44, 0x24, 0x58, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x78, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xB8, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x48, 0x89, 0x44, 0x24, 0x68, 0x48,
	0xB8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x48, 0x89, 0x84, 0x24, 0x80, 0x00, 0x00,
	0x00, 0x48, 0xB8, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x48, 0x89, 0x84, 0x24, 0x90,
	0x00, 0x00, 0x00, 0x48, 0xB8, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x04, 0x00, 0x48, 0x89, 0x84,
	0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7,
	0x44, 0x24, 0x48, 0x00, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x70, 0x00, 0x00, 0x00, 0x00,
	0x48, 0xC7, 0x44, 0x24, 0x60, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x68, 0x0F, 0xB7,
	0x00, 0x3D, 0x4D, 0x5A, 0x00, 0x00, 0x0F, 0x85, 0x3E, 0x03, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24,
	0x68, 0x48, 0x63, 0x40, 0x3C, 0x48, 0x8B, 0x4C, 0x24, 0x68, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1,
	0x48, 0x89, 0x44, 0x24, 0x70, 0x48, 0x8B, 0x44, 0x24, 0x70, 0x0F, 0xB7, 0x40, 0x14, 0x48, 0x8B,
	0x4C, 0x24, 0x70, 0x48, 0x8D, 0x44, 0x01, 0x18, 0x48, 0x89, 0x44, 0x24, 0x60, 0x48, 0xC7, 0x44,
	0x24, 0x50, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x0D, 0x48, 0x8B, 0x44, 0x24, 0x50, 0x48, 0xFF, 0xC0,
	0x48, 0x89, 0x44, 0x24, 0x50, 0x48, 0x8B, 0x44, 0x24, 0x70, 0x0F, 0xB7, 0x40, 0x06, 0x48, 0x39,
	0x44, 0x24, 0x50, 0x0F, 0x83, 0xE1, 0x02, 0x00, 0x00, 0x48, 0x6B, 0x44, 0x24, 0x50, 0x28, 0x48,
	0x8B, 0x4C, 0x24, 0x60, 0x8B, 0x44, 0x01, 0x0C, 0x48, 0x8B, 0x4C, 0x24, 0x68, 0x48, 0x03, 0xC8,
	0x48, 0x8B, 0xC1, 0x48, 0x89, 0x44, 0x24, 0x38, 0x48, 0x6B, 0x44, 0x24, 0x50, 0x28, 0x48, 0x8B,
	0x4C, 0x24, 0x60, 0x8B, 0x44, 0x01, 0x24, 0x25, 0x00, 0x00, 0x00, 0x40, 0x85, 0xC0, 0x0F, 0x84,
	0xA1, 0x02, 0x00, 0x00, 0x48, 0x6B, 0x44, 0x24, 0x50, 0x28, 0x48, 0x8B, 0x4C, 0x24, 0x60, 0x8B,
	0x44, 0x01, 0x24, 0x25, 0x00, 0x00, 0x00, 0x20, 0x85, 0xC0, 0x0F, 0x84, 0x85, 0x02, 0x00, 0x00,
	0x48, 0x6B, 0x44, 0x24, 0x50, 0x28, 0x48, 0x8B, 0x4C, 0x24, 0x60, 0x83, 0x7C, 0x01, 0x08, 0x0F,
	0x0F, 0x86, 0x6F, 0x02, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00, 0xEB,
	0x0D, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0xFF, 0xC0, 0x48, 0x89, 0x44, 0x24, 0x30, 0x48, 0x6B,
	0x44, 0x24, 0x50, 0x28, 0x48, 0x8B, 0x4C, 0x24, 0x60, 0x8B, 0x44, 0x01, 0x08, 0x83, 0xE8, 0x0F,
	0x8B, 0xC0, 0x48, 0x39, 0x44, 0x24, 0x30, 0x0F, 0x83, 0x38, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x44,
	0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x00,
	0x3D, 0x8B, 0x00, 0x00, 0x00, 0x0F, 0x85, 0x15, 0x02, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30,
	0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x02, 0x83,
	0xF8, 0x24, 0x0F, 0x85, 0xF8, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C,
	0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x04, 0x3D, 0xE8, 0x00, 0x00,
	0x00, 0x0F, 0x85, 0xD9, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24,
	0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x09, 0x3D, 0xBA, 0x00, 0x00, 0x00,
	0x0F, 0x85, 0xBA, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38,
	0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x0A, 0x83, 0xF8, 0x01, 0x0F, 0x85, 0x9D,
	0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8,
	0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x0B, 0x85, 0xC0, 0x0F, 0x85, 0x81, 0x01, 0x00, 0x00, 0x48,
	0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F,
	0xB6, 0x40, 0x0C, 0x85, 0xC0, 0x0F, 0x85, 0x65, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30,
	0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x0D, 0x85,
	0xC0, 0x0F, 0x85, 0x49, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24,
	0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x0F, 0xB6, 0x40, 0x0E, 0x3D, 0x8B, 0x00, 0x00, 0x00,
	0x0F, 0x85, 0x2A, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38,
	0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x8B, 0x40, 0x10, 0x89, 0x44, 0x24, 0x40, 0x48, 0x8B, 0x44,
	0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x8B, 0x4C, 0x24,
	0x40, 0x48, 0x8D, 0x44, 0x08, 0x14, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0xC7, 0x44, 0x24, 0x78,
	0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x68, 0x48, 0x39, 0x44, 0x24, 0x48, 0x0F, 0x82,
	0xDC, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x70, 0x8B, 0x40, 0x50, 0x48, 0x8B, 0x4C, 0x24,
	0x68, 0x48, 0x8D, 0x44, 0x01, 0xF8, 0x48, 0x3B, 0x44, 0x24, 0x48, 0x0F, 0x86, 0xBF, 0x00, 0x00,
	0x00, 0x48, 0x8D, 0x44, 0x24, 0x58, 0x48, 0x89, 0x44, 0x24, 0x20, 0x41, 0xB9, 0x04, 0x00, 0x00,
	0x00, 0x4C, 0x8D, 0x44, 0x24, 0x78, 0x48, 0x8D, 0x54, 0x24, 0x48, 0x48, 0xC7, 0xC1, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x0F, 0x8C, 0x8F, 0x00, 0x00,
	0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24, 0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B,
	0xC1, 0x8B, 0x4C, 0x24, 0x40, 0x48, 0x8D, 0x44, 0x08, 0x14, 0x48, 0x89, 0x44, 0x24, 0x48, 0x48,
	0x8B, 0x84, 0x24, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x4C, 0x24, 0x48, 0x8B, 0x09, 0x89, 0x08,
	0x48, 0x8B, 0x44, 0x24, 0x48, 0x8B, 0x8C, 0x24, 0x90, 0x00, 0x00, 0x00, 0x89, 0x08, 0x48, 0xC7,
	0x44, 0x24, 0x78, 0x04, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x30, 0x48, 0x8B, 0x4C, 0x24,
	0x38, 0x48, 0x03, 0xC8, 0x48, 0x8B, 0xC1, 0x8B, 0x4C, 0x24, 0x40, 0x48, 0x8D, 0x44, 0x08, 0x14,
	0x48, 0x89, 0x44, 0x24, 0x48, 0x48, 0x8D, 0x44, 0x24, 0x58, 0x48, 0x89, 0x44, 0x24, 0x20, 0x44,
	0x8B, 0x4C, 0x24, 0x58, 0x4C, 0x8D, 0x44, 0x24, 0x78, 0x48, 0x8D, 0x54, 0x24, 0x48, 0x48, 0xC7,
	0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x94, 0x24, 0x80, 0x00, 0x00, 0x00, 0xB0, 0x01, 0xEB, 0x0C,
	0xE9, 0x9C, 0xFD, 0xFF, 0xFF, 0xE9, 0xFE, 0xFC, 0xFF, 0xFF, 0x32, 0xC0, 0x48, 0x81, 0xC4, 0xA8,
	0x00, 0x00, 0x00, 0xC3
};

namespace excep_callback
{
	PVOID nt_continue = NULL;  


	auto  callback_proto(EXCEPTION_POINTERS* excep_pointer) -> ULONG
	{
		return NULL;
	}

	auto _stdcall callback_ki_excep_proto(PEXCEPTION_RECORD excep_record, PCONTEXT ctx) -> VOID
	{

	}

	auto _stdcall dispatcher_excepthion_proto(PVOID excep_record, PCONTEXT ctx) -> BOOLEAN
	{
		return FALSE;
	}
	  
	auto _stdcall guard_context_proto(PVOID excep_record, PCONTEXT ctx) -> ULONG
	{
		return NULL;
	}

	auto nt_raise_excepthion_proto(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context,BOOLEAN FirstChance) -> NTSTATUS
	{
		return STATUS_SUCCESS;
	}

	auto rtl_raise_excepthion_proto(NTSTATUS nt_status) -> VOID
	{

	}


	 

 
	NO_INLINE auto get_rip_fixer(PVOID addr,PVOID ki_callback, uint32_t copy_size) -> PVOID
	{
		BOOLEAN is_fix = FALSE;
		BOOLEAN is_fix_jcc = FALSE;

		uint64_t jcc_address = NULL;
		PVOID cg_intstr_address = NULL;
		PVOID alloce_mem = NULL;

		LABEL_INFO cur_lable;
		ZydisDisassembledInstruction dis_instr = { NULL };
		asmjit::Label* jcc_label = NULL;

		asmjit::JitRuntime rt;
		asmjit::CodeHolder code;

		std::vector<LABEL_INFO> label_inf;
		std::vector<ZydisDisassembledInstruction> dis_list;

		alloce_mem = VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!alloce_mem)
			return NULL;

		code.init(rt.environment(), rt.cpuFeatures());

		asmjit::x86::Assembler ass(&code);


#ifndef _WIN64 
		ass.push(asmjit::x86::dword_ptr(asmjit::x86::esp, sizeof(PVOID))); //<- save PCONTEXT
		ass.push(asmjit::x86::dword_ptr(asmjit::x86::esp, sizeof(PVOID))); //<- save PEXCEPTION_RECORD
		ass.mov(asmjit::x86::eax, ki_callback);
		ass.call(asmjit::x86::eax);
#else  
		//mov rcx,rsp
		//add rcx, 0x4F0
		//mov rdx, rsp
		ass.mov(asmjit::x86::rcx, asmjit::x86::rsp);
		ass.add(asmjit::x86::rcx, 0x4F0); 
		ass.mov(asmjit::x86::rdx, asmjit::x86::rsp);
		ass.mov(asmjit::x86::rax, ki_callback);
		ass.call(asmjit::x86::rax);
#endif // !_WIN64 


		for (size_t cur_size = NULL, dis_count = NULL; cur_size < copy_size; cur_size += dis_instr.info.length, dis_count++)
		{
			if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, reinterpret_cast<CHAR*>(addr) + cur_size)))
			{
				dis_list.push_back(dis_instr);

			}
			else
			{
 
				if (alloce_mem)
					VirtualFree(alloce_mem, NULL, MEM_RELEASE);
				label_inf.clear();
				dis_list.clear();
				return NULL;
			}
		}

		for (size_t i = NULL; i < dis_list.size(); i++)
		{
			if (dis::is_jmp(&dis_list[i]))
			{
				jcc_address = dis::get_absolute_address(&dis_list[i], dis_list[i].runtime_address);
 				if (jcc_address >= reinterpret_cast<uint64_t>(addr) && reinterpret_cast<uint64_t>(addr) + copy_size > jcc_address)
				{
					cur_lable.id_instr_addr_lable = cg_util::get_instr_id(reinterpret_cast<uint64_t>(addr), jcc_address, dis_list);
					cur_lable.id_instr_rip = i;
					cur_lable.new_label = ass.newLabel();
					label_inf.push_back(cur_lable);
				}
			} 
		}

		for (size_t i = NULL, cur_size = NULL; i < dis_list.size(); i++)
		{
			for (size_t j = NULL; j < label_inf.size(); j++)
			{
				if (label_inf[j].id_instr_addr_lable == i)
				{
					ass.bind(label_inf[j].new_label);
				}
				if (label_inf[j].id_instr_rip == i)
				{
					jcc_label = &label_inf[j].new_label;
					is_fix_jcc = TRUE;
 				}
			}

				cg_util::copy_instr(reinterpret_cast<uint8_t*>(addr) + cur_size, &ass, &dis_list[i], is_fix_jcc, jcc_label, cur_size + dis_list[i].info.length >= copy_size);
				cur_size += dis_list[i].info.length; 
				jcc_label = NULL;
				is_fix_jcc = FALSE;
		}

		if (rt.add(&cg_intstr_address, &code))//cg_intstr_address - alloceted code
		{ 
			if (alloce_mem)
				VirtualFree(alloce_mem, NULL, MEM_RELEASE);

			label_inf.clear();
			dis_list.clear();			
			return NULL;
		}

		memcpy(alloce_mem, cg_intstr_address, code.codeSize());
		rt.release(cg_intstr_address);
		code.~CodeHolder();
		ass.~Assembler();

		label_inf.clear();
		dis_list.clear();

		if (alloce_mem)
		{
			VirtualProtect(alloce_mem, PAGE_SIZE, PAGE_EXECUTE_READ, NULL);
		}
		return alloce_mem;
	}
	NO_INLINE auto _stdcall callback_ki_excep(PEXCEPTION_RECORD excep_record, PCONTEXT ctx) -> VOID
	{
		INT exep_res = NULL;
		ULONG ret_execute = EXCEPTION_CONTINUE_SEARCH;
		uint8_t* addr_rsp = NULL;
		EXCEPTION_POINTERS excep_pointer = { NULL };

		 
 
		if (callback_info.type == excep_ki_dispatcher_callback)
		{
#ifndef _WIN64
			__asm
			{
				mov addr_rsp,ebp 
			}
			addr_rsp += (sizeof(PVOID) * 2); //call & push ebp
			addr_rsp = reinterpret_cast<uint8_t*>(&excep_record);
 
			ctx = *reinterpret_cast<PCONTEXT*>(addr_rsp + sizeof(PVOID));
			excep_record = *reinterpret_cast<PEXCEPTION_RECORD*>(addr_rsp);
#endif // _WIN64

			excep_pointer.ExceptionRecord = excep_record;
			excep_pointer.ContextRecord = ctx;
			 
			ret_execute = reinterpret_cast<decltype(&callback_proto)>(callback_info.user_callback)(&excep_pointer);
			if (ret_execute != EXCEPTION_CONTINUE_SEARCH)
			{
				//call NtContinue
				reinterpret_cast<decltype(&NtContinue)>(nt_continue)(ctx,FALSE);
				return;
			}  
		}
#ifdef _WIN64
		else if (callback_info.type == excep_wow_prepare_callback)
		{
			excep_pointer.ExceptionRecord = excep_record;
			excep_pointer.ContextRecord = ctx;

			ret_execute = reinterpret_cast<decltype(&callback_proto)>(callback_info.user_callback)(&excep_pointer);
			if (ret_execute != EXCEPTION_CONTINUE_SEARCH)
			{
				//call NtContinue
				reinterpret_cast<decltype(&NtContinue)>(nt_continue)(excep_pointer.ContextRecord, FALSE);
			}
			if (callback_info.orig_callback != NULL)
			{
				reinterpret_cast<decltype(&callback_ki_excep_proto)>(callback_info.orig_callback)(excep_record, ctx);
			}
		}
#else
		else if (callback_info.type == excep_wow_ki_dispatcher_callback)
		{
			//addr_rsp = reinterpret_cast<uint8_t*>(&excep_record);
			// 
			//ctx = *reinterpret_cast<PCONTEXT*>(addr_rsp);
			//excep_record = *reinterpret_cast<PEXCEPTION_RECORD*>(addr_rsp - sizeof(PVOID));

#ifndef _WIN64
			__asm
			{
				mov addr_rsp, ebp
			}
			addr_rsp += sizeof(PVOID); //push ebp
			addr_rsp = reinterpret_cast<uint8_t*>(&excep_record);

			ctx = *reinterpret_cast<PCONTEXT*>(addr_rsp + sizeof(PVOID));
			excep_record = *reinterpret_cast<PEXCEPTION_RECORD*>(addr_rsp);
#endif // _WIN64

			excep_pointer.ExceptionRecord = excep_record;
			excep_pointer.ContextRecord = ctx;
			 
			ret_execute = reinterpret_cast<decltype(&callback_proto)>(callback_info.user_callback)(&excep_pointer);
			if (ret_execute != EXCEPTION_CONTINUE_SEARCH)
			{				
				//call NtContinue
				reinterpret_cast<decltype(&NtContinue)>(nt_continue)(ctx, FALSE);
				 
			}
			if (callback_info.orig_callback != NULL)
			{ 
				__asm
				{
					push [ctx]
					push [excep_record]
					jmp [callback_info.orig_callback]

				}
 			}
		}
#endif // _WIN64
		//Need call NtContinue
	}
	NO_INLINE auto callback_pointer
	(
		EXCEPTION_POINTERS* excep_pointer
	) -> LONG
	{ 
		LONG ret_execute = EXCEPTION_CONTINUE_SEARCH;

		ret_execute = reinterpret_cast<decltype(&callback_proto)>(callback_info.user_callback)(excep_pointer);

		return ret_execute;
	}





	 
	NO_INLINE auto add_calback(PVOID addr_filter, TYPE_CALLBACK_EXCEPTHION type = excep_veh_callback) -> BOOLEAN
	{

		uint32_t offset = NULL; 
		uint32_t id_fun = NULL;
		DWORD old_prot = NULL;
 		DWORD64 ntdll = NULL;
		DWORD64 wow64_dll = NULL;
		DWORD64 virt_protect = NULL;

		uint8_t* shell_wow = NULL;
		uint8_t* api_addr = NULL;
		uint8_t* cur_api_addr = NULL; 
		uint8_t* addr_hook = NULL;
		PVOID rip_fixer = NULL;
		PVOID copy_pointer = NULL;
		HMODULE ntdll_base = NULL;

		ZydisDisassembledInstruction dis_instr = { NULL };

		uint8_t ki_sig_check[] = 
		{
			0xFC, //cld
			0x48, 0x8B, 0x05 // mov rax, [rip+offset]
		};
  

#ifndef _WIN64
		uint8_t shell_jmp[] =
		{
			0xB8, 0x00, 0x00, 0x00, 0x00,   // mov eax,NULL
			0xFF, 0xE0	//jmp rax
		};
#else

		uint8_t shell_jmp[] =
		{
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax,NULL
			0xFF, 0xE0	//jmp rax
		};
#endif // !_WIN64

 		SYSTEM_INFO sys_inf = { NULL };

		if (!nt_continue)
		{
			ntdll_base = GetModuleHandleW(L"ntdll.dll");
			if (ntdll_base)
			{
				nt_continue =  reinterpret_cast<PVOID>(GetProcAddress(ntdll_base, "NtContinue"));
			}
		}
		 
		if (type == excep_veh_callback)
		{
			//just call RtlAddVectoredExceptionHandler
			callback_info.user_callback = addr_filter;
			callback_info.type = excep_veh_callback;
			 
			callback_info.handle_veh = AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(callback_pointer));
 
			return callback_info.handle_veh != NULL;
		}
		else if (type == excep_ki_dispatcher_callback)
		{
			ntdll_base = GetModuleHandleW(L"ntdll.dll");
			if (ntdll_base)
			{
				//just hook KiUserExceptionDispatcher
				api_addr = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll_base, "KiUserExceptionDispatcher"));

				if (api_addr)
				{
					rip_fixer = get_rip_fixer(api_addr, callback_ki_excep, sizeof(shell_jmp));
					if (rip_fixer)
					{ 
						copy_pointer = rip_fixer;
						if (VirtualProtect(api_addr, sizeof(shell_jmp), PAGE_EXECUTE_READWRITE, &old_prot))
						{
							callback_info.type = excep_ki_dispatcher_callback;
							callback_info.user_callback = addr_filter;
							callback_info.orig_callback = NULL;
 

#ifndef _WIN64
							memcpy(reinterpret_cast<uint8_t*>(shell_jmp) + 1, &copy_pointer, sizeof(PVOID));
#else
							memcpy(reinterpret_cast<uint8_t*>(shell_jmp) + 2, &copy_pointer, sizeof(PVOID));

#endif // !_WIN64
 
							memcpy(api_addr, shell_jmp, sizeof(shell_jmp));

							VirtualProtect(api_addr, sizeof(shell_jmp), old_prot, &old_prot);

 							return TRUE;
						}
						VirtualFree(rip_fixer, NULL, MEM_RELEASE);

					}
				}
			}
			return callback_info.orig_callback != NULL; 
		} 
		else  
		{
			GetNativeSystemInfo(&sys_inf);

#ifdef _WIN64  
 			if (
					type == excep_wow_prepare_callback &&
					(
						sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
						sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
					)
				)
			{
				//We change pointer in Wow64PrepareForException
				ntdll_base = GetModuleHandleW(L"ntdll.dll");
				if (ntdll_base)
				{
					api_addr = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll_base, "KiUserExceptionDispatcher"));
					if (api_addr && !memcmp(api_addr, ki_sig_check, sizeof(ki_sig_check)))
					{
						//memcpy(&offset, api_addr + sizeof(ki_sig_check), sizeof(offset));
						//addr_hook = api_addr + sizeof(uint8_t) + 7 + offset; //7 - size instructhion, offset - the difference in values ​​between the target value, sizeof(uint8_t) - targer instr next
						if (ZYAN_SUCCESS(dis::get_dis(&dis_instr, api_addr + sizeof(uint8_t))))
						{ 
							addr_hook = dis::get_absolute_address(&dis_instr, api_addr + sizeof(uint8_t));
							/*
								mov     rcx, rsp
								add     rcx, 4F0h
								mov     rdx, rsp
								call    rax ; Wow64PrepareForException
								;Some code
								mov     rcx, rsp
								add     rcx, 4F0h
								mov     rdx, rsp
								call    RtlDispatchException
							*/
							if (addr_hook && VirtualProtect(addr_hook, sizeof(PVOID), PAGE_READWRITE, &old_prot))
							{

								callback_info.type = excep_wow_prepare_callback;
								callback_info.user_callback = addr_filter;
								callback_info.orig_callback = *reinterpret_cast<PVOID*>(addr_hook);

								*reinterpret_cast<PVOID*>(addr_hook) = callback_ki_excep;

								VirtualProtect(addr_hook, sizeof(PVOID), old_prot, &old_prot);
								return TRUE;
							}
						}
					}
				}
				//Wow64PrepareForException
 			}
#else   
			if
			(
				//Change Ntdll32KiUserExceptionDispatcher in wow64.dll
				type == excep_wow_ki_dispatcher_callback &&
				(
					sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
					sys_inf.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64
				)
			)
			{  
				ntdll_base = GetModuleHandleW(L"ntdll.dll");
				ntdll = wow_util::get_module_64(L"ntdll.dll");
				wow64_dll = wow_util::get_module_64(L"wow64.dll");

				if (ntdll_base && ntdll && wow64_dll)
				{					
					virt_protect = wow_util::get_export(ntdll, "NtProtectVirtualMemory");
					api_addr = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll_base, "KiUserExceptionDispatcher"));
  
					if (api_addr && virt_protect)
					{
						shell_wow = reinterpret_cast<uint8_t*>(VirtualAlloc(NULL, sizeof(change_callback_wow), MEM_COMMIT, PAGE_EXECUTE_READWRITE));
						if (shell_wow)
						{

							callback_info.type = excep_wow_ki_dispatcher_callback;
							callback_info.user_callback = addr_filter;

							memcpy(shell_wow, change_callback_wow, sizeof(change_callback_wow));

							memcpy(reinterpret_cast<uint8_t*>(shell_wow) + 0x20 + 0x2, &wow64_dll, sizeof(wow64_dll));
							memcpy(reinterpret_cast<uint8_t*>(shell_wow) + 0x2F + 2, &virt_protect, sizeof(wow64_dll));

							memset(reinterpret_cast<uint8_t*>(shell_wow) + 0x41 + 0x2, NULL, sizeof(DWORD64));
							memset(reinterpret_cast<uint8_t*>(shell_wow) + 0x53 + 0x2, NULL, sizeof(DWORD64));
 
							copy_pointer = (PVOID)callback_ki_excep;
							memcpy(reinterpret_cast<uint8_t*>(shell_wow) + 0x41 + 0x2, &copy_pointer, sizeof(ULONG));
							
							copy_pointer = (PVOID)&callback_info.orig_callback;
							memcpy(reinterpret_cast<uint8_t*>(shell_wow) + 0x53 + 0x2, &copy_pointer, sizeof(ULONG));

							wow_util::X64Call(reinterpret_cast<DWORD64>(shell_wow), NULL);
							 
						}
					}
				}
				
				return callback_info.orig_callback != NULL;

			}
			 
#endif // _WIN64
		}
	 
		return FALSE;
	}
}
#endif // !EXCEPTHION_CALLBACK
