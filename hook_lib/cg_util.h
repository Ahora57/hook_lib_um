#ifndef CG_UTIL
#define CG_UTIL 1
#include "Struct.h"
#include "disassembly_util.h"
#include <asmjit.h>

namespace cg_util
{
	NO_INLINE auto reg_conv(ZydisRegister* reg) -> asmjit::_abi_1_10::x86::Gp //aye trick
	{
		uint32_t reg_size = NULL;
		uint32_t num_reg = NULL;

		if (*reg >= ZYDIS_REGISTER_RAX && ZYDIS_REGISTER_R15 >= *reg)
		{
			//.r64()  
			num_reg = *reg - ZYDIS_REGISTER_RAX;
			return asmjit::_abi_1_10::x86::Gpq(num_reg).r64(); //see x86::rax

		}
		else if (*reg >= ZYDIS_REGISTER_EAX && ZYDIS_REGISTER_R15D >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_EAX;
			return asmjit::_abi_1_10::x86::Gpq(num_reg).r32(); //see x86::rax
		}
		else if (*reg >= ZYDIS_REGISTER_AX && ZYDIS_REGISTER_R15W >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AX;
			return asmjit::_abi_1_10::x86::Gpq(num_reg).r16(); //see x86::rax
		}
		else if (*reg >= ZYDIS_REGISTER_AL && ZYDIS_REGISTER_R15B >= *reg)
		{
			num_reg = *reg - ZYDIS_REGISTER_AL;
			return asmjit::_abi_1_10::x86::Gpq(num_reg).r8(); //see x86::rax
		}
	}

	auto push_correct(asmjit::x86::Assembler* ass, ZydisDisassembledInstruction* dis_instr, uint32_t id_reg) -> VOID
	{
#ifndef _WIN64
		ass->push(reg_conv(&dis_instr->operands[id_reg].reg.value).r32());

#else
		ass->push(reg_conv(&dis_instr->operands[id_reg].reg.value).r64());
#endif // !_WIN64 
	}


	auto push_correct(asmjit::x86::Assembler* ass, ZydisRegister* reg) -> VOID
	{
#ifndef _WIN64
		ass->push(reg_conv(reg).r32());

#else
		ass->push(reg_conv(reg).r64());
#endif // !_WIN64 
	}


	auto push_eflag(asmjit::x86::Assembler* ass) -> VOID
	{
#ifndef _WIN64
		ass->pushfd();

#else
		ass->pushfq();
#endif // !_WIN64 
	}

	auto pop_eflag(asmjit::x86::Assembler* ass) -> VOID
	{
#ifndef _WIN64
		ass->popfd();

#else
		ass->popfq();
#endif // !_WIN64 
	}


	auto pop_correct(asmjit::x86::Assembler* ass, ZydisDisassembledInstruction* dis_instr, uint32_t id_reg) -> VOID
	{
#ifndef _WIN64
		ass->pop(reg_conv(&dis_instr->operands[id_reg].reg.value).r32());

#else
		ass->pop(reg_conv(&dis_instr->operands[id_reg].reg.value).r64());
#endif // !_WIN64 
	}

	auto pop_correct(asmjit::x86::Assembler* ass, ZydisRegister* reg) -> VOID
	{

#ifndef _WIN64
		ass->pop(reg_conv(reg).r32());

#else
		ass->pop(reg_conv(reg).r64());
#endif // !_WIN64 
	}

	NO_INLINE auto get_rand_reg(ZydisRegister* reg, ZydisRegister* reg_ignore, uint32_t size) -> BOOLEAN
	{
		BOOLEAN is_create = FALSE;
		if (size == sizeof(ULONG) * 2)
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_RAX + __rdtsc() % (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_RSP == *reg)
				{
					is_create = FALSE;
				}
				else if (reg_ignore && *reg == *reg_ignore)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(ULONG))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_EAX + __rdtsc() % (ZYDIS_REGISTER_EDI - ZYDIS_REGISTER_EAX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_ESP == *reg)
				{
					is_create = FALSE;
				}
				else if (reg_ignore && *reg == *reg_ignore)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(USHORT))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AX + __rdtsc() % (ZYDIS_REGISTER_DI - ZYDIS_REGISTER_AX));
				is_create = TRUE;
				if (ZYDIS_REGISTER_SP == *reg)
				{
					is_create = FALSE;
				}
				else if (reg_ignore && *reg == *reg_ignore)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(CHAR))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AL + __rdtsc() % (ZYDIS_REGISTER_BH - ZYDIS_REGISTER_AL));
				is_create = TRUE;
				if (ZYDIS_REGISTER_SPL == *reg)
				{
					is_create = FALSE;
				}
				else if (reg_ignore && *reg == *reg_ignore)
				{
					is_create = FALSE;
				}
			}
		}
		return is_create;

	}

 
	NO_INLINE auto get_rand_reg(ZydisRegister* reg, uint32_t size, std::vector<ZydisRegister>& ignore_reg) -> BOOLEAN
	{
		BOOLEAN is_create = FALSE;
		uint64_t rand = __rdtsc() + __rdtsc() << 32;
		INT cpuid[4];
		if (size == sizeof(ULONG) * 2)
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_RAX + (rand % (ZYDIS_REGISTER_R15 - ZYDIS_REGISTER_RAX)));
				is_create = TRUE;
				rand += GetTickCount() + __rdtsc();
				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_RSP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(ULONG))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_EAX + rand % (ZYDIS_REGISTER_EDI - ZYDIS_REGISTER_EAX));
				is_create = TRUE;
				rand += GetTickCount() + __rdtsc();
				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_ESP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(USHORT))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AX + rand % (ZYDIS_REGISTER_DI - ZYDIS_REGISTER_AX));
				is_create = TRUE;
				rand += GetTickCount() + __rdtsc();

				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_SP == *reg)
				{
					is_create = FALSE;
				}
			}
		}
		else if (size == sizeof(CHAR))
		{
			while (is_create == FALSE)
			{
				*reg = (ZydisRegister)(ZYDIS_REGISTER_AL + rand % (ZYDIS_REGISTER_BH - ZYDIS_REGISTER_AL));
				is_create = TRUE;
				rand += GetTickCount() + __rdtsc() << 32;

				for (size_t i = 0; i < ignore_reg.size(); i++)
				{
					if (ignore_reg[i] == *reg)
					{
						is_create = FALSE;
					}
				}
				if (ZYDIS_REGISTER_SPL == *reg)
				{
					is_create = FALSE;
				}
			}
		}

		if (is_create)
		{
			ignore_reg.push_back(*reg);
		}
		return is_create;

	}

	NO_INLINE auto get_instr_id(uint64_t start_address, uint64_t res_addr, std::vector<ZydisDisassembledInstruction>& dis_list) -> uint32_t
	{
		uint32_t len_fun = NULL;
		for (size_t i = NULL; i < dis_list.size(); i++)
		{
			if (start_address + len_fun == res_addr)
			{
				return i;
			}

			len_fun += dis_list[i].info.length;
		}
		return NULL;
	}

	//https://github.com/Ahora57/VMP_UTIL/blob/3a08f6249a80e6a0717f8a0657ba773d1c781697/VMP_UTIL/single_step_hook.h#L378
	auto WINAPI copy_instr(uint8_t* addr, asmjit::x86::Assembler* ass, ZydisDisassembledInstruction* dis_instr, BOOLEAN is_fix_jcc, asmjit::Label* label_fix = NULL, BOOLEAN set_exit = FALSE) -> VOID
	{
		BOOLEAN is_fix = FALSE;
		BOOLEAN is_copy = FALSE;

		uint32_t pointer_size = NULL;
		asmjit::Label label_jcc_next;
		ZydisRegister reg_ignore = { ZYDIS_REGISTER_NONE };
		ZydisRegister reg_rand[8] = { ZYDIS_REGISTER_NONE };

		UNHANDLED_JCC jcc_bad = { NULL };
		std::vector<UNHANDLED_JCC>unhandled_jcc;

		for (uint8_t i = NULL; i < dis_instr->info.operand_count_visible; i++)
		{
			if ((dis_instr->operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && dis_instr->operands[i].imm.is_relative == ZYAN_TRUE) || dis_instr->operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY)
			{
				is_fix = TRUE;
			}
		}
		if (is_fix && dis_instr->info.length >= 2)
		{
			if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CALL)
			{
#ifndef _WIN64
				//emul push stack by call and jmp 
				ass->sub(asmjit::x86::esp, sizeof(PVOID) * 2);
				ass->push(asmjit::x86::eax);
				ass->mov(asmjit::x86::eax, reinterpret_cast<CHAR*>(dis_instr->runtime_address) + dis_instr->info.length);
				ass->mov(asmjit::x86::dword_ptr(asmjit::x86::esp, sizeof(PVOID) * 2), asmjit::x86::eax);

				//set ret addr
				ass->mov(asmjit::x86::eax, dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
				ass->mov(asmjit::x86::dword_ptr(asmjit::x86::esp, sizeof(PVOID)), asmjit::x86::eax);
				ass->pop(asmjit::x86::eax);
				ass->ret();

#else
				//emul push stack by call and jmp 
				ass->sub(asmjit::x86::rsp, sizeof(PVOID) * 2);
				ass->push(asmjit::x86::rax);
				ass->mov(asmjit::x86::rax, reinterpret_cast<CHAR*>(dis_instr->runtime_address) + dis_instr->info.length);
				ass->mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, sizeof(PVOID) * 2), asmjit::x86::rax);

				//set ret addr
				ass->mov(asmjit::x86::rax, dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
				ass->mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, sizeof(PVOID)), asmjit::x86::rax);
				ass->pop(asmjit::x86::rax);
				ass->ret();
#endif // !_WIN64 
				is_copy = TRUE;
			}
			else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_JMP)
			{
#ifndef _WIN64
				ass->sub(asmjit::x86::esp, sizeof(PVOID));
				ass->push(asmjit::x86::eax);
				ass->mov(asmjit::x86::eax, dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
				ass->mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, sizeof(PVOID)), asmjit::x86::eax);
				ass->pop(asmjit::x86::eax);
				ass->ret();
#else
				ass->sub(asmjit::x86::rsp, sizeof(PVOID));
				ass->push(asmjit::x86::rax);
				ass->mov(asmjit::x86::rax, dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
				ass->mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, sizeof(PVOID)), asmjit::x86::rax);
				ass->pop(asmjit::x86::rax);
				ass->ret();
#endif // !_WIN64 				
				is_copy = TRUE;

			}
			else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_LEA && dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER && dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && dis_instr->operands[1].mem.base == ZYDIS_REGISTER_RIP)
			{
				ass->mov(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
				is_copy = TRUE;
			}
			else if (dis_instr->info.mnemonic == ZYDIS_MNEMONIC_MOV && (dis_instr->operands[NULL].mem.base == ZYDIS_REGISTER_RIP || dis_instr->operands[1].mem.base == ZYDIS_REGISTER_RIP))
			{
				if (dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER && dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && dis_instr->operands[1].mem.base == ZYDIS_REGISTER_RIP)
				{
					cg_util::get_rand_reg(&reg_rand[0], &dis_instr->operands[NULL].reg.value, sizeof(PVOID));
					cg_util::push_correct(ass, &reg_rand[0]);
					ass->mov(cg_util::reg_conv(&reg_rand[0]), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));

					pointer_size = dis::get_pointer_size(dis_instr);
					if (pointer_size == sizeof(ULONG) * 2)
					{
						ass->mov(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::qword_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(ULONG))
					{
						ass->mov(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::dword_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(USHORT))
					{
						ass->mov(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::word_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(CHAR))
					{
						ass->mov(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::byte_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					cg_util::pop_correct(ass, &reg_rand[0]);
				}
				else if (dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY && dis_instr->operands[NULL].mem.base == ZYDIS_REGISTER_RIP)
				{

					if (dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
					{
						cg_util::get_rand_reg(&reg_rand[0], &dis_instr->operands[1].reg.value, sizeof(PVOID));
						cg_util::push_correct(ass, &reg_rand[0]);
						ass->mov(cg_util::reg_conv(&reg_rand[0]), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));

						pointer_size = dis::get_pointer_size(dis_instr);
						if (pointer_size == sizeof(ULONG) * 2)
						{
							ass->mov(asmjit::x86::qword_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[NULL].reg.value));
						}
						else if (pointer_size == sizeof(ULONG))
						{
							ass->mov(asmjit::x86::dword_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[NULL].reg.value));
						}
						else if (pointer_size == sizeof(USHORT))
						{
							ass->mov(asmjit::x86::word_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[NULL].reg.value));
						}
						else if (pointer_size == sizeof(CHAR))
						{
							ass->mov(asmjit::x86::byte_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[NULL].reg.value));
						}

						cg_util::pop_correct(ass, &reg_rand[0]);
					}
					else if (dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
					{
						cg_util::get_rand_reg(&reg_rand[0], &dis_instr->operands[NULL].reg.value, sizeof(PVOID));
						cg_util::push_correct(ass, &reg_rand[0]);
						ass->mov(cg_util::reg_conv(&reg_rand[0]), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));

						pointer_size = dis::get_pointer_size(dis_instr);
						if (pointer_size == sizeof(ULONG) * 2)
						{
							ass->mov(asmjit::x86::qword_ptr(cg_util::reg_conv(&reg_rand[0])), dis_instr->operands[NULL].imm.value.u);
						}
						else if (pointer_size == sizeof(ULONG))
						{
							ass->mov(asmjit::x86::dword_ptr(cg_util::reg_conv(&reg_rand[0])), dis_instr->operands[NULL].imm.value.u);
						}
						else if (pointer_size == sizeof(USHORT))
						{
							ass->mov(asmjit::x86::word_ptr(cg_util::reg_conv(&reg_rand[0])), dis_instr->operands[NULL].imm.value.u);
						}
						else if (pointer_size == sizeof(CHAR))
						{
							ass->mov(asmjit::x86::byte_ptr(cg_util::reg_conv(&reg_rand[0])), dis_instr->operands[NULL].imm.value.u);
						}
						cg_util::pop_correct(ass, &reg_rand[0]);
					}

				}
				is_copy = TRUE;

			}
			else if (!is_fix_jcc && dis_instr->info.mnemonic == ZYDIS_MNEMONIC_CMP && (dis_instr->operands[NULL].mem.base == ZYDIS_REGISTER_RIP || dis_instr->operands[1].mem.base == ZYDIS_REGISTER_RIP))
			{
				if (dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_REGISTER && dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && dis_instr->operands[1].mem.base == ZYDIS_REGISTER_RIP)
				{
					cg_util::get_rand_reg(&reg_rand[0], &dis_instr->operands[NULL].reg.value, dis::get_reg_size(&dis_instr->operands[NULL].reg.value));
					cg_util::push_correct(ass, &reg_rand[0]);
					ass->mov(cg_util::reg_conv(&reg_rand[0]), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));

					pointer_size = dis::get_pointer_size(dis_instr);
					if (pointer_size == sizeof(ULONG) * 2)
					{
						ass->cmp(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::qword_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(ULONG))
					{
						ass->cmp(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::dword_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(USHORT))
					{
						ass->cmp(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::word_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					else if (pointer_size == sizeof(CHAR))
					{
						ass->cmp(cg_util::reg_conv(&dis_instr->operands[NULL].reg.value), asmjit::x86::byte_ptr(cg_util::reg_conv(&reg_rand[0])));
					}
					cg_util::pop_correct(ass, &reg_rand[0]);
				}
				else if (dis_instr->operands[NULL].type == ZYDIS_OPERAND_TYPE_MEMORY && dis_instr->operands[NULL].mem.base == ZYDIS_REGISTER_RIP)
				{

					if (dis_instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER)
					{
						reg_ignore = dis::reg_to_reg_sized(&dis_instr->operands[1].reg.value, sizeof(PVOID));
						cg_util::get_rand_reg(&reg_rand[0], &reg_ignore, sizeof(PVOID));

						cg_util::push_correct(ass, &reg_rand[0]);
						ass->mov(cg_util::reg_conv(&reg_rand[0]), dis::get_absolute_address(dis_instr, dis_instr->runtime_address));

						pointer_size = dis::get_pointer_size(dis_instr);
						if (pointer_size == sizeof(ULONG) * 2)
						{
							ass->cmp(asmjit::x86::qword_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[1].reg.value));
						}
						else if (pointer_size == sizeof(ULONG))
						{
							ass->cmp(asmjit::x86::dword_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[1].reg.value));
						}
						else if (pointer_size == sizeof(USHORT))
						{
							ass->cmp(asmjit::x86::word_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[1].reg.value));
						}
						else if (pointer_size == sizeof(CHAR))
						{
							ass->cmp(asmjit::x86::byte_ptr(cg_util::reg_conv(&reg_rand[0])), cg_util::reg_conv(&dis_instr->operands[1].reg.value));
						}

						cg_util::pop_correct(ass, &reg_rand[0]);
					}
				}
				is_copy = TRUE;

			}
			else if (dis::is_jmp(dis_instr))
			{
				//jcc 
				switch (dis_instr->info.mnemonic)
				{
				case ZYDIS_MNEMONIC_JB:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jb(jcc_bad.new_label);
					}
					else
					{
						ass->jb(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JBE:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						ass->jbe(jcc_bad.new_label);
						unhandled_jcc.push_back(jcc_bad);
					}
					else
					{
						ass->jbe(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JCXZ:
				{

					//jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(&dis_instr[i], reinterpret_cast<CHAR*>(addr_mod) + va_to_rva(addr_va) + len_fun));
					//jcc_bad.new_label = ass->newLabel();
					//ass.jcxz(jcc_bad.new_label);

					break;
				}
				case ZYDIS_MNEMONIC_JECXZ:
				{

					//jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(&dis_instr[i], reinterpret_cast<CHAR*>(addr_mod) + va_to_rva(addr_va) + len_fun));
					//jcc_bad.new_label = ass->newLabel();
					//ass.jecxz(jcc_bad.new_label);

					break;
				}
				case ZYDIS_MNEMONIC_JKNZD:
				{

					//jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(&dis_instr[i], reinterpret_cast<CHAR*>(addr_mod) + va_to_rva(addr_va) + len_fun));
					//jcc_bad.new_label = ass->newLabel();
					//ass.jknzd(jcc_bad.new_label);

					break;
				}
				case ZYDIS_MNEMONIC_JKZD:
				{

					//jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(&dis_instr[i], reinterpret_cast<CHAR*>(addr_mod) + va_to_rva(addr_va) + len_fun));
					//jcc_bad.new_label = ass->newLabel();
					//ass.jkdz(jcc_bad.new_label);

					break;
				}
				case ZYDIS_MNEMONIC_JL:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jl(jcc_bad.new_label);
					}
					else
					{
						ass->jl(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JLE:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jle(jcc_bad.new_label);
					}
					else
					{
						ass->jle(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNB:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jnb(jcc_bad.new_label);
					}
					else
					{
						ass->jnb(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNBE:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jnbe(jcc_bad.new_label);
					}
					else
					{
						ass->jnbe(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNL:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jnl(jcc_bad.new_label);
					}
					else
					{
						ass->jnl(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNLE:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jnle(jcc_bad.new_label);
					}
					else
					{
						ass->jnle(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNO:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jno(jcc_bad.new_label);
					}
					else
					{
						ass->jno(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNS:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jns(jcc_bad.new_label);
					}
					else
					{
						ass->jns(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JNZ:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jnz(jcc_bad.new_label);
					}
					else
					{
						ass->jnz(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JO:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jo(jcc_bad.new_label);
					}
					else
					{
						ass->jo(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JP:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jp(jcc_bad.new_label);
					}
					else
					{
						ass->jp(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JRCXZ:
				{

					//jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(&dis_instr[i], reinterpret_cast<CHAR*>(addr_mod) + va_to_rva(addr_va) + len_fun));
					//jcc_bad.new_label = ass->newLabel();
					//ass.jrcxz(jcc_bad.new_label);

					break;

				}
				case ZYDIS_MNEMONIC_JS:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->js(jcc_bad.new_label);
					}
					else
					{
						ass->js(*label_fix);
					}
					break;
				}
				case ZYDIS_MNEMONIC_JZ:
				{
					if (!is_fix_jcc)
					{
						jcc_bad.addr_call = reinterpret_cast<PVOID>(dis::get_absolute_address(dis_instr, dis_instr->runtime_address));
						jcc_bad.new_label = ass->newLabel();
						unhandled_jcc.push_back(jcc_bad);
						ass->jz(jcc_bad.new_label);
					}
					else
					{
						ass->jz(*label_fix);
					}
					break;
				}
				default:
					break;
				}


			}

		}
		else
		{
			for (size_t i = NULL; i < dis_instr->info.length; i++)
			{
				ass->db(*(addr + i));
			}
		}

		if (!is_copy)
		{
			for (size_t i = NULL; i < dis_instr->info.length; i++)
			{
				ass->db(*(addr + i));
			}
		}


		if (is_fix_jcc && !set_exit)
		{
			label_jcc_next = ass->newLabel();
			ass->jmp(label_jcc_next);
		}
		if (set_exit)
		{
#ifndef _WIN64
			ass->push(asmjit::x86::eax);
			ass->push(asmjit::x86::eax);
			ass->mov(asmjit::x86::eax, dis_instr->runtime_address + dis_instr->info.length);
			ass->mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, sizeof(PVOID)), asmjit::x86::eax);
			ass->pop(asmjit::x86::eax);
			ass->ret();
#else
			ass->push(asmjit::x86::rax);
			ass->push(asmjit::x86::rax);
			ass->mov(asmjit::x86::rax, dis_instr->runtime_address + dis_instr->info.length);
			ass->mov(asmjit::x86::dword_ptr(asmjit::x86::rsp, sizeof(PVOID)), asmjit::x86::rax);
			ass->pop(asmjit::x86::rax);
			ass->ret();
#endif // !_WIN64 
		}

		for (size_t i = NULL; i < unhandled_jcc.size(); i++)
		{

			ass->bind(unhandled_jcc[i].new_label);
			cg_util::get_rand_reg(&reg_rand[0], NULL, sizeof(PVOID));
			cg_util::push_correct(ass, &reg_rand[0]);
			cg_util::push_correct(ass, &reg_rand[0]);
			ass->mov(cg_util::reg_conv(&reg_rand[0]), unhandled_jcc[i].addr_call);
#ifndef _WIN64
			ass->mov(asmjit::x86::qword_ptr(asmjit::x86::esp, sizeof(PVOID)), cg_util::reg_conv(&reg_rand[0]));

#else
			ass->mov(asmjit::x86::qword_ptr(asmjit::x86::rsp, sizeof(PVOID)), cg_util::reg_conv(&reg_rand[0]));
#endif // !_WIN64

			cg_util::pop_correct(ass, &reg_rand[0]);
			ass->ret();
		}

		if (is_fix_jcc && !set_exit)
		{
			ass->bind(label_jcc_next);
		}
		unhandled_jcc.clear();

	}

	NO_INLINE auto get_rip_fixer(PVOID addr, uint32_t copy_size) -> PVOID
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
					cur_lable.id_instr_addr_lable = get_instr_id(reinterpret_cast<uint64_t>(addr), jcc_address, dis_list);
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

			copy_instr(reinterpret_cast<uint8_t*>(addr) + cur_size, &ass, &dis_list[i], is_fix_jcc, jcc_label, cur_size + dis_list[i].info.length >= copy_size);
			cur_size += dis_list[i].info.length;
			jcc_label = NULL;
			is_fix_jcc = FALSE;
		}

		if (rt.add(&cg_intstr_address, &code))//cg_intstr_address - alloceted code
		{
			if (alloce_mem)
				VirtualFree(alloce_mem, NULL, MEM_RELEASE);

			label_inf.clear();
			dis_list.clear();			return NULL;
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

}
#endif // !CG_UTIL
