#ifndef BP_HOOK
#define BP_HOOK 1
#include "Struct.h"
#include "disassembly_util.h"
#include <asmjit.h>

//https://github.com/svn2github/reactos/blob/d461c3f6a3cb7ce06d1d63a3370556f71d305b21/ntoskrnl/ke/i386/traphdlr.c#L1013
//https://www.c7zero.info/stuff/source-seattle-2015-generic_vmm_fingerprinting.pdf
//https://shreklane.github.io/winkrnldocs/d1/d3/ia32trap_8c-source.html

//STATUS_BREAKPOINT
// CC int3
// CD 03 int 3

//STATUS_SINGLE_STEP
// F1 icebp or int1

// STATUS_PRIVILEGED_INSTRUCTION
// 0F 08 invd 
// 0F 06 clts 
// F4 hlt 
// 0F 09 wbinvd 
// 0F 32 rdmsr 

namespace bp_hook
{
	class bp_hook
	{
	private:
		 
		auto set_patch(PVOID addr, BP_TYPE_INFO bp_type, BP_INFO* bp) -> BOOLEAN
		{
			uint32_t copy_size = NULL;
			DWORD old_prot = NULL;

			//STATUS_BREAKPOINT
			uint8_t opcode_int3[] = { 0xCC };
			uint8_t opcode_long_int3[] = { 0xCD , 0x03 };
 			
			//STATUS_SINGLE_STEP
			uint8_t opcode_icebp[] = { 0xF1 };
			
			//STATUS_PRIVILEGED_INSTRUCTION
			uint8_t opcode_invd[] = { 0x0F, 0x08 };
			uint8_t opcode_clts[] = { 0x0F, 0x06 };
			uint8_t opcode_hlt[] = { 0xF4 };
			uint8_t opcode_wbinvd[] = { 0x0F, 0x09 };
			uint8_t opcode_rdmsr[] = { 0x0F, 0x32 };

			//for don't use if,else if and switch
			uint8_t* list_opcode [] = { opcode_int3 ,opcode_long_int3, opcode_icebp,opcode_invd, opcode_clts, opcode_hlt,opcode_wbinvd ,opcode_rdmsr };
			
			if (bp_type == bp_icebp || bp_type == bp_hlt || bp_type == bp_int3)
			{
				copy_size = 1;
			}
			else
			{
				copy_size = 2;
			}
			 
			if (VirtualProtect(addr, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &old_prot))
			{ 
				if (bp_type == bp_icebp)
				{
					bp_single_step_list.push_back(*bp);
				}
				else if (bp_type == bp_int3 || bp_type == bp_long_int3)
				{
					bp_list.push_back(*bp);
				}
				else
				{
					bp_priv_instr_list.push_back(*bp);
				} 
					
				memcpy(addr, list_opcode[bp_type], copy_size);
 				 
				VirtualProtect(addr, sizeof(PVOID), old_prot, &old_prot); 
				return TRUE;
			}
			return FALSE;

		}
	public:
	 
		NO_INLINE auto add_bp(PVOID addr, BP_TYPE_INFO bp_type) -> BOOLEAN
		{
			uint32_t copy_size = NULL;
			BP_INFO bp = { NULL };
			 
			bp.addr_bp = addr;


			if (bp_type == bp_icebp || bp_type == bp_hlt || bp_type == bp_int3)
			{
				copy_size = 1;
			}
			else
			{
				copy_size = 2;
			}

			//https://howtohypervise.blogspot.com/2019/01/a-common-missight-in-most-hypervisors.html
			//not entirely sure, but this is just an example
			bp.addr_single_step = reinterpret_cast<uint8_t*>(addr) + sizeof(uint8_t);
			bp.type_info = bp_type;
			memcpy(bp.orig_byte, addr, 2);
			bp.rip_fixer = cg_util::get_rip_fixer(addr, copy_size);
			  
			if (bp.rip_fixer)
			{
				return set_patch(addr, bp_type, &bp);
			}
			return FALSE; 
 		}

		NO_INLINE auto del_bp(PVOID addr, BP_TYPE_INFO bp_type) -> BOOLEAN
		{
			BOOLEAN is_del = FALSE;
			uint32_t copy_size = NULL;
			DWORD old_prot = NULL;

			if (bp_type == bp_icebp || bp_type == bp_hlt || bp_type == bp_int3)
			{
				copy_size = 1;
			}
			else
			{
				copy_size = 2;
			}

			if (bp_type == bp_icebp)
			{
				for (size_t i = NULL; i < bp_single_step_list.size(); i++)
				{
					if (bp_single_step_list[i].addr_bp == addr && VirtualProtect(addr, copy_size, PAGE_EXECUTE_READWRITE, &old_prot))
					{
						is_del = TRUE;
						memcpy(addr, bp_single_step_list[i].orig_byte, copy_size);
						bp_single_step_list.erase(bp_single_step_list.begin() + i);

						if (bp_single_step_list[i].rip_fixer)
							VirtualFree(bp_single_step_list[i].rip_fixer, NULL, MEM_RELEASE);

						VirtualProtect(addr, copy_size, old_prot, &old_prot);
					}
				} 
			}
			else if (bp_type == bp_int3 || bp_type == bp_long_int3)
			{
				for (size_t i = NULL; i < bp_list.size(); i++)
				{
					if (bp_list[i].addr_bp == addr && VirtualProtect(addr, copy_size, PAGE_EXECUTE_READWRITE, &old_prot))
					{
						is_del = TRUE;
						memcpy(addr, bp_list[i].orig_byte, copy_size);
						bp_list.erase(bp_list.begin() + i);

						if (bp_list[i].rip_fixer)
							VirtualFree(bp_list[i].rip_fixer, NULL, MEM_RELEASE);

						VirtualProtect(addr, copy_size, old_prot, &old_prot);
					}

				} 
			}
			else
			{
				for (size_t i = NULL; i < bp_priv_instr_list.size(); i++)
				{
					if (bp_priv_instr_list[i].addr_bp == addr && VirtualProtect(addr, copy_size, PAGE_EXECUTE_READWRITE, &old_prot))
					{
						is_del = TRUE;
						memcpy(addr, bp_priv_instr_list[i].orig_byte, copy_size);
						bp_priv_instr_list.erase(bp_priv_instr_list.begin() + i);

						if(bp_priv_instr_list[i].rip_fixer)
							VirtualFree(bp_priv_instr_list[i].rip_fixer, NULL, MEM_RELEASE);

						VirtualProtect(addr, copy_size, old_prot, &old_prot);
					}
				} 
			}
			return is_del;
		}
	};
}

#endif // !BP_HOOK
