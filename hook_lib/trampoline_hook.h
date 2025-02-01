#ifndef TRAMPLINE_HOOK_UTIL
#define  TRAMPLINE_HOOK_UTIL 1
#include "Struct.h"
#include "disassembly_util.h"
#include <asmjit.h>

namespace trampline_hook
{
	class tramppline_hook
	{ 
	private:


	public:

		NO_INLINE auto set_hook(PVOID addr, PVOID callback, PVOID* trampline_fun) -> BOOLEAN
		{ 
			DWORD old_prot = NULL;
			PVOID rip_fixer = NULL;
 			PVOID copy_pointer = NULL;

			TRAMPLINE_HOOK cur_hook = { NULL };

#ifndef _WIN64
			uint8_t shell_jmp[] =
			{
				0x50, //push eax
				0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00, // mov [esp+4],NULL
				0xC3  //ret
			};
#else

			uint8_t shell_jmp[] =
			{
				0x50, //push rax
				0x50, //push rax
				0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //mov rax,NULL
				0x48, 0x89, 0x44, 0x24,	0x08, //mpv [rsp+8],rax
				0x58, //pop rax
				0xC3  //ret
			};
#endif // !_WIN64
			 

			cur_hook.addr = addr;
			cur_hook.orig_size = sizeof(shell_jmp);

			copy_pointer = callback;

			memcpy(&cur_hook.orig_byte, addr, sizeof(shell_jmp));
			rip_fixer = cg_util::get_rip_fixer(addr, sizeof(shell_jmp));
			if (rip_fixer)
			{
				*trampline_fun = rip_fixer;
				if (VirtualProtect(addr, sizeof(shell_jmp), PAGE_EXECUTE_READWRITE, &old_prot))
				{
					memcpy(reinterpret_cast<uint8_t*>(shell_jmp) + 4, &copy_pointer, sizeof(PVOID));

					memcpy(addr, shell_jmp, sizeof(shell_jmp));

					VirtualProtect(addr, sizeof(shell_jmp), old_prot, &old_prot);

					trampline_list.push_back(cur_hook);
					return TRUE;
				}
				VirtualFree(rip_fixer, NULL, MEM_RELEASE);

			}
			return FALSE;
		}

		NO_INLINE auto remove_hook(PVOID addr) -> BOOLEAN
		{
			DWORD old_prot = NULL;

			for (size_t i = NULL ; i < trampline_list.size(); i++)
			{
				if (trampline_list[i].addr == addr)
				{
					if (VirtualProtect(addr, trampline_list[i].orig_size, PAGE_EXECUTE_READWRITE, &old_prot))
					{
						memcpy(addr, trampline_list[i].orig_byte, trampline_list[i].orig_size);
						VirtualProtect(addr, trampline_list[i].orig_size, old_prot, &old_prot);
						trampline_list.erase(trampline_list.begin() + i);

						return TRUE;
					}
				}
			}
			return FALSE;
		}
	};
	 
}
#endif // !TRAMPLINE_HOOK_UTIL
