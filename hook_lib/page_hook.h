#ifndef PH_HOOK_UTIL
#define PH_HOOK_UTIL 1
#include "Struct.h"
 
namespace page_guard_hook
{
	class page_guard_hook
	{ 
	private:

	public:

		NO_INLINE auto set_pg_hook(PVOID addr, PAGE_GUARD_TYPE_ACCESS access)
		{
			DWORD old_prot = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL };
			PAGE_GUARD_INFO cur_pg;

			if(VirtualQuery(addr, &mbi, sizeof(mbi)))
			{
				if (!(mbi.Protect & PAGE_GUARD) && !(mbi.Protect & PAGE_NOACCESS))
				{
					cur_pg.is_single_step = FALSE;
					cur_pg.access = access;
					cur_pg.addr = addr;
					cur_pg.reg_addr = mbi.BaseAddress;
					cur_pg.reg_size = mbi.RegionSize;
					 
 					if (VirtualProtect(addr, sizeof(PVOID), mbi.Protect | PAGE_GUARD, &old_prot))
					{
						pg_list.push_back(cur_pg);
						return TRUE;
					}
				}
			}
			return FALSE;
		}

		NO_INLINE auto remove_pg_hook(PVOID addr)
		{
			DWORD old_prot = NULL;
			MEMORY_BASIC_INFORMATION mbi = { NULL }; 

			for (size_t i = 0; i < pg_list.size(); i++)
			{
				if (pg_list[i].reg_addr == addr || (addr >= pg_list[i].reg_addr && reinterpret_cast<uint8_t*>(pg_list[i].reg_addr) + pg_list[i].reg_size > addr))
				{
					if (VirtualQuery(addr, &mbi, sizeof(mbi)))
					{
						if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS))
						{
							mbi.Protect &= ~(PAGE_GUARD | PAGE_NOACCESS);
							if (VirtualProtect(addr, mbi.RegionSize, sizeof(PVOID), &old_prot))
							{
								hwbp_list.erase(hwbp_list.begin() + i);
								return TRUE;
							}
						}
					}
				}
			}
			 
			return FALSE;
		}
	};

}

#endif // !PH_HOOK_UTIL
