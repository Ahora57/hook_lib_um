#ifndef POINTER_SWAP
#define POINTER_SWAP 1
#include "Struct.h"
 
class pointer_swap
{
private:

	auto tolower(INT c) -> INT
	{
		if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
		return c;
	}

	auto stricmp(const CHAR* cs, const CHAR* ct) -> INT
	{
		if (cs && ct)
		{
			while (tolower(*cs) == tolower(*ct))
			{
				if (*cs == 0 && *ct == 0) return 0;
				if (*cs == 0 || *ct == 0) break;
				cs++;
				ct++;
			}
			return tolower(*cs) - tolower(*ct);
		}
		return -1;
	}

	auto is_exist_code_cave(PVOID addr) -> BOOLEAN
	{
		for (size_t i = NULL; i < breaked_pointer.size(); i++)
		{
			if (breaked_pointer[i].bad_pointer == addr)
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	 
	auto is_bad_imp(CHAR* name) -> BOOLEAN
	{
		CONST CHAR* ignore_imp_hook[] = 
		{
			"RtlDecodePointer", "RtlEncodePointer", 
			"RtlCreateHeap","RtlProtectHeap","RtlReAllocateHeap","RtlSizeHeap","RtlFreeHeap","RtlAllocateHeap","RtlLockHeap","RtlUnlockHeap",
			"RtlInitializeCriticalSection","RtlDeleteCriticalSection","RtlTryEnterCriticalSection","RtlLeaveCriticalSection","RtlEnterCriticalSection", "RtlInitializeCriticalSectionAndSpinCount",
			"RtlSetLastWin32Error", "RtlSetLastWin32ErrorAndNtStatusFromNtStatus","RtlGetLastNtStatus", "RtlGetLastWin32Error",
			"RtlPcToFileHeader","RtlImageNtHeader",
			"RtlDllShutdownInProgress",
			"memset",

		};

		for (size_t i = 0; i < _countof(ignore_imp_hook); i++)
		{
			if (!stricmp(name, ignore_imp_hook[i]))
			{
				return TRUE;
			}
		}
		return FALSE;
	}

	auto get_rva_code_cave_execute(PVOID mod_addr, PIMAGE_NT_HEADERS headers, PIMAGE_SECTION_HEADER sections) -> uint32_t
	{
		uint8_t* sec_addr = NULL;
		for (size_t i = NULL; i < headers->FileHeader.NumberOfSections; i++)
		{
			if ((sections[i].Characteristics & IMAGE_SCN_MEM_READ) && (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE))
			{
				sec_addr = reinterpret_cast<uint8_t*>(mod_addr) + sections[i].VirtualAddress;
				for (size_t j = NULL; j < sections[i].Misc.VirtualSize; j++)
				{
					if (*(sec_addr + j) == OPCODE_INT3 && !(is_exist_code_cave(sec_addr + j)))
					{
						return sections[i].VirtualAddress + j;
					}
				}
			}
		}
		return NULL;
	}
public:

	auto imp_swap(PVOID mod_addr, CHAR* name_dll, CHAR* name_api, PVOID point) -> BOOLEAN
	{
		BOOLEAN is_imp_change = FALSE;
		DWORD old_prot = NULL;
		CHAR* name_imp_dll = NULL;
		uint64_t* orig_first_thunk = NULL;
		uint64_t* first_thunk = NULL;
 		PIMAGE_NT_HEADERS headers = NULL;
		PIMAGE_SECTION_HEADER sections = NULL;
		PIMAGE_IMPORT_BY_NAME import_name = NULL;
		PIMAGE_IMPORT_DESCRIPTOR imp_descript = NULL;
		
		headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(mod_addr) + static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew);
		sections = IMAGE_FIRST_SECTION(headers);

		if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		{
			imp_descript = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<CHAR*>(name_dll) + headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			for (; imp_descript->Name; ++imp_descript)
			{
				name_imp_dll = reinterpret_cast<CHAR*>(mod_addr) + imp_descript->Name;
				 
				if (!stricmp(name_imp_dll, name_dll))
				{
					orig_first_thunk = reinterpret_cast<uint64_t*>(reinterpret_cast<CHAR*>(mod_addr) + imp_descript->OriginalFirstThunk);
					first_thunk = reinterpret_cast<uint64_t*>(reinterpret_cast<CHAR*>(mod_addr) + imp_descript->FirstThunk);

					if (!orig_first_thunk) //load by index https://stackoverflow.com/questions/42413937/why-pe-need-original-first-thunkoft
					{
						return is_imp_change;
					}
					for (; *orig_first_thunk; orig_first_thunk++, first_thunk++)
					{  
						import_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(reinterpret_cast<CHAR*>(mod_addr) + *orig_first_thunk);
						if (import_name->Name && !stricmp(import_name->Name, name_api))
						{
							if (VirtualProtect(first_thunk,PAGE_SIZE, PAGE_EXECUTE_READWRITE,&old_prot))
							{
								*first_thunk = reinterpret_cast<uint64_t>(point);
								VirtualProtect(first_thunk, PAGE_SIZE, old_prot, &old_prot);

								is_imp_change = TRUE;
							}
 						} 

					}
				}
				
			}
		}
		return is_imp_change;
	}

	auto exp_unbreak() -> VOID
	{
		DWORD old_prot = NULL;
		for (size_t i = NULL; i < breaked_pointer.size(); i++)
		{
			if (VirtualProtect(breaked_pointer[i].swap_pointer, sizeof(PVOID), PAGE_READWRITE, &old_prot))
			{
				*reinterpret_cast<ULONG*>(breaked_pointer[i].swap_pointer) = breaked_pointer[i].correct_rva;
				VirtualProtect(breaked_pointer[i].swap_pointer, sizeof(PVOID), old_prot, &old_prot);
			}
		}
		breaked_pointer.clear();
	}
	auto exp_break(PVOID mod_addr) -> BOOLEAN
	{

		BOOLEAN is_success = FALSE;
		DWORD old_prot = NULL;
		uint32_t code_cave = NULL;
		CHAR* name_exp = NULL;
		uint8_t* memory_sec = NULL;
 		PIMAGE_NT_HEADERS headers = NULL;
		PIMAGE_SECTION_HEADER sections  = NULL;
		PIMAGE_EXPORT_DIRECTORY export_info = NULL;
		POINTER_BAD cur_point_bad = { NULL };
 
 
		if (static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_magic == IMAGE_DOS_SIGNATURE)
		{

			headers = reinterpret_cast<PIMAGE_NT_HEADERS>(static_cast<CHAR*>(mod_addr) + static_cast<PIMAGE_DOS_HEADER>(mod_addr)->e_lfanew);
			sections = IMAGE_FIRST_SECTION(headers);

			if (headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
			{
				export_info = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<CHAR*>(mod_addr) +   headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				if (sizeof(uint8_t) > export_info->NumberOfFunctions)
				{
					return is_success;
				}

				auto names = (PDWORD)(reinterpret_cast<CHAR*>(mod_addr) +  export_info->AddressOfNames);
				auto ordinals = (PWORD)(reinterpret_cast<CHAR*>(mod_addr) +  export_info->AddressOfNameOrdinals);
				auto functions = (PDWORD)(reinterpret_cast<CHAR*>(mod_addr) +  export_info->AddressOfFunctions);


				for (uint32_t i = NULL; i < export_info->NumberOfFunctions; ++i)
				{
					if (!code_cave)
						code_cave = get_rva_code_cave_execute(mod_addr, headers, sections);

					if (!code_cave)
					{
						printf("bad ->\t%s\n", reinterpret_cast<CHAR*>(mod_addr) + names[i]);
					}

					 

					if (!is_bad_imp(reinterpret_cast<CHAR*>(mod_addr) + names[i]) &&& code_cave && VirtualProtect(&functions[ordinals[i]], PAGE_SIZE, PAGE_READWRITE, &old_prot))
					{
						//push addr excep(mod+i)
						//copy correct address
						//after change only set fake;
						cur_point_bad.bad_pointer = reinterpret_cast<CHAR*>(mod_addr) + code_cave;
						cur_point_bad.correct_pointer = reinterpret_cast<CHAR*>(mod_addr) + functions[ordinals[i]];
						cur_point_bad.execute_only = TRUE;
						cur_point_bad.exp_name = reinterpret_cast<CHAR*>(mod_addr) + names[i];
						cur_point_bad.correct_rva = functions[ordinals[i]];

						//for remove if need
						cur_point_bad.swap_pointer = &functions[ordinals[i]];
						breaked_pointer.push_back(cur_point_bad);
						 
						functions[ordinals[i]] = code_cave;

						is_success = TRUE;
						VirtualProtect(&functions[ordinals[i]], PAGE_SIZE, old_prot, &old_prot);

						code_cave = NULL;
					}


				}					
 			}

		}
		return is_success;
	}
};
#endif // !POINTER_SWAP
