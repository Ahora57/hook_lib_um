#ifndef HWBP_HOOK
#define HWBP_HOOK 1

#include "Struct.h"
#include "nt_api.h"

#ifndef bit_set  
#define bit_set(bit_id) (1 << (bit_id -1))
#endif // !bit_set


namespace hwbp_hook
{
	class hwbp_hook
	{
		 
	 
	private:

		auto malloc(size_t size) -> PVOID
		{
			return VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		}

		auto free(PVOID ptr) -> VOID
		{
			if (nullptr != ptr)
				VirtualFree(ptr, NULL, MEM_RELEASE);
		}


		//The value in DRn defines the low - end of the address range used in the comparison.LENn is used
		//	to mask the low - order address bits in the corresponding DRn register so that they are not used in
		//	the address comparison.To work properly, breakpoint boundaries must be aligned on an address
		//	corresponding to the range size specified by LENn.The LENn control - field encodings specify the
		//	following address - breakpoint - comparison ranges :
		//	-00—1 byte.
		//	- 01—2 byte, must be aligned on a word boundary.
		//	- 10—8 byte, must be aligned on a quadword boundary. (Long mode only; otherwise undefined.)
		//	- 11—4 byte, must be aligned on a doubleword boundary.
		
		auto set_thread_dr(PVOID addr, HWBP_TYPE_ACCESS hwbp_access, HWBP_LEN_ACCESS hwbp_len, PCONTEXT ctx) -> BOOLEAN
		{
			DWORD64 mask_dr = NULL;
			  
			if (!ctx->Dr0)
			{
 				ctx->Dr7 |= bit_set(hwbp_dr0);
				 
				if (hwbp_access == hwbp_execute)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr0_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr0_read);
				}
				else if (hwbp_access == hwbp_write)
				{
					ctx->Dr7 |= bit_set(hwbp_dr0_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr0_read);
				}
				else if (hwbp_access == hwbp_read)
				{
					ctx->Dr7 |= bit_set(hwbp_dr0_read_write);
					ctx->Dr7 |= bit_set(hwbp_dr0_read);
				} 

				if (hwbp_len == hwbp_byte)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr0_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr0_len_dword); 
				}
				else if (hwbp_len == hwbp_word)
				{
					ctx->Dr7 |= bit_set(hwbp_dr0_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr0_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 |= bit_set(hwbp_dr0_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr0_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr0_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr0_len_dword);
				}
				ctx->Dr0 = reinterpret_cast<DWORD64>(addr);
				return TRUE;
			}
			else if (!ctx->Dr1)
			{
				ctx->Dr7 |= bit_set(hwbp_dr1);
				if (hwbp_access == hwbp_execute)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr1_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr1_read);
				}
				else if (hwbp_access == hwbp_write)
				{
					ctx->Dr7 |= bit_set(hwbp_dr1_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr1_read);
				}
				else if (hwbp_access == hwbp_read)
				{
					ctx->Dr7 |= bit_set(hwbp_dr1_read_write);
					ctx->Dr7 |= bit_set(hwbp_dr1_read);
				}

				if (hwbp_len == hwbp_byte)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr1_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr1_len_dword);
				}
				else if (hwbp_len == hwbp_word)
				{
					ctx->Dr7 |= bit_set(hwbp_dr1_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr1_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 |= bit_set(hwbp_dr1_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr1_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr1_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr1_len_dword);
				}

				ctx->Dr1 = reinterpret_cast<DWORD64>(addr);

				return TRUE;
			}
			else if (!ctx->Dr2)
			{
				ctx->Dr7 |= bit_set(hwbp_dr2);
				if (hwbp_access == hwbp_execute)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr2_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr2_read);
				}
				else if (hwbp_access == hwbp_write)
				{
					ctx->Dr7 |= bit_set(hwbp_dr2_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr2_read);
				}
				else if (hwbp_access == hwbp_read)
				{
					ctx->Dr7 |= bit_set(hwbp_dr2_read_write);
					ctx->Dr7 |= bit_set(hwbp_dr2_read);
				}


				if (hwbp_len == hwbp_byte)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr2_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr2_len_dword);
				}
				else if (hwbp_len == hwbp_word)
				{
					ctx->Dr7 |= bit_set(hwbp_dr2_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr2_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 |= bit_set(hwbp_dr2_len_dword);
					ctx->Dr7 |= bit_set(hwbp_dr2_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr2_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr2_len_dword);
				}

				ctx->Dr2 = reinterpret_cast<DWORD64>(addr);

				return TRUE;
			}
			else if (!ctx->Dr3)
			{
				ctx->Dr7 |= bit_set(hwbp_dr3);
				if (hwbp_access == hwbp_execute)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr3_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr3_read);
				}
				else if (hwbp_access == hwbp_write)
				{
					ctx->Dr7 |= bit_set(hwbp_dr3_read_write);
					ctx->Dr7 &= ~bit_set(hwbp_dr3_read);
				}
				else if (hwbp_access == hwbp_read)
				{
					ctx->Dr7 |= bit_set(hwbp_dr3_read_write);
					ctx->Dr7 |= bit_set(hwbp_dr3_read);
				} 


				if (hwbp_len == hwbp_byte)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr3_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr3_len_dword);
				}
				else if (hwbp_len == hwbp_word)
				{
					ctx->Dr7 |= bit_set(hwbp_dr3_len_word);
					ctx->Dr7 &= ~bit_set(hwbp_dr3_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 |= bit_set(hwbp_dr3_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr3_len_dword);
				}
				else if (hwbp_len == hwbp_dword)
				{
					ctx->Dr7 &= ~bit_set(hwbp_dr3_len_word);
					ctx->Dr7 |= bit_set(hwbp_dr3_len_dword);
				}
				ctx->Dr3 = reinterpret_cast<DWORD64>(addr);

				return TRUE;
			}
			return FALSE;

		}


		auto remove_thread_dr(PVOID addr,  PCONTEXT ctx) -> BOOLEAN
		{
			DWORD64 mask_dr = NULL;

			if (ctx->Dr0 == reinterpret_cast<DWORD64>(addr))
			{
				ctx->Dr7 &= ~bit_set(hwbp_dr0);

				ctx->Dr7 &= ~bit_set(hwbp_dr0_read_write);
				ctx->Dr7 &= ~bit_set(hwbp_dr0_read);

				ctx->Dr7 &= ~bit_set(hwbp_dr0_len_word);
				ctx->Dr7 &= ~bit_set(hwbp_dr0_len_dword);

				ctx->Dr0 = NULL;
				return TRUE;
			}
			else if (ctx->Dr1 == reinterpret_cast<DWORD64>(addr))
			{
				ctx->Dr7 &= ~bit_set(hwbp_dr1);

				ctx->Dr7 &= ~bit_set(hwbp_dr1_read_write);
				ctx->Dr7 &= ~bit_set(hwbp_dr1_read);

				ctx->Dr7 &= ~bit_set(hwbp_dr1_len_word);
				ctx->Dr7 &= ~bit_set(hwbp_dr1_len_dword);

				ctx->Dr1 = NULL;
				return TRUE; 
			}
			else if (ctx->Dr2 == reinterpret_cast<DWORD64>(addr))
			{
				ctx->Dr7 &= ~bit_set(hwbp_dr2);

				ctx->Dr7 &= ~bit_set(hwbp_dr2_read_write);
				ctx->Dr7 &= ~bit_set(hwbp_dr2_read);

				ctx->Dr7 &= ~bit_set(hwbp_dr2_len_word);
				ctx->Dr7 &= ~bit_set(hwbp_dr2_len_dword);

				ctx->Dr2 = NULL;
				return TRUE;
			}
			else if (ctx->Dr3 == reinterpret_cast<DWORD64>(addr))
			{
				ctx->Dr7 &= ~bit_set(hwbp_dr3);

				ctx->Dr7 &= ~bit_set(hwbp_dr3_read_write);
				ctx->Dr7 &= ~bit_set(hwbp_dr3_read);

				ctx->Dr7 &= ~bit_set(hwbp_dr3_len_word);
				ctx->Dr7 &= ~bit_set(hwbp_dr3_len_dword);

				ctx->Dr3 = NULL;
				return TRUE;
			}
			return FALSE;

		}
 
 
	public:
 
		NO_INLINE auto set_hwbp(PVOID addr, HWBP_TYPE_ACCESS hwbp_access, HWBP_LEN_ACCESS hwbp_len, uint32_t thread_id = NULL, BOOLEAN set_all_thread = FALSE) -> BOOLEAN
		{
			BOOLEAN is_success = FALSE;
			ULONG ret_lenght = NULL;
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			PVOID nt_get_context = NULL;
			PVOID nt_set_context = NULL;

			PVOID nt_query_sys = NULL;

			PVOID buffer = NULL;
			HANDLE acces = NULL;
			PSYSTEM_PROCESS_INFORMATION process_info = NULL;

			HMODULE ntdll_base = NULL;
			CONTEXT ctx = { NULL };
			HWBP_INFO cur_hwbp;

			ntdll_base = GetModuleHandleW(L"ntdll.dll");

			if (ntdll_base)
			{
				nt_get_context = GetProcAddress(ntdll_base, "NtGetContextThread");
				nt_set_context = GetProcAddress(ntdll_base, "NtSetContextThread");

				nt_query_sys = GetProcAddress(ntdll_base, "NtQuerySystemInformation");
  
				if (nt_get_context && nt_set_context && nt_query_sys)
				{
					if (set_all_thread)
					{

						nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_sys)(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);
						while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
						{
							if (buffer != NULL)
								free(buffer);

							buffer = malloc(ret_lenght);
							nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_sys)(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
						}

						if (!NT_SUCCESS(nt_status))
						{
							if (buffer != NULL)
								free(buffer);
							return FALSE;
						}
						process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
						while (process_info->NextEntryOffset) // Loop over the list until we reach the last entry.
						{
							if (reinterpret_cast<uint32_t>(process_info->UniqueProcessId) == GetCurrentProcessId())
							{
								is_success = TRUE;

								if (hwbp_access == hwbp_execute)
								{
									cur_hwbp.rip_fixer = cg_util::get_rip_fixer(addr, MIN_LENGHT_INSTR);
								}
								else
								{
									cur_hwbp.rip_fixer = NULL;
								}

 								cur_hwbp.access = hwbp_access;
								cur_hwbp.addr_bp = addr; 
								cur_hwbp.addr_single_step = reinterpret_cast<uint8_t*>(addr) + sizeof(uint8_t);

								hwbp_list.push_back(cur_hwbp);

								for (size_t i = NULL; i < process_info->NumberOfThreads; i++)
								{
									acces = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, reinterpret_cast<uint32_t>(process_info->Threads[i].ClientId.UniqueThread));
									if (acces)
									{
										ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
										nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context)(acces, &ctx);
										if (NT_SUCCESS(nt_status))
										{
											if (set_thread_dr(addr, hwbp_access, hwbp_len, &ctx))
											{
												ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
												nt_status = reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context)(acces, &ctx);
												if (!NT_SUCCESS(nt_status))
												{
													is_success = FALSE;
												}
											}
											else
											{
												is_success = FALSE;
											}
										}
										else
										{
											is_success = FALSE;
										}
										CloseHandle(acces);
									} 
									else
									{
										is_success = FALSE;
									} 
								}
								break;
							}
							process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset); // Calculate the address of the next entry.
						}
						free(buffer);
					}
					else
					{
						acces = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
						if (acces)
						{
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context)(acces, &ctx);
							if (NT_SUCCESS(nt_status))
							{
								if (set_thread_dr(addr, hwbp_access, hwbp_len, &ctx))
								{
									ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
									nt_status = reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context)(acces, &ctx);
									if (NT_SUCCESS(nt_status))
									{
										is_success = TRUE;
									}
								} 
							} 
						}
					}
				}
			}
			return is_success;
		}

		NO_INLINE auto remove_hwbp(PVOID addr, uint32_t thread_id = NULL, BOOLEAN remove_all_thread = FALSE) -> BOOLEAN
		{
			BOOLEAN is_success = FALSE;
			ULONG ret_lenght = NULL;
			NTSTATUS nt_status = STATUS_UNSUCCESSFUL;
			PVOID nt_get_context = NULL;
			PVOID nt_set_context = NULL;

			PVOID nt_query_sys = NULL;

			PVOID buffer = NULL;
			HANDLE acces = NULL;
			PSYSTEM_PROCESS_INFORMATION process_info = NULL;

			HMODULE ntdll_base = NULL;
			CONTEXT ctx = { NULL };

			ntdll_base = GetModuleHandleW(L"ntdll.dll");

			if (ntdll_base)
			{
				nt_get_context = GetProcAddress(ntdll_base, "NtGetContextThread");
				nt_set_context = GetProcAddress(ntdll_base, "NtSetContextThread");

				nt_query_sys = GetProcAddress(ntdll_base, "NtQuerySystemInformation");

				if (nt_get_context && nt_set_context && nt_query_sys)
				{
					if (remove_all_thread)
					{

						nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_sys)(SystemProcessInformation, &ret_lenght, ret_lenght, &ret_lenght);
						while (nt_status == STATUS_INFO_LENGTH_MISMATCH)
						{
							if (buffer != NULL)
								free(buffer);

							buffer = malloc(ret_lenght);
							nt_status = reinterpret_cast<decltype(&NtQuerySystemInformation)>(nt_query_sys)(SystemProcessInformation, buffer, ret_lenght, &ret_lenght);
						}

						process_info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);
						while (process_info->NextEntryOffset) // Loop over the list until we reach the last entry.
						{
							if (reinterpret_cast<uint32_t>(process_info->UniqueProcessId) == GetCurrentProcessId())
							{
								is_success = TRUE;
								for (size_t i = NULL; i < process_info->NumberOfThreads; i++)
								{
									acces = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, reinterpret_cast<uint32_t>(process_info->Threads[i].ClientId.UniqueThread));
									if (acces)
									{
										ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
										nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context)(acces, &ctx);
										if (NT_SUCCESS(nt_status))
										{
											remove_thread_dr(addr, &ctx);

											ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; 
											nt_status = reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context)(acces, &ctx);
											if (!NT_SUCCESS(nt_status))
											{
												is_success = FALSE;
											}
										}
										else
										{
											is_success = FALSE;
										}										
										CloseHandle(acces);
									}
									else
									{
										is_success = FALSE;
									}
								}
								break;
							}
							process_info = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)process_info + process_info->NextEntryOffset); // Calculate the address of the next entry.
						}
						free(buffer);
					}
					else
					{
						acces = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, thread_id);
						if (acces)
						{
							ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
							nt_status = reinterpret_cast<decltype(&NtGetContextThread)>(nt_get_context)(acces, &ctx);
							if (NT_SUCCESS(nt_status))
							{
								remove_thread_dr(addr, &ctx);
 								ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
								nt_status = reinterpret_cast<decltype(&NtSetContextThread)>(nt_set_context)(acces, &ctx);
								if (NT_SUCCESS(nt_status))
								{
									is_success = TRUE;
								} 
							}										
							CloseHandle(acces);
						}
					}
				}
			}
			if (is_success)
			{
				for (size_t i = NULL; i < hwbp_list.size(); i++)
				{ 
					if (hwbp_list[i].addr_bp == addr)
					{
						hwbp_list.erase(hwbp_list.begin() + i);

						if (hwbp_list[i].rip_fixer)
							VirtualFree(hwbp_list[i].rip_fixer, NULL, MEM_RELEASE);
					}
				} 
			}
			return is_success;
		}
	};


}
#endif // !HWBP_HOOK
