#include <iostream>
#include "excepthion_callback.h"
#include "pointer_hook.h"
#include "bp_hook.h"
#include "hwbp_hook.h"
#include "trampoline_hook.h"
#include "page_hook.h"

//prevent infinite recursion
uint32_t count_call = NULL;

 auto example_filter(EXCEPTION_POINTERS* excep_pointer) -> ULONG
{
    DWORD old_prot = NULL;

    ULONG sys_excep_type = NULL;
    ULONG ret_execute = EXCEPTION_CONTINUE_SEARCH;
    uint64_t sys_excep_addr = NULL;
    MEMORY_BASIC_INFORMATION mbi = { NULL }; 

 

    if (excep_pointer->ExceptionRecord->ExceptionInformation)
    {
        sys_excep_type = excep_pointer->ExceptionRecord->ExceptionInformation[NULL];
        sys_excep_addr = excep_pointer->ExceptionRecord->ExceptionInformation[1];
    }

    
    if (excep_pointer->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
    {


        for (size_t i = NULL; i < pg_list.size(); i++) 
        {
             
            if (sys_excep_addr >= reinterpret_cast<uint64_t>(pg_list[i].reg_addr) && reinterpret_cast<uint64_t>(pg_list[i].reg_addr) + pg_list[i].reg_size > sys_excep_addr)
            {
                if (pg_list[i].access == pg_execute && sys_excep_type == sys_execute)
                { 
                    //call handler
                    printf("callback!\n");
                    count_call++;
                } 
                else if (pg_list[i].access == pg_read && sys_excep_type == sys_read)
                {

                }
                else if (pg_list[i].access == pg_write && sys_excep_type == sys_write)
                {

                }
                excep_pointer->ContextRecord->EFlags |= TRAP_FLAG;
                pg_list[i].is_single_step = TRUE;

                ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                return ret_execute;
            } 
        }

    }
    else if ((excep_pointer->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT || excep_pointer->ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION) && breaked_pointer.size()) // or check all by some status
    {
        for (size_t i = NULL; i < breaked_pointer.size(); i++)
        {
            if (ret_execute == EXCEPTION_CONTINUE_SEARCH && breaked_pointer[i].execute_only)
            {
                if (breaked_pointer[i].bad_pointer == reinterpret_cast<PVOID>(RIP_CONTEXT(excep_pointer->ContextRecord)))
                {
                    printf("exp call ->\t%s\n", breaked_pointer[i].exp_name);

                    RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(breaked_pointer[i].correct_pointer);
                    ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    return ret_execute;
                }
            }
        }
    }

    if (ret_execute == EXCEPTION_CONTINUE_SEARCH)
    {
        if (excep_pointer->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT && bp_list.size())
        {
            for (size_t i = NULL; i < bp_list.size(); i++)
            {
                if (bp_list[i].addr_bp == reinterpret_cast<PVOID>(RIP_CONTEXT(excep_pointer->ContextRecord)))
                {
                    RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(bp_list[i].rip_fixer);
                    ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    return ret_execute;
                }
            }
        }
        else if (excep_pointer->ExceptionRecord->ExceptionCode == STATUS_PRIVILEGED_INSTRUCTION && bp_priv_instr_list.size())
        {
            for (size_t i = NULL; i < bp_priv_instr_list.size(); i++)
            {
                if (bp_priv_instr_list[i].addr_bp == reinterpret_cast<PVOID>(RIP_CONTEXT(excep_pointer->ContextRecord)))
                {
                    RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(bp_priv_instr_list[i].rip_fixer);
                    ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    return ret_execute;
                }
            }
        }
        else if (excep_pointer->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP && (pg_list.size() || bp_single_step_list.size() || hwbp_list.size()))
        {

            for (size_t i = NULL; i < bp_single_step_list.size(); i++)
            {
                if (bp_single_step_list[i].addr_single_step == reinterpret_cast<PVOID>(RIP_CONTEXT(excep_pointer->ContextRecord)))
                {
                    RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(bp_single_step_list[i].rip_fixer);
                    excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                    ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    return ret_execute;
                }
            }
            for (size_t i = NULL; i < hwbp_list.size(); i++)
            {

                if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(RIP_CONTEXT(excep_pointer->ContextRecord)) && hwbp_list[i].access == hwbp_execute)
                {

                    if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr0) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr0))
                    {

                        RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(hwbp_list[i].rip_fixer);
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr1) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr1))
                    {

                        RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(hwbp_list[i].rip_fixer);
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr2) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr2))
                    {

                        RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(hwbp_list[i].rip_fixer);
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr3) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr3))
                    {
                        RIP_CONTEXT(excep_pointer->ContextRecord) = reinterpret_cast<DWORD64>(hwbp_list[i].rip_fixer);
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    return ret_execute;
                }
                else if (hwbp_list[i].access == hwbp_read)
                { 

                    if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr0) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr0))
                    {

                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr1) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr1))
                    {

                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr2) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr2))
                    {
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr3) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr3))
                    {
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    }
                    return ret_execute;
                }
                else if (hwbp_list[i].access == hwbp_write)
                {
                    if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr0) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr0))
                    {
                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                        return ret_execute;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr1) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr1))
                    {

                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                        return ret_execute;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr2) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr2))
                    {

                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                        return ret_execute;
                    }
                    else  if (hwbp_list[i].addr_bp == reinterpret_cast<PVOID>(excep_pointer->ContextRecord->Dr3) && (excep_pointer->ContextRecord->Dr6 & hwbp_excep_bit_dr3))
                    {

                        excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
                        ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                        return ret_execute;
                    }
                }
            }

            for (size_t i = NULL; i < pg_list.size(); i++)
            {
                if (pg_list[i].is_single_step == TRUE)
                {  
                    printf("tf PG!\n");
                    
                    if (count_call == 3)
                    {
                        printf("call 3!\n");
                    }

                    if (count_call != 3 && VirtualQuery(reinterpret_cast<uint8_t*>(excep_pointer->ExceptionRecord->ExceptionAddress), &mbi, sizeof(mbi)))
                    { 
                        if(VirtualProtect(reinterpret_cast<uint8_t*>(excep_pointer->ExceptionRecord->ExceptionAddress), sizeof(PVOID), mbi.Protect | PAGE_GUARD, &old_prot))
                            printf("set PG!\n"); 
                    }
                    else
                    {
                        printf("bad get | set PG!\n"); 
                    }
                    pg_list[i].is_single_step = FALSE;
                    excep_pointer->ContextRecord->EFlags &= ~TRAP_FLAG;
 
                    ret_execute = EXCEPTION_CONTINUE_EXECUTION;
                    return ret_execute;
                }
            }
        }
    }
 



    return ret_execute;
}


PVOID orig_get_context = NULL;

auto my_get_context
(
    HANDLE ThreadHandle,
    PCONTEXT Context
) -> NTSTATUS
{
    printf("get context!\n");
    return STATUS_SUCCESS;
}


int main()
{ 
   
    pointer_swap point_break;
    HMODULE ntdll_base = NULL;
    HMODULE user32_base = NULL;
    PVOID get_context = NULL;
    PVOID message_boxw = NULL;
    CONTEXT ctx = { NULL };
    bp_hook::bp_hook bp_util;
    hwbp_hook::hwbp_hook hwbp_util;
    trampline_hook::tramppline_hook tramp_hook; // :)
    page_guard_hook::page_guard_hook pg_hook;

    SetConsoleTitleW(L"[hook lib]");

    ntdll_base = GetModuleHandleW(L"ntdll.dll");
    user32_base = LoadLibraryW(L"User32.dll");
    get_context = GetProcAddress(ntdll_base, "NtGetContextThread");
    printf("addr get context ->\t%p\n", get_context);
    excep_callback::add_calback(example_filter, excep_ki_dispatcher_callback);

   //export break
   point_break.exp_break(ntdll_base);
   get_context = GetProcAddress(ntdll_base, "NtGetContextThread");
   
   printf("addr get context ->\t%p\n", get_context);
   printf("break export!\n");

   ctx.ContextFlags = CONTEXT_ALL;
   reinterpret_cast<decltype(&NtGetContextThread)>(get_context)(NtCurrentThread, &ctx);
   point_break.exp_unbreak();

    message_boxw = GetProcAddress(user32_base, "MessageBoxW");
    get_context = GetProcAddress(ntdll_base, "NtGetContextThread");

    printf("bp_icebp!\n");
     
    bp_util.add_bp(get_context, bp_icebp);
    reinterpret_cast<decltype(&NtGetContextThread)>(get_context)(NtCurrentThread, &ctx);
    bp_util.del_bp(get_context, bp_icebp);
   
    printf("hwbp!\n");
   
    hwbp_util.set_hwbp(get_context,hwbp_execute, hwbp_byte, NULL, TRUE);
    reinterpret_cast<decltype(&NtGetContextThread)>(get_context)(NtCurrentThread, &ctx);
   
    hwbp_util.set_hwbp(get_context, hwbp_read, hwbp_byte, NULL, TRUE);
    printf("addr get context ->\t%p\n", *reinterpret_cast<uint8_t*>(get_context));
   
    //this will cause recursion, but this is for example :)
    hwbp_util.remove_hwbp(get_context, NULL, TRUE); 
    hwbp_util.remove_hwbp(get_context, NULL, TRUE);
   
    printf("bp system!\n");

    //check correct call with arg RtlDispatchException
    __try
    {
        DebugBreak();
    }
    __except (1)
    {
        printf("bp!\n");
    } 
    printf("tramp_hook!\n");

    tramp_hook.set_hook(get_context, my_get_context, &orig_get_context);
    reinterpret_cast<decltype(&NtGetContextThread)>(get_context)(NtCurrentThread, &ctx);
    tramp_hook.remove_hook(get_context);
   
    printf("pg hook!\n");

    pg_hook.set_pg_hook(message_boxw,pg_execute);
    reinterpret_cast<decltype(&MessageBoxW)>(message_boxw)(NULL,L"Test 1",L"Test 1",MB_OK);
    reinterpret_cast<decltype(&MessageBoxW)>(message_boxw)(NULL,L"Test 2",L"Test 2",MB_OK);
    reinterpret_cast<decltype(&MessageBoxW)>(message_boxw)(NULL,L"Test 3",L"Test 3",MB_OK);
    pg_hook.remove_pg_hook(message_boxw);

     getchar();
    return STATUS_SUCCESS;
}