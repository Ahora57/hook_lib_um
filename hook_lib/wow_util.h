#ifndef WOW_UTIL
#define WOW_UTIL 1
#include "Struct.h"

#ifndef _WIN64

// sorry i had to ctrl + C & ctrl + V this in but i wasn't in the best mood when i was thinking about this part ಥ_ಥ


 /*
 *
 * WOW64Ext Library
 *
 * Copyright (c) 2014 ReWolf
 * http://blog.rewolf.pl/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define PTR_TO_DWORD64(p) ((DWORD64)(ULONG_PTR)(p))




//to fool M$ inline asm compiler I'm using 2 DWORDs instead of DWORD64
//use of DWORD64 will generate wrong 'pop word ptr[]' and it will break stack
union reg64
{
    DWORD64 v;
    DWORD dw[2];
};


//https://github.com/rwfpl/rewolf-wow64ext/blob/master/src/internal.h
#pragma pack(push)
#pragma pack(1)
template <class T>
struct _LIST_ENTRY_T
{
    T Flink;
    T Blink;
};

template <class T>
struct _UNICODE_STRING_T
{
    union
    {
        struct
        {
            WORD Length;
            WORD MaximumLength;
        };
        T dummy;
    };
    T Buffer;
};

template <class T>
struct _NT_TIB_T
{
    T ExceptionList;
    T StackBase;
    T StackLimit;
    T SubSystemTib;
    T FiberData;
    T ArbitraryUserPointer;
    T Self;
};

template <class T>
struct _WOW_CLIENT_ID
{
    T UniqueProcess;
    T UniqueThread;
};

template <class T>
struct _TEB_T_
{
    _NT_TIB_T<T> NtTib;
    T EnvironmentPointer;
    _WOW_CLIENT_ID<T> ClientId;
    T ActiveRpcHandle;
    T ThreadLocalStoragePointer;
    T ProcessEnvironmentBlock;
    DWORD LastErrorValue;
    DWORD CountOfOwnedCriticalSections;
    T CsrClientThread;
    T Win32ThreadInfo;
    DWORD User32Reserved[26];
    //rest of the structure is not defined for now, as it is not needed
};

template <class T>
struct _LDR_DATA_TABLE_ENTRY_T
{
    _LIST_ENTRY_T<T> InLoadOrderLinks;
    _LIST_ENTRY_T<T> InMemoryOrderLinks;
    _LIST_ENTRY_T<T> InInitializationOrderLinks;
    T DllBase;
    T EntryPoint;
    union
    {
        DWORD SizeOfImage;
        T dummy01;
    };
    _UNICODE_STRING_T<T> FullDllName;
    _UNICODE_STRING_T<T> BaseDllName;
    DWORD Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union
    {
        _LIST_ENTRY_T<T> HashLinks;
        struct
        {
            T SectionPointer;
            T CheckSum;
        };
    };
    union
    {
        T LoadedImports;
        DWORD TimeDateStamp;
    };
    T EntryPointActivationContext;
    T PatchInformation;
    _LIST_ENTRY_T<T> ForwarderLinks;
    _LIST_ENTRY_T<T> ServiceTagLinks;
    _LIST_ENTRY_T<T> StaticLinks;
    T ContextInformation;
    T OriginalBase;
    _LARGE_INTEGER LoadTime;
};

template <class T>
struct _PEB_LDR_DATA_T
{
    DWORD Length;
    DWORD Initialized;
    T SsHandle;
    _LIST_ENTRY_T<T> InLoadOrderModuleList;
    _LIST_ENTRY_T<T> InMemoryOrderModuleList;
    _LIST_ENTRY_T<T> InInitializationOrderModuleList;
    T EntryInProgress;
    DWORD ShutdownInProgress;
    T ShutdownThreadId;

};

template <class T, class NGF, int A>
struct _PEB_T
{
    union
    {
        struct
        {
            BYTE InheritedAddressSpace;
            BYTE ReadImageFileExecOptions;
            BYTE BeingDebugged;
            BYTE BitField;
        };
        T dummy01;
    };
    T Mutant;
    T ImageBaseAddress;
    T Ldr;
    T ProcessParameters;
    T SubSystemData;
    T ProcessHeap;
    T FastPebLock;
    T AtlThunkSListPtr;
    T IFEOKey;
    T CrossProcessFlags;
    T UserSharedInfoPtr;
    DWORD SystemReserved;
    DWORD AtlThunkSListPtr32;
    T ApiSetMap;
    T TlsExpansionCounter;
    T TlsBitmap;
    DWORD TlsBitmapBits[2];
    T ReadOnlySharedMemoryBase;
    T HotpatchInformation;
    T ReadOnlyStaticServerData;
    T AnsiCodePageData;
    T OemCodePageData;
    T UnicodeCaseTableData;
    DWORD NumberOfProcessors;
    union
    {
        DWORD NtGlobalFlag;
        NGF dummy02;
    };
    LARGE_INTEGER CriticalSectionTimeout;
    T HeapSegmentReserve;
    T HeapSegmentCommit;
    T HeapDeCommitTotalFreeThreshold;
    T HeapDeCommitFreeBlockThreshold;
    DWORD NumberOfHeaps;
    DWORD MaximumNumberOfHeaps;
    T ProcessHeaps;
    T GdiSharedHandleTable;
    T ProcessStarterHelper;
    T GdiDCAttributeList;
    T LoaderLock;
    DWORD OSMajorVersion;
    DWORD OSMinorVersion;
    WORD OSBuildNumber;
    WORD OSCSDVersion;
    DWORD OSPlatformId;
    DWORD ImageSubsystem;
    DWORD ImageSubsystemMajorVersion;
    T ImageSubsystemMinorVersion;
    T ActiveProcessAffinityMask;
    T GdiHandleBuffer[A];
    T PostProcessInitRoutine;
    T TlsExpansionBitmap;
    DWORD TlsExpansionBitmapBits[32];
    T SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    T pShimData;
    T AppCompatInfo;
    _UNICODE_STRING_T<T> CSDVersion;
    T ActivationContextData;
    T ProcessAssemblyStorageMap;
    T SystemDefaultActivationContextData;
    T SystemAssemblyStorageMap;
    T MinimumStackCommit;
    T FlsCallback;
    _LIST_ENTRY_T<T> FlsListHead;
    T FlsBitmap;
    DWORD FlsBitmapBits[4];
    T FlsHighIndex;
    T WerRegistrationData;
    T WerShipAssertPtr;
    T pContextData;
    T pImageHeaderHash;
    T TracingFlags;
};

typedef _LDR_DATA_TABLE_ENTRY_T<DWORD> LDR_DATA_TABLE_ENTRY32;
typedef _LDR_DATA_TABLE_ENTRY_T<DWORD64> LDR_DATA_TABLE_ENTRY64;

typedef _TEB_T_<DWORD> TEB32;
typedef _TEB_T_<DWORD64> TEB64;

typedef _PEB_LDR_DATA_T<DWORD> PEB_LDR_DATA32;
typedef _PEB_LDR_DATA_T<DWORD64> PEB_LDR_DATA64;

typedef _PEB_T<DWORD, DWORD64, 34> PEB32;
typedef _PEB_T<DWORD64, DWORD, 30> PEB64;

struct _XSAVE_FORMAT64
{
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    _M128A FloatRegisters[8];
    _M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _CONTEXT64
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    _XSAVE_FORMAT64 FltSave;
    _M128A Header[2];
    _M128A Legacy[8];
    _M128A Xmm0;
    _M128A Xmm1;
    _M128A Xmm2;
    _M128A Xmm3;
    _M128A Xmm4;
    _M128A Xmm5;
    _M128A Xmm6;
    _M128A Xmm7;
    _M128A Xmm8;
    _M128A Xmm9;
    _M128A Xmm10;
    _M128A Xmm11;
    _M128A Xmm12;
    _M128A Xmm13;
    _M128A Xmm14;
    _M128A Xmm15;
    _M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};
 

#pragma pack(pop)

namespace wow_util
{ 

    void getMem64(void* dstMem, DWORD64 srcMem, size_t sz)
    {
        if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
            return;

        reg64 _src = { srcMem };

        __asm
        {
            X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi;// push     rdi
            push   esi;// push     rsi
            ;//
            mov    edi, dstMem;// mov      edi, dword ptr [dstMem]        ; high part of RDI is zeroed
            REX_W mov    esi, _src.dw[0];// mov      rsi, qword ptr [_src]
            mov    ecx, sz;// mov      ecx, dword ptr [sz]            ; high part of RCX is zeroed
            ;//
            mov    eax, ecx;// mov      eax, ecx
            and eax, 3;// and      eax, 3
            shr    ecx, 2;// shr      ecx, 2
            ;//
            rep    movsd;// rep movs dword ptr [rdi], dword ptr [rsi]
            ;//
            test   eax, eax;// test     eax, eax
            je     _move_0;// je       _move_0
            cmp    eax, 1;// cmp      eax, 1
            je     _move_1;// je       _move_1
            ;//
            movsw;// movs     word ptr [rdi], word ptr [rsi]
            cmp    eax, 2;// cmp      eax, 2
            je     _move_0;// je       _move_0
            ;//
        _move_1:;//
            movsb;// movs     byte ptr [rdi], byte ptr [rsi]
            ;//
        _move_0:;//
            pop    esi;// pop      rsi
            pop    edi;// pop      rdi

            X64_End();
        }
    }
 


    void* malloc(size_t size)
    {
        return HeapAlloc(GetProcessHeap(), NULL, size);
    }

    void free(void* ptr)
    {
        if (nullptr != ptr)
            HeapFree(GetProcessHeap(), NULL, ptr);
    }

    int _wcsicmp(const wchar_t* string1, const wchar_t* string2)
    {
        wchar_t c1;
        wchar_t c2;
        int i = 0;
        do
        {
            c1 = string1[i];
            if (c1 >= 'A' && c1 <= 'Z')
                c1 += 0x20;

            c2 = string2[i];
            if (c2 >= 'A' && c2 <= 'Z')
                c2 += 0x20;

            i++;
        } while (c1 && c1 == c2);
        return c1 - c2;
    }

 

#pragma warning(push)
#pragma warning(disable : 4409)
    DWORD64 __cdecl X64Call(DWORD64 func, INT argC, ...)
    { 

        va_list args;
        va_start(args, argC);
        reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
        reg64 _rax = { 0 };

        reg64 restArgs = { PTR_TO_DWORD64(&va_arg(args, DWORD64)) };

        // conversion to QWORD for easier use in inline assembly
        reg64 _argC = { (DWORD64)argC };
        DWORD back_esp = 0;
        WORD back_fs = 0;

        __asm
        {
            ;// reset FS segment, to properly handle RFG
            mov    back_fs, fs
                mov    eax, 0x2B
                mov    fs, ax

                ;// keep original esp in back_esp variable
            mov    back_esp, esp

                ;// align esp to 0x10, without aligned stack some syscalls may return errors !
            ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
            ;// requires 0x10 alignment), it will be further adjusted according to the
            ;// number of arguments above 4
            and esp, 0xFFFFFFF0

                X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            ;// fill first four arguments
            REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
            REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
            push   _r8.v;// push    qword ptr [_r8]
            X64_Pop(_R8); ;// pop     r8
            push   _r9.v;// push    qword ptr [_r9]
            X64_Pop(_R9); ;// pop     r9
            ;//
            REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
            ;// 
            ;// final stack adjustment, according to the    ;//
            ;// number of arguments above 4                 ;// 
            test   al, 1;// test    al, 1
            jnz    _no_adjust;// jnz     _no_adjust
            sub    esp, 8;// sub     rsp, 8
        _no_adjust:;//
            ;// 
            push   edi;// push    rdi
            REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
            ;// 
            ;// put rest of arguments on the stack          ;// 
            REX_W test   eax, eax;// test    rax, rax
            jz     _ls_e;// je      _ls_e
            REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
            ;// 
        _ls:;// 
            REX_W test   eax, eax;// test    rax, rax
            jz     _ls_e;// je      _ls_e
            push   dword ptr[edi];// push    qword ptr [rdi]
            REX_W sub    edi, 8;// sub     rdi, 8
            REX_W sub    eax, 1;// sub     rax, 1
            jmp    _ls;// jmp     _ls
        _ls_e:;// 
            ;// 
            ;// create stack space for spilling registers   ;// 
            REX_W sub    esp, 0x20;// sub     rsp, 20h
            ;// 
            call   func;// call    qword ptr [func]
            ;// 
            ;// cleanup stack                               ;// 
            REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
            REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
            ;// 
            pop    edi;// pop     rdi
            ;// 
// set return value                             ;// 
            REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

            X64_End();

            mov    ax, ds
                mov    ss, ax
                mov    esp, back_esp

                ;// restore FS segment
            mov    ax, back_fs
                mov    fs, ax
        }
        return _rax.v;
    }
#pragma warning(pop)

 
    bool cmpMem64(const void* dstMem, DWORD64 srcMem, size_t sz)
    {
        if ((nullptr == dstMem) || (0 == srcMem) || (0 == sz))
            return false;

        bool result = false;
        reg64 _src = { srcMem };
        __asm
        {
            X64_Start();

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            push   edi;// push      rdi
            push   esi;// push      rsi
            ;//           
            mov    edi, dstMem;// mov       edi, dword ptr [dstMem]       ; high part of RDI is zeroed
            REX_W mov    esi, _src.dw[0];// mov       rsi, qword ptr [_src]
            mov    ecx, sz;// mov       ecx, dword ptr [sz]           ; high part of RCX is zeroed
            ;//           
            mov    eax, ecx;// mov       eax, ecx
            and eax, 3;// and       eax, 3
            shr    ecx, 2;// shr       ecx, 2
            ;// 
            repe   cmpsd;// repe cmps dword ptr [rsi], dword ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            ;// 
            test   eax, eax;// test      eax, eax
            je     _move_0;// je        _move_0
            cmp    eax, 1;// cmp       eax, 1
            je     _move_1;// je        _move_1
            ;// 
            cmpsw;// cmps      word ptr [rsi], word ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            cmp    eax, 2;// cmp       eax, 2
            je     _move_0;// je        _move_0
            ;// 
        _move_1:;// 
            cmpsb;// cmps      byte ptr [rsi], byte ptr [rdi]
            jnz     _ret_false;// jnz       _ret_false
            ;// 
        _move_0:;// 
            mov    result, 1;// mov       byte ptr [result], 1
            ;// 
        _ret_false:;// 
            pop    esi;// pop      rsi
            pop    edi;// pop      rdi

            X64_End();
        }

        return result;
    }

    DWORD64 getTEB64()
    {
        reg64 reg;
        reg.v = 0;

        X64_Start();
        // R12 register should always contain pointer to TEB64 in WoW64 processes
        X64_Push(_R12);
        // below pop will pop QWORD from stack, as we're in x64 mode now
        __asm pop reg.dw[0]
            X64_End();

        return reg.v;
    }

    DWORD64 __cdecl get_module_64(const wchar_t* lpModuleName)
    { 

        TEB64 teb64;
        getMem64(&teb64, getTEB64(), sizeof(TEB64));

        PEB64 peb64;
        getMem64(&peb64, teb64.ProcessEnvironmentBlock, sizeof(PEB64));
        PEB_LDR_DATA64 ldr;
        getMem64(&ldr, peb64.Ldr, sizeof(PEB_LDR_DATA64));

        DWORD64 LastEntry = peb64.Ldr + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList);
        LDR_DATA_TABLE_ENTRY64 head;
        head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;
        do
        {
            getMem64(&head, head.InLoadOrderLinks.Flink, sizeof(LDR_DATA_TABLE_ENTRY64));

            wchar_t* tempBuf = (wchar_t*)malloc(head.BaseDllName.MaximumLength);
            if (!tempBuf)
                return NULL; 
            getMem64(tempBuf, head.BaseDllName.Buffer, head.BaseDllName.MaximumLength);

            if (!_wcsicmp(lpModuleName, tempBuf))
            {
                free(tempBuf);
                return head.DllBase;
            }
            free(tempBuf);

        } while (head.InLoadOrderLinks.Flink != LastEntry);
         return NULL;
    }
     
    DWORD64 get_export(DWORD64 mod_addr, CONST CHAR* exp_name)
    {  
        DWORD64 res = NULL;
        IMAGE_DOS_HEADER idh;
        getMem64(&idh, mod_addr, sizeof(idh));

        IMAGE_NT_HEADERS64 inh;
        getMem64(&inh, mod_addr + idh.e_lfanew, sizeof(IMAGE_NT_HEADERS64));

        IMAGE_DATA_DIRECTORY& idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (!idd.VirtualAddress)
            return NULL;

        IMAGE_EXPORT_DIRECTORY ied;
        getMem64(&ied, mod_addr + idd.VirtualAddress, sizeof(ied));

        DWORD* rvaTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfFunctions);
        if (!rvaTable)
            return NULL;
         getMem64(rvaTable, mod_addr + ied.AddressOfFunctions, sizeof(DWORD) * ied.NumberOfFunctions);

        WORD* ordTable = (WORD*)malloc(sizeof(WORD) * ied.NumberOfFunctions);
        if (!ordTable)
        {
            free(rvaTable);
            return NULL;
        }
         getMem64(ordTable, mod_addr + ied.AddressOfNameOrdinals, sizeof(WORD) * ied.NumberOfFunctions);

        DWORD* nameTable = (DWORD*)malloc(sizeof(DWORD) * ied.NumberOfNames);
        if (!nameTable)
        {
            free(rvaTable);
            free(ordTable);
            return NULL;
        }
        getMem64(nameTable, mod_addr + ied.AddressOfNames, sizeof(DWORD) * ied.NumberOfNames);

        // lazy search, there is no need to use binsearch for just one function
        for (DWORD i = 0; i < ied.NumberOfFunctions; i++)
        {
            if (cmpMem64(exp_name, mod_addr + nameTable[i], strlen(exp_name)))
            {
                res = mod_addr + rvaTable[ordTable[i]];
                break;
                
             }
        }
        free(rvaTable);
        free(ordTable);
        free(nameTable);

        return res;
    }
}
#endif

#endif // !WOW_UTIL
