#ifndef NT_API_DEF
#define NT_API_DEF 1
#include "Struct.h"

NTSTATUS
NTAPI
NtContinue
(

	IN PCONTEXT             ThreadContext,
	IN BOOLEAN              RaiseAlert
);


NTSTATUS
NTAPI
NtGetContextThread
(
	HANDLE ThreadHandle,
	PCONTEXT Context
);

NTSTATUS
NTAPI
NtSetContextThread
(
	HANDLE ThreadHandle,
	PCONTEXT Context
);

NTSTATUS
NTAPI
NtQuerySystemInformation
(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID               SystemInformation,
	ULONG                SystemInformationLength,
	PULONG              ReturnLength OPTIONAL
);

#endif // !NT_API_DEF
