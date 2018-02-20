#include "BaseImpl.h"

BaseIoctlImpl::BaseIoctlImpl() : device(deviceName) { }
BaseIoctlImpl::~BaseIoctlImpl()
{
	std::cout << "[INFO] Close Ioctl.." << std::endl;
}

HANDLE BaseIoctlImpl::OpenDevice()
{
	HANDLE hdevice = CreateFileA(device.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		NULL, NULL,
		OPEN_EXISTING,
		NULL, NULL);
	openDevice = hdevice;

	return openDevice;
}

void BaseIoctlImpl::CloseDevice() const
{
	CloseHandle(openDevice);
}

BOOL BaseIoctlImpl::sendData(const char* payload, std::size_t size, DWORD code)
{
	BYTE* inBuffer = (BYTE*)HeapAlloc(
		GetProcessHeap(), HEAP_ZERO_MEMORY, size);
	memcpy(inBuffer, payload, size);
	DWORD ret = 0;
	BOOL _ret = DeviceIoControl(openDevice,
		code,
		inBuffer,
		size,
		NULL,
		0,
		&ret,
		NULL
	);
	HeapFree(GetProcessHeap(), 0, (LPVOID)inBuffer);
	return _ret;
}