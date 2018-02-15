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
	DWORD ret = 0;
	BOOL _ret = DeviceIoControl(openDevice,
		code,
		(LPVOID)payload,
		size,
		NULL,
		0,
		&ret,
		NULL
	);
	return _ret;
}