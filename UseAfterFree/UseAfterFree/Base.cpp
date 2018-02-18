#include "Base.h"

BaseIoctl::BaseIoctl() : newIoctl(new BaseIoctlImpl()) { }
BaseIoctl::~BaseIoctl() { }
HANDLE BaseIoctl::OpenDevice()
{
	HANDLE dv = newIoctl->OpenDevice();
	if (dv == INVALID_HANDLE_VALUE)
	{
		std::cout << "OpenDevice() Failed.." << std::endl;
		std::exit(0);
	}
	return dv;
}
void BaseIoctl::CloseDevice() const
{
	newIoctl->CloseDevice();
}
BOOL BaseIoctl::sendData(const char* payload, std::size_t size, DWORD code)
{
	return newIoctl->sendData(payload, size, code);
}