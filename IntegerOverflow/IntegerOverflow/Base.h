#pragma once
#include "BaseImpl.h"

class BaseIoctlImpl;
class BaseIoctl
{
public:
	BaseIoctl();
	~BaseIoctl();
	HANDLE OpenDevice();
	void CloseDevice() const;
	BOOL sendData(const char* payload, std::size_t size, DWORD code);
private:
	std::tr1::shared_ptr<BaseIoctlImpl> newIoctl;
};