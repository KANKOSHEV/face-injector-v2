#include "driver.h"
#include "../api/xor.h"

#define DVR_DEVICE_FILE xor_w(L"\\\\.\\EIQDV") 

c_driver::c_driver()
{
/**/
}
NTSTATUS c_driver::send_serivce(ULONG ioctl_code, LPVOID io, DWORD size)
{
	if (h_driver == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;

	if (!DeviceIoControl(h_driver, ioctl_code, io, size, nullptr, 0, NULL, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
void c_driver::attach_process(DWORD pid)
{
	process_id = pid;
}
NTSTATUS c_driver::get_module_information_ex(const wchar_t* name, pget_module_information mod)
{
	if (h_driver == INVALID_HANDLE_VALUE)
		return STATUS_DEVICE_DOES_NOT_EXIST;
	
	set_module_information req = { 0 };

	req.pid = process_id;
	wcscpy_s(req.sz_name, name);

	if (!DeviceIoControl(h_driver, ioctl_get_module_information, &req, sizeof(req), mod, sizeof(get_module_information), 0, NULL))
		return STATUS_UNSUCCESSFUL;

	return STATUS_SUCCESS;
}
NTSTATUS c_driver::read_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	copy_memory req = { 0 };

	req.pid = process_id;
	req.address = reinterpret_cast<ULONGLONG>(base);
	req.buffer = reinterpret_cast<ULONGLONG>(buffer);
	req.size = (uint64_t)size;
	req.write = FALSE;

	return send_serivce(ioctl_copy_memory, &req, sizeof(req));
}
NTSTATUS c_driver::write_memory_ex(PVOID base, PVOID buffer, DWORD size)
{
	copy_memory req = { 0 };

	req.pid = process_id;
	req.address = reinterpret_cast<ULONGLONG>(base);
	req.buffer = reinterpret_cast<ULONGLONG>(buffer);
	req.size = (uint64_t)size;
	req.write = TRUE;

	return send_serivce(ioctl_copy_memory, &req, sizeof(req));
}
NTSTATUS c_driver::protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection)
{
	protect_memory req = { 0 };

	req.pid = process_id;
	req.address = base;
	req.size = size;
	req.new_protect = protection;

	return send_serivce(ioctl_protect_memory, &req, sizeof(req));
}
PVOID c_driver::alloc_memory_ex(DWORD size, DWORD protect)
{
	PVOID p_out_address = NULL;
	alloc_memory req = { 0 };

	req.pid = process_id;
	req.out_address = reinterpret_cast<ULONGLONG>(&p_out_address);
	req.size = size;
	req.protect = protect;

	send_serivce(ioctl_alloc_memory, &req, sizeof(req));

	return p_out_address;
}
NTSTATUS c_driver::free_memory_ex(PVOID address)
{
	free_memory req = { 0 };

	req.pid = process_id;
	req.address = reinterpret_cast<ULONGLONG>(address);

	return send_serivce(ioctl_free_memory, &req, sizeof(req));
}
void c_driver::handle_driver()
{
	h_driver = CreateFileW(DVR_DEVICE_FILE, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
}
c_driver::~c_driver()
{
	CloseHandle(h_driver);
}
c_driver& c_driver::singleton()
{
	static c_driver p_object;
	return p_object;
}