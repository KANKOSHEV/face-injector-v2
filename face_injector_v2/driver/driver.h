#pragma once
#include <Windows.h>
#include <string>
#pragma warning(disable : 4005)
#include <ntstatus.h>
#pragma warning(default : 4005)
#include "defines.h"

class c_driver
{
public:
	c_driver();
	~c_driver();

	DWORD process_id = 0;

	static   c_driver& singleton();
	void     handle_driver();
	void     attach_process(DWORD pid);

	NTSTATUS send_serivce(ULONG ioctl_code, LPVOID io, DWORD size);
	NTSTATUS get_module_information_ex(const wchar_t* name, pget_module_information mod);
	NTSTATUS read_memory_ex(PVOID base, PVOID buffer, DWORD size);
	NTSTATUS write_memory_ex(PVOID base, PVOID buffer, DWORD size);
	NTSTATUS protect_memory_ex(uint64_t base, uint64_t size, PDWORD protection);
	PVOID    alloc_memory_ex(DWORD size, DWORD protect);
	NTSTATUS free_memory_ex(PVOID address);
	
	inline bool is_loaded()  const { return h_driver != INVALID_HANDLE_VALUE; }
private:	
	c_driver(const c_driver&) = delete;
	c_driver& operator = (const c_driver&) = delete;
	HANDLE   h_driver = INVALID_HANDLE_VALUE;
};

inline c_driver& driver()
{
	return c_driver::singleton();
}



