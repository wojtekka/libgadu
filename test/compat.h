/*
 *  (C) Copyright 2001-2006 Wojtek Kaniewski <wojtekka@irc.pl>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License Version
 *  2.1 as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307,
 *  USA.
 */

#ifdef _WIN32

#define install_win32_hook(orig_func, hook_func) \
	install_win32_hook_f((void (*)())(orig_func), (void (*)())(hook_func))

static inline void
install_win32_hook_f(void (*orig_func)(), void (*hook_func)())
{
	DWORD dPermission = 0;
	uint8_t trap[] = {
#ifdef _WIN64
		0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, /* mov rax, uint64_t */
		0xff, 0xe0 /* jmp rax */
#else
		0xB8, 0, 0, 0, 0, /* mov eax, uint32_t */
		0xff, 0xe0 /* jmp eax */
#endif
	};

#ifdef _WIN64
	uint64_t addr = (uint64_t)hook_func;
	memcpy(&trap[2], &addr, sizeof(addr));
#else
	uint32_t addr = (uint32_t)hook_func;
	memcpy(&trap[1], &addr, sizeof(addr));
#endif

	VirtualProtect(orig_func, sizeof(trap),
		PAGE_EXECUTE_READWRITE, &dPermission);
	memcpy(orig_func, trap, sizeof(trap));
	VirtualProtect(orig_func, sizeof(trap),
		dPermission, &dPermission);
}

#endif
