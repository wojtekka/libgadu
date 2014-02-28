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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "libgadu.h"
#include "internal.h"

static void test_gg_fix64(void)
{
	const char *source = "\xff\xee\xdd\xcc\xbb\xaa\x99\x88";
	uint64_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix64(value) != 0x8899aabbccddeeffLL) {
		fprintf(stderr, "gg_fix64 failed\n");
		exit(1);
	}
}

static void test_gg_fix32(void)
{
	const char *source = "\xee\xdd\xcc\xbb";
	uint32_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix32(value) != 0xbbccddee) {
		fprintf(stderr, "gg_fix32 failed\n");
		exit(1);
	}
}

static void test_gg_fix16(void)
{
	const char *source = "\xdd\xcc";
	uint16_t value;

	memcpy(&value, source, sizeof(value));

	if (gg_fix16(value) != 0xccdd) {
		fprintf(stderr, "gg_fix16 failed\n");
		exit(1);
	}
}

int main(void)
{
	test_gg_fix64();
	test_gg_fix32();
	test_gg_fix16();

	return 0;
}
