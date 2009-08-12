#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

typedef struct gg_buffer gg_buffer_t;

struct gg_buffer {
	char *start;
	size_t length;
	const char *end;
	char *ptr;
	int overflow;
};

void gg_buffer_init(gg_buffer_t *buf, char *start, size_t length)
{
	if (buf == NULL || start == NULL) {
		errno = EINVAL;
		return;
	}

	buf->start = start;
	buf->length = length;
	buf->end = buf->start + buf->length;

	buf->ptr = buf->start;
	buf->overflow = 0;
}

int gg_buffer_reset(gg_buffer_t *buf)
{
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	buf->ptr = buf->start;
	buf->overflow = 0;

	return 0;
}

int gg_buffer_get_remaining(gg_buffer_t *buf)
{
	if (buf == NULL || buf->ptr > buf->end || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	return buf->end - buf->ptr;
}

int gg_buffer_get_offset(gg_buffer_t *buf)
{
	if (buf == NULL || buf->ptr < buf->start || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	return buf->ptr - buf->start;
}

int gg_buffer_get_overflow(gg_buffer_t *buf)
{
	if (buf == NULL) {
		errno = EINVAL;
		return -1;
	}

	return buf->overflow;
}

int gg_buffer_pack_uint8(gg_buffer_t *buf, uint8_t value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint8_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	*(buf->ptr++) = value;

	return 0;
}

int gg_buffer_pack_uint16(gg_buffer_t *buf, uint16_t value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint16_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	*(buf->ptr++) = value & 255;
	*(buf->ptr++) = (value >> 8) & 255;

	return 0;
}

int gg_buffer_pack_uint32(gg_buffer_t *buf, uint32_t value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint32_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	*(buf->ptr++) = value & 255;
	*(buf->ptr++) = (value >> 8) & 255;
	*(buf->ptr++) = (value >> 16) & 255;
	*(buf->ptr++) = (value >> 24) & 255;

	return 0;
}

int gg_buffer_pack_array(gg_buffer_t *buf, uint8_t *array, size_t len)
{
	if (buf == NULL || buf->overflow == 1) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + len >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	memcpy(buf->ptr, array, len);
	buf->ptr += len;

	return 0;
}

int gg_buffer_pack_string(gg_buffer_t *buf, char *str, int null)
{
	size_t len;

	if (buf == NULL || str == NULL) {
		errno = EINVAL;
		return -1;
	}

	len = strlen(str);

	if (null)
		len++;

	if (buf->ptr + len >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	memcpy(buf->ptr, str, len);
	buf->ptr += len;

	return 0;
}

int gg_buffer_unpack_uint8(gg_buffer_t *buf, uint8_t *value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint8_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	if (value != NULL)
		*value = *(buf->ptr++);
	else
		buf->ptr += sizeof(uint8_t);

	return 0;
}

int gg_buffer_unpack_uint16(gg_buffer_t *buf, uint16_t *value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint16_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	if (value != NULL) {
		*value = *(buf->ptr++);
		*value |= ((uint16_t) *(buf->ptr++)) << 8;
	} else {
		buf->ptr += sizeof(uint16_t);
	}

	return 0;
}

int gg_buffer_unpack_uint32(gg_buffer_t *buf, uint32_t *value)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + sizeof(uint32_t) >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	if (value != NULL) {
		*value = *(buf->ptr++);
		*value |= ((uint32_t) *(buf->ptr++)) << 8;
		*value |= ((uint32_t) *(buf->ptr++)) << 16;
		*value |= ((uint32_t) *(buf->ptr++)) << 24;
	} else {
		buf->ptr += sizeof(uint32_t);
	}

	return 0;
}

int gg_buffer_unpack_array(gg_buffer_t *buf, uint8_t *array, size_t len)
{
	if (buf == NULL || buf->overflow) {
		errno = EINVAL;
		return -1;
	}

	if (buf->ptr + len >= buf->end) {
		buf->overflow = 1;
		errno = EINVAL;
		return -1;
	}

	if (array != NULL)
		memcpy(array, buf->ptr, len);

	buf->ptr += len;

	return 0;
}

int gg_buffer_unpack_string(gg_buffer_t *buf, char **str, size_t len)
{
	// XXX 
	
	return -1;
}

// XXX zrobić z tego funkcję inline? sprawdzić, czy na x86 gcc zoptymalizuje
// do zwykłego odczytu. jeśli nie, ifdefować.
//
uint32_t gg_buffer_get_uint32(const char *ptr)
{
	return ((uint8_t) ptr[0]) |
		(((uint8_t) ptr[1]) << 8) |
		(((uint8_t) ptr[2]) << 16) |
		(((uint8_t) ptr[3]) << 24);
}

