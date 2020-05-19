#ifndef __CSTRING_H__
#define __CSTRING_H__

#include <types.h>

size_t strlen(const char *s);
char *strncpy(char *dst, const char *src, size_t num);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t len);
char *strstr(const char *haystack, const char *needle);
int memcmp(const void *p1, const void *p2, size_t len);
void memset(void *dst, int ch, size_t len);
void memcpy(void *dst, const void *src, size_t len);
void memmove(void *dst, const void *src, size_t len);

#endif
