/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef UTIL_H
#define UTIL_H

#include <sys/time.h>
#include <string.h>
#include <stdio.h>

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define ATTRIBUTE(x) __attribute__ (x)
#define LIKELY(_x) __builtin_expect(!!(_x), 1)
#define UNLIKELY(_x) __builtin_expect(!!(_x), 0)
#else
#define ATTRIBUTE(x) /**/
#define LIKELY(_x) !!(_x)
#define UNLIKELY(_x) !!(_x)
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ >= 3)
#define COLD __attribute__ ((cold))
#else
#define COLD /**/
#endif              

extern int log_level;
extern int log_indent_level;
extern FILE *log_output;

void log_msg(int level, const char *format, ...)
    ATTRIBUTE ((format (printf, 2, 3))) COLD;
const char *printhex(const unsigned char *mem, int len);
const char *format_address(const unsigned char *address);
const char *format_prefix(const unsigned char *address, unsigned char prefix);
int wait_for_fd(int direction, int fd, int msecs);
int martian_prefix(const unsigned char *prefix, int plen) ATTRIBUTE ((pure));
int linklocal(const unsigned char *address) ATTRIBUTE ((pure));
int v4mapped(const unsigned char *address) ATTRIBUTE ((pure));
void v4tov6(unsigned char *dst, const unsigned char *src);
void *memdup(const void *src, int size);
int daemonise(void);
int set_nonblock(int fd);

#define MAX(x,y) ((x) > (y) ? (x) : (y))
#define MIN(x,y) ((x) < (y) ? (x) : (y))

static inline int int_cmp(int i, int j)
{
    return i - j;
}

static inline int
prefix_cmp(const unsigned char *paddr1, int plen1,
           const unsigned char *paddr2, int plen2)
{
    int i = memcmp(paddr1, paddr2, 16);
    return i ? i : int_cmp(plen1, plen2);
}

/* If debugging is disabled, we want to avoid calling format_address
   for every omitted debugging message.  So debug is a macro.  But
   vararg macros are not portable. */
#if defined NO_DEBUG

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define debugf(...) do {} while(0)
#elif defined __GNUC__
#define debugf(_args...) do {} while(0)
#else
#define debugf if(0) log_msg
#endif

#define DEBUG(level, statement)

#else /* !NO_DEBUG */

/* log levels */

#define LOG_ERROR               2
#define LOG_DEBUG               4
#define LOG_MAX                 7
#define LOG_GET_LEVEL(x)        (x & 0xF)

/* log flags type */

#define LOG_PERROR              ((1 << 7) | LOG_ERROR)
#define LOG_DEBUG_COMMON        ((1 << 8) | LOG_DEBUG)
#define LOG_DEBUG_KERNEL        ((1 << 9) | LOG_DEBUG)
#define LOG_DEBUG_ALL           ((0xFF00) | LOG_DEBUG)

#define DEBUG(level, statement)                         \
    if(UNLIKELY(level & log_level)) {statement;}

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define log_dbg(level, ...)                                            \
    do {                                                               \
        if(UNLIKELY((level) & log_level)) log_msg(level, __VA_ARGS__); \
    } while(0)
#elif defined __GNUC__
#define log_dbg(level, _args...)                                        \
    do {                                                                \
        if(UNLIKELY((level) & log_level)) log_msg(level, _args);        \
    } while(0)
#else
#warning No debug available.
static inline void debugf(int level, const char *format, ...) { return; }
#endif

#endif /* NO_DEBUG */

#endif /* UTIL_H */
