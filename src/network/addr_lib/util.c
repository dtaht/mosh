/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright (c) 2013 by Matthieu Boutier

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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "util.h"

int log_level = LOG_MAX | LOG_DEBUG_ALL;
int log_indent_level;
FILE *log_output = NULL;

void
log_msg(int level, const char *format, ...)
{
    int i;
    va_list args;
    if (UNLIKELY(log_output == NULL)) {
        log_output = stderr;
    }
    if (LOG_GET_LEVEL(log_level) < LOG_GET_LEVEL(level))
        return;
    va_start(args, format);
    for (i = 0; i < log_indent_level; i ++)
        fprintf(log_output, "  ");
    vfprintf(log_output, format, args);
    if (level & (LOG_PERROR & ~LOG_ERROR))
        fprintf(log_output, ": %s.\n", strerror(errno));
    fflush(log_output);
    va_end(args);
}

static const unsigned char zeroes[16] = {0};

static const unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

static const unsigned char llprefix[16] =
    {0xFE, 0x80};

const char *
format_address(const unsigned char *address)
{
    static char buf[4][INET6_ADDRSTRLEN];
    static int i = 0;
    i = (i + 1) % 4;
    if(v4mapped(address))
       inet_ntop(AF_INET, address + 12, buf[i], INET6_ADDRSTRLEN);
    else
       inet_ntop(AF_INET6, address, buf[i], INET6_ADDRSTRLEN);
    return buf[i];
}

const char *printhex(const unsigned char *mem, int len)
{
    static char *ptr = NULL;
    static int ptr_len = 0;
    int i;
    if(ptr_len < 2*len + 1) {
        char *tmp = ptr;
        tmp = realloc(ptr, 2*len + 1);
        if (tmp != NULL) {
            ptr = tmp;
            ptr_len = 2*len + 1;
        } /* continue when failure */
    }
    if(ptr_len < 2*len + 1) len = ptr_len / 2;
    for (i=0; i < len; i ++)
        snprintf(ptr + (2 * i), 3, "%02x", (unsigned int) mem[i]);
    return ptr;
}

const char *
format_prefix(const unsigned char *prefix, unsigned char plen)
{
    static char buf[4][INET6_ADDRSTRLEN + 4];
    static int i = 0;
    int n;
    i = (i + 1) % 4;
    if(plen >= 96 && v4mapped(prefix)) {
        inet_ntop(AF_INET, prefix + 12, buf[i], INET6_ADDRSTRLEN);
        n = strlen(buf[i]);
        snprintf(buf[i] + n, INET6_ADDRSTRLEN + 4 - n, "/%d", plen - 96);
    } else {
        inet_ntop(AF_INET6, prefix, buf[i], INET6_ADDRSTRLEN);
        n = strlen(buf[i]);
        snprintf(buf[i] + n, INET6_ADDRSTRLEN + 4 - n, "/%d", plen);
    }
    return buf[i];
}

int
wait_for_fd(int direction, int fd, int msecs)
{
    fd_set fds;
    int rc;
    struct timeval tv;

    tv.tv_sec = msecs / 1000;
    tv.tv_usec = (msecs % 1000) * 1000;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    if(direction)
        rc = select(fd + 1, NULL, &fds, NULL, &tv);
    else
        rc = select(fd + 1, &fds, NULL, NULL, &tv);

    return rc;
}

int
martian_prefix(const unsigned char *prefix, int plen)
{
    return
        (plen >= 8 && prefix[0] == 0xFF) ||
        (plen >= 10 && prefix[0] == 0xFE && (prefix[1] & 0xC0) == 0x80) ||
        (plen >= 128 && memcmp(prefix, zeroes, 15) == 0 &&
         (prefix[15] == 0 || prefix[15] == 1)) ||
        (plen >= 96 && v4mapped(prefix) &&
         ((plen >= 104 && (prefix[12] == 127 || prefix[12] == 0)) ||
          (plen >= 100 && (prefix[12] & 0xE0) == 0xE0)));
}

int
linklocal(const unsigned char *address)
{
    return memcmp(address, llprefix, 8) == 0;
}

int
v4mapped(const unsigned char *address)
{
    return memcmp(address, v4prefix, 12) == 0;
}

void
v4tov6(unsigned char *dst, const unsigned char *src)
{
    memcpy(dst, v4prefix, 12);
    memcpy(dst + 12, src, 4);
}

void *
memdup(const void *src, int size)
{
    void* tmp = malloc(size);
    if (!tmp) return NULL;
    memcpy(tmp, src, size);
    return tmp;
}

int
daemonise()
{
    int rc;

    fflush(stdout);
    fflush(stderr);

    rc = fork();
    if(rc < 0)
        return -1;

    if(rc > 0)
        exit(0);

    rc = setsid();
    if(rc < 0)
        return -1;

    return 1;
}

int
set_nonblock(int fd)
{
    int rc;
    rc = fcntl(fd, F_GETFL, 0);
    if(rc < 0)
        return -1;

    rc = fcntl(fd, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        return -1;
    return 0;
}
