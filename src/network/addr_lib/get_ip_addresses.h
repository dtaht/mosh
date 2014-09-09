/*
Copyright 2014 by Matthieu Boutier

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

#ifndef GET_IP_ADDRESSES_H
#define GET_IP_ADDRESSES_H

#include <sys/socket.h>
#include <arpa/inet.h>
#include "array.h"
#include "util.h"

struct kernel_address {
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_in6 sin6;
        struct sockaddr_storage ss;
    };
    int flags;
#define ADDR_LOCAL (1 <<  0)
};

int addr_cmp(const struct kernel_address *a1, const struct kernel_address *a2);
void addr_add(array_t *addresses, struct kernel_address *addr);
void addr_del(array_t addresses, struct kernel_address *addr);
void print_address(const struct kernel_address *kaddr);
array_t get_kernel_addresses(void);
#endif /* GET_IP_ADDRESSES_H */

