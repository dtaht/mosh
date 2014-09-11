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

#include <stdio.h>
#include <string.h>
#include "get_ip_addresses.h"

int
addr_cmp(const struct kernel_address *a1, const struct kernel_address *a2)
{
    int i;
    i = memcmp(a1, a2, sizeof(struct kernel_address));
    if (i) return i;
    return 0;
}

void
addr_add(array_t *addresses, struct kernel_address *addr)
{
    struct kernel_address *copy = NULL;
    int rc;

    copy = memdup(addr, sizeof(struct kernel_address));
    if (!copy) goto fail;

    rc = array_add(addresses, copy, (cmp_fun_t)addr_cmp);
    if (rc < 0) goto fail2;
    return;

 fail2:
    free(copy);
 fail:
    log_msg(LOG_PERROR, "Fail to add address");
    return;
}

void
addr_del(array_t addresses, struct kernel_address *addr)
{
    struct kernel_address *copy = NULL;

    copy = array_del(addresses, addr, (cmp_fun_t)addr_cmp);
    if (!copy)
        log_msg(LOG_PERROR, "Fail to remove address");
    else
        free(copy);
}

int print_address(char *dst, const struct kernel_address *kaddr)
{
    int family = kaddr->sa.sa_family;
    const char *tmp;
    void *addr;
    if (family == AF_INET) {
        addr = (void*) &kaddr->sin.sin_addr;
    } else if (family == AF_INET6) {
        addr = (void*) &kaddr->sin6.sin6_addr;
    } else {
        printf("unknown address family: %d\n", family);
        return -1;
    }
    tmp = inet_ntop(family, addr, dst, INET6_ADDRSTRLEN);
    return tmp ? 0 : -1;
}

#ifdef __linux
#include "get_ip_addresses_netlink.c"
#else
#include "get_ip_addresses_bsd.c"
#endif
