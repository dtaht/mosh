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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <assert.h>
#include <malloc/malloc.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <err.h>

#include "get_ip_addresses.h"

array_t get_kernel_addresses()
{
    array_t addresses = NULL;
    int ioctl_sock;
    struct ifconf ifconf;
    char buffer[2048];
    struct ifreq *req;
    struct ifreq *end;
    struct kernel_address kaddr;

    ioctl_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ioctl_sock < 0) {
        perror("socket");
        return NULL;
    }

    memset(&ifconf, 0, sizeof(ifconf));
    ifconf.ifc_buf = buffer;
    ifconf.ifc_len = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));

    if (ioctl(ioctl_sock, SIOCGIFCONF, &ifconf) == -1) {
        perror("ioctl");
        return NULL;
    }

    end = (struct ifreq*)(buffer + ifconf.ifc_len);
    if ((struct ifreq*) (buffer + 2048) < end + 1)
        fprintf(stderr, "Warning: some addresses may be missing (buf size).\n");

    req = ifconf.ifc_ifcu.ifcu_req;
    while ((char*)req + IFNAMSIZ + sizeof(req->ifr_addr.sa_len) < (char*)end &&
           (char*)req + IFNAMSIZ + req->ifr_addr.sa_len <= (char*)end) {
        if (req->ifr_addr.sa_family == AF_INET ||
            req->ifr_addr.sa_family == AF_INET6) {
            memcpy(&kaddr, &req->ifr_addr, req->ifr_addr.sa_len);
            addr_add(&addresses, &kaddr);
        }
        req = (struct ifreq*)((char*)req + IFNAMSIZ + req->ifr_addr.sa_len);
    }

    close(ioctl_sock);

    return addresses;
}


int
main(int argc, char **argv, char **env)
{
    array_t addresses;
    array_iter_t iter;
    struct kernel_address *kaddr = NULL;
    addresses = get_kernel_addresses();

    init_iterator(&iter);
    while (NULL != (kaddr = get_next(addresses, &iter)))
        print_address(kaddr);

    return 0;
}
