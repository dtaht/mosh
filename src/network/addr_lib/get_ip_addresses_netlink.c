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
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/route.h>
#include <arpa/inet.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "get_ip_addresses.h"

#include "util.h"

static array_t addresses;

static int get_netlink_socket(uint32_t groups, int generic);
static int parse_address(struct nlmsghdr *msg);
static int netlink_read_all(int sock);
static int netlink_read_ack(int sock);


static unsigned short nl_seqno = 0;
int nl_socket = -1;
#define NL_SOCKLENGTH (sizeof(struct sockaddr_nl))
static int pending_ack = -1; /* == nl_seqno sent if pending, -error on error, -1
                                otherwise */

static inline unsigned int
rtnlgrp_to_mask(unsigned int grp)
{
    return grp ? 1 << (grp - 1) : 0;
}

int
kernel_setup(int setup)
{
    int rc;

    if(setup) {
        /* Route netlink socket */
        rc = get_netlink_socket(rtnlgrp_to_mask(RTNLGRP_IPV4_IFADDR)
                              | rtnlgrp_to_mask(RTNLGRP_IPV6_IFADDR), 0);
        if(rc < 0) {
            log_msg(LOG_PERROR, "Get route netlink socket");
            goto fail_setup;
        }
        nl_socket = rc;

        return 1;
    fail_setup:
        close(nl_socket);
        nl_socket = -1;
        return -1;
    } else {
        close(nl_socket);
        nl_socket = -1;

        return 1;
    }
}

static int
get_netlink_socket(uint32_t groups, int generic)
{
    int rc;
    int sock;
    socklen_t nl_socklen = 0;
    struct sockaddr_nl nl_sockaddr;

    if (generic)
        sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    else
        sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(sock < 0)
        return -1;

    memset(&nl_sockaddr, 0, sizeof(nl_sockaddr));
    nl_sockaddr.nl_family = AF_NETLINK;
    nl_sockaddr.nl_groups = groups;
    nl_socklen = NL_SOCKLENGTH;

    if (!generic)
        nl_seqno = time(NULL) % 0xFF00;

    rc = set_nonblock(sock);
    if (rc < 0)
        return -1;

    rc = bind(sock, (struct sockaddr *)&nl_sockaddr, nl_socklen);
    if(rc < 0)
        return -1;

    rc = getsockname(sock,
                     (struct sockaddr *)&nl_sockaddr, &nl_socklen);
    if(rc < 0)
        return -1;

    if (nl_socklen != NL_SOCKLENGTH) {
        log_msg(LOG_ERROR, "Invalid netlink socket length\n");
        return -1;
    }

    return sock;
}

/* Return -1 on error, 0 on success */
static int
netlink_read_all(int sock)
{
    struct iovec iov;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct nlmsghdr *nh;
    int len;
    char buf[8192];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = &buf;

    while(1) {
        iov.iov_len = sizeof(buf);
        len = recvmsg(sock, &msg, 0);
        if(len < 0 && (errno == EAGAIN || errno == EINTR)) {
            errno = EAGAIN;
            return 0;
        }

        if(len < 0) {
            log_msg(LOG_PERROR, "netlink_read - recvmsg()");
            return -1;
        } else if(len == 0) {
            log_msg(LOG_ERROR, "netlink_read - EOF\n");
            goto socket_error;
        } else if(msg.msg_namelen != NL_SOCKLENGTH) {
            log_msg(LOG_ERROR,
                    "netlink_read - unexpected sender address length (%d)\n",
                    msg.msg_namelen);
            goto socket_error;
        } else if(nladdr.nl_pid != 0) {
            log_dbg(LOG_DEBUG_KERNEL,
                    "netlink_read - message not sent by kernel.\n");
            goto next_message;
        }

        if (sock == nl_socket) {
            log_dbg(LOG_DEBUG_KERNEL,
                    "Message received on the route NL socket.\n");
            for (nh = (struct nlmsghdr *)buf;
                 NLMSG_OK(nh, len);
                 nh = NLMSG_NEXT(nh, len)) {
                
                switch (nh->nlmsg_type) {
                case NLMSG_DONE: continue;

                case NLMSG_ERROR: {
                    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
                    if (UNLIKELY(nh->nlmsg_seq != pending_ack)) {
                        log_dbg(LOG_DEBUG_KERNEL,
                                "netlink_read: answer with wrong seqno.\n");
                        continue;
                    } else if(err->error != 0) {
                        log_dbg(LOG_DEBUG_KERNEL, "netlink_read: %s\n",
                                strerror(-err->error));
                        pending_ack = -err->error;
                    } else {
                        log_dbg(LOG_DEBUG_KERNEL,
                                "netlink_read: request successfully ack.\n");
                        pending_ack = -1;
                    }

                    break;
                }
                case RTM_NEWADDR:
                case RTM_DELADDR:
                    parse_address(nh);
                    break;
                default:
                    break;
                }
            }
        } else {
            assert(0);
            /* we didn't have generic socket */
        }

    next_message:
        if(msg.msg_flags & MSG_TRUNC)
            fprintf(stderr, "netlink_read - message truncated\n");
    }

    return 0;

 socket_error:
    close(nl_socket);
    nl_socket = -1;
    errno = EIO;
    return -1;
}

static int
netlink_read_ack(int sock)
{
    int rc, again = 0;
    assert(pending_ack >= 0);
 again:
    rc = netlink_read_all(sock);
    if(!again && rc >= 0 && pending_ack >= 0) {
        rc = wait_for_fd(1, nl_socket, 100);
        if(rc <= 0) {
            if(rc == 0)
                errno = EAGAIN;
        } else {
            again = 1;
            goto again;
        }
    }
    return pending_ack < 0 ? 0 : -1;
}

static int
netlink_send(struct nlmsghdr *nh, int sock)
{
    int rc;
    struct sockaddr_nl nladdr;
    struct msghdr msg;
    struct iovec iov;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = 0;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &nladdr;
    msg.msg_namelen = sizeof(nladdr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    iov.iov_base = nh;
    iov.iov_len = nh->nlmsg_len;

    nh->nlmsg_flags |= NLM_F_ACK;
    nh->nlmsg_seq = ++nl_seqno;
    pending_ack = nl_seqno;

    rc = sendmsg(sock, &msg, 0);
    if(rc < 0 && (errno == EAGAIN || errno == EINTR)) {
        rc = wait_for_fd(1, sock, 100);
        if(rc <= 0) {
            if(rc == 0)
                errno = EAGAIN;
        } else {
            rc = sendmsg(sock, &msg, 0);
        }
    }

    if(rc < nh->nlmsg_len) {
        log_msg(LOG_PERROR, "sendmsg");
        return -1;
    }

    return rc;
}

static int
netlink_send_dump_request(int type, unsigned char family)
{
    char buffer[sizeof(struct nlmsghdr) + sizeof(struct rtgenmsg) + 16];
    struct nlmsghdr *message_header = (void*)buffer;
    struct rtgenmsg *message = NULL;

    memset(buffer, 0, sizeof(buffer));

    /* Set the header */
    message_header->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    message_header->nlmsg_type  = type;
    message_header->nlmsg_len   = NLMSG_LENGTH(0);

    /* Append the message */
    message = NLMSG_DATA(message_header);
    message->rtgen_family = family;
    message_header->nlmsg_len += NLMSG_ALIGN(sizeof(struct rtgenmsg));

    assert(message_header->nlmsg_len <= sizeof(buffer));
    return netlink_send(message_header, nl_socket);
}

static int
parse_address(struct nlmsghdr *nh)
{
    int len;
    struct kernel_address kaddr;
    struct ifaddrmsg *ifa = NULL;
    struct rtattr *rta = NULL;
    unsigned int rta_len;
    int is_v4 = 0;

    len = nh->nlmsg_len;

    ifa = (struct ifaddrmsg*)NLMSG_DATA(nh);
    len -= NLMSG_LENGTH(0);

    memset(&kaddr, 0, sizeof(kaddr));
    kaddr.sa.sa_family = ifa->ifa_family;

    if (kaddr.sa.sa_family != AF_INET && kaddr.sa.sa_family != AF_INET6) {
        log_dbg(LOG_DEBUG_KERNEL, "Unknown family: %d\n", kaddr.sa.sa_family);
        return -1;
    }
    is_v4 = kaddr.sa.sa_family == AF_INET;

    rta = IFA_RTA(ifa);
    len -= NLMSG_ALIGN(sizeof(*ifa));

#define COPY_ADDR(d, s)                                                 \
    do {                                                                \
        if(!is_v4) {                                                    \
            assert(rta_len >= 16);                                      \
            memcpy(&d.sin6.sin6_addr, s, 16);                           \
        }else {                                                         \
            assert(rta_len >= 4);                                       \
            memcpy(&d.sin.sin_addr, s, 4);                              \
        }                                                               \
    } while(0)

    for(; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        rta_len = RTA_PAYLOAD(rta);
        switch (rta->rta_type) {
        case IFA_UNSPEC: break;
        case IFA_ADDRESS:
            COPY_ADDR(kaddr, RTA_DATA(rta));
            break;

        case IFA_LOCAL:
            COPY_ADDR(kaddr, RTA_DATA(rta));
            kaddr.flags |= ADDR_LOCAL;
            break;
        default:
            break;
        }
    }
#undef COPY_ADDR
#undef GET_PLEN

    if (nh->nlmsg_type == RTM_NEWADDR)
        addr_add(&addresses, &kaddr);
    else
        addr_del(addresses, &kaddr);

    return 0;
}

int
update_kernel_addresses(int dump)
{
    int rc;

    if(nl_socket < 0) {
        log_msg(LOG_ERROR, "Netlink not initialized.\n");
        errno = EIO;
        return -1;
    }

    if(dump) {
        int i;
        int families[2] = { AF_INET6, AF_INET };
        free_array(&addresses, free);
        for(i = 0; i < 2; i++) {
            /* ask for routes */
            rc = netlink_send_dump_request(RTM_GETADDR, families[i]);
            if(rc < 0)
                return -1;
            rc = netlink_read_ack(nl_socket);
        }
    } else {
        rc = netlink_read_all(nl_socket);
    }

    return 0;
}

array_t
get_kernel_addresses(void)
{
    array_t addr;
    if (nl_socket < 0)
        kernel_setup(1);
    update_kernel_addresses(1);
    addr = addresses;
    addresses = NULL;
    return addr;
}
