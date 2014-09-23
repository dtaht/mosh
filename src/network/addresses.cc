/*
    Mosh: the mobile shell
    Copyright 2012 Keith Winstein

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    In addition, as a special exception, the copyright holders give
    permission to link the code of portions of this program with the
    OpenSSL library under certain conditions as described in each
    individual source file, and distribute linked combinations including
    the two.

    You must obey the GNU General Public License in all respects for all
    of the code used other than OpenSSL. If you modify file(s) with this
    exception, you may extend this exception to your version of the
    file(s), but you are not obligated to do so. If you do not wish to do
    so, delete this exception statement from your version. If you delete
    this exception statement from all source files in the program, then
    also delete it here.
*/

#include "addresses.h"
#include "timestamp.h"

extern "C" {
#include "addr_lib/get_ip_addresses.h"
}

using namespace Network;

std::vector< Addr > Addresses::get_host_addresses( int *has_change )
{
  array_t kaddrs = get_kernel_addresses();
  array_iter_t iter;
  struct kernel_address *kaddr = NULL;
  std::set< Addr > addr;
  int changed = 0;

  init_iterator( &iter );
  while ( NULL != (kaddr = (struct kernel_address *)get_next( kaddrs, &iter )) ) {
    Addr tmp = Addr( kaddr->sa );
    if ( tmp.is_loopback() || tmp.is_linklocal() ) {
      continue;
    }
    log_dbg( LOG_DEBUG_COMMON, "Host address read: %s.\n", tmp.tostring().c_str() );
    addr.insert( tmp );
  }
  free_array( &kaddrs, free );
  changed = !( addr == addresses );
  if ( has_change ) {
      *has_change = changed;
  }
  if ( changed ) {
      addresses = addr;
  }
  last_addr_check = frozen_timestamp();
  return std::vector< Addr >( addr.begin(), addr.end() );;
}

string Addr::tostring( void ) const {
  string result;
  char dst[INET6_ADDRSTRLEN + 6];
  int family = sa.sa_family;
  int port;
  const char *tmp;
  void *addr;
  if (family == AF_INET) {
    addr = (void*) &sin.sin_addr;
    port = ntohs( sin.sin_port );
  } else if (family == AF_INET6) {
    addr = (void*) &sin6.sin6_addr;
    port = ntohs( sin6.sin6_port );
  } else if ( family == AF_UNSPEC ) {
    return string("<unspecified>"); /* Choice let to the system. */
  } else {
    return string("<Unknown protocol family address>");
  }
  tmp = inet_ntop(family, addr, dst, INET6_ADDRSTRLEN);
  if ( port ) {
    snprintf( dst + strlen(tmp), 6 + 1, ":%d", port );
  }
  return string( tmp );
}

int Addresses::get_fd( void )
{
  return -1;
}
