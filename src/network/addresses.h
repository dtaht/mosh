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

#ifndef ADDRESSES_HPP
#define ADDRESSES_HPP

#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <set>
#include <vector>
#include <string>

#define IN_IS_ADDR_LOOPBACK(sin) ( ( (char*)sin)[0] == 127 )

using namespace std;

namespace Network {

  struct Addr {
  public:
    int addrlen; /* length of the socket address (not just the IP address). */
    union {
      struct sockaddr sa;
      struct sockaddr_in sin;
      struct sockaddr_in6 sin6;
      struct sockaddr_storage ss;
    };

    Addr() : addrlen( sizeof( ss ) ), ss() { memset( &ss, 0, sizeof( ss ) ); }
    Addr( struct sockaddr &s ) {
      switch ( s.sa_family ) {
      case AF_UNSPEC: addrlen = 0;              break;
      case AF_INET:   addrlen = sizeof( sin );  break;
      case AF_INET6:  addrlen = sizeof( sin6 ); break;
      default:        addrlen = sizeof( ss );   break;
      }
      memcpy( &ss, &s, addrlen );
    }
    Addr( struct sockaddr &s, socklen_t len ) : addrlen( (int)len ) { memcpy( &ss, &s, len ); }
    Addr( struct sockaddr_in &s ) : addrlen( sizeof( struct sockaddr_in ) ), sin( s ) {}
    Addr( struct sockaddr_in6 &s ) : addrlen( sizeof( struct sockaddr_in6 ) ), sin6( s ) {}
    Addr( struct sockaddr_storage &s ) : addrlen( sizeof( struct sockaddr_storage ) ), ss( s ) {}

    int compare( const Addr &a2 ) const {
      if ( sa.sa_family != a2.sa.sa_family ) {
	return sa.sa_family - a2.sa.sa_family;
      }

      if ( sa.sa_family == AF_INET ) {
	return memcmp( &sin.sin_addr, &a2.sin.sin_addr, 4 );
      }
      if ( sa.sa_family == AF_INET6 ) {
	return memcmp( &sin6.sin6_addr, &a2.sin6.sin6_addr, 16 );
      }
      return memcmp( &ss, &a2.ss, sizeof( ss ) );
    }

    bool operator<( const Addr &a2 ) const {
      return compare( a2 ) < 0;
    }

    bool operator==( const Addr &a2 ) const {
      return compare( a2 ) == 0;
    }

    bool operator!=( const Addr &a2 ) const {
      return compare( a2 ) != 0;
    }

    string tostring( void ) const;

    bool is_loopback( void ) const {
      return ( sa.sa_family == AF_INET && IN_IS_ADDR_LOOPBACK( &sin.sin_addr ) ) ||
	( sa.sa_family == AF_INET6 && IN6_IS_ADDR_LOOPBACK( &sin6.sin6_addr ) );
    }

    bool is_linklocal( void ) const {
      return sa.sa_family == AF_INET6 && IN6_IS_ADDR_LINKLOCAL( &sin6.sin6_addr );
    }
  };

  class Addresses {
  private:
    std::set< Addr > addresses;
    uint64_t last_addr_check;
  public:
    std::vector< Addr > get_host_addresses( int *has_change );
    int get_fd( void ); /* to monitor things */
    uint64_t last_check( void ) { return last_addr_check; }
  };
}

#endif /* ADDRESSES_HPP */
