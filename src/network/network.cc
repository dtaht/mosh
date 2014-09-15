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

#include "config.h"
extern "C" {
#include "util.h"
}

#include <sys/types.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <algorithm>


#include "dos_assert.h"
#include "fatal_assert.h"
#include "byteorder.h"
#include "network.h"
#include "crypto.h"

#include "timestamp.h"

#ifndef MSG_DONTWAIT
#define MSG_DONTWAIT MSG_NONBLOCK
#endif

using namespace std;
using namespace Network;
using namespace Crypto;

const uint64_t DIRECTION_MASK = 0x8000000000000000;
const uint64_t SOCKID_MASK    = 0x7FFF000000000000;
const uint64_t SEQUENCE_MASK  = 0x0000FFFFFFFFFFFF;
#define TO_DIRECTION(d) (uint64_t( (d) == TO_CLIENT ) << 63)
#define TO_SOCKID(id) (uint64_t( id ) << 48)
#define GET_DIRECTION(nonce) ( ((nonce) & DIRECTION_MASK) ? TO_CLIENT : TO_SERVER )
#define GET_SOCKID(nonce) ( uint16_t( ( (nonce) & SOCKID_MASK ) >> 48 ) )
const uint16_t PROBE_FLAG = 1 << 0;
const uint16_t ADDR_FLAG = 1 << 1;

/* Read in packet from coded string */
Packet::Packet( string coded_packet, Session *session )
  : seq( -1 ),
    direction( TO_SERVER ),
    timestamp( -1 ),
    timestamp_reply( -1 ),
    payload()
{
  Message message = session->decrypt( coded_packet );

  direction = GET_DIRECTION( message.nonce.val() );
  sock_id = GET_SOCKID( message.nonce.val() );
  seq = message.nonce.val() & SEQUENCE_MASK;

  dos_assert( message.text.size() >= 3 * sizeof( uint16_t ) );

  uint16_t *data = (uint16_t *)message.text.data();
  timestamp = be16toh( data[ 0 ] );
  timestamp_reply = be16toh( data[ 1 ] );
  flags = be16toh( data[2] );

  payload = string( message.text.begin() + 3 * sizeof( uint16_t ), message.text.end() );
}

bool Packet::is_probe( void )
{
  return flags & PROBE_FLAG;
}

bool Packet::is_addr_msg( void )
{
  return flags & ADDR_FLAG;
}

/* Output coded string from packet */
string Packet::tostring( Session *session )
{
  assert( seq < SEQUENCE_MASK ); /* when this will happen, we'll be dead, brother. */
  uint64_t direction_id_seq = TO_DIRECTION( direction ) | TO_SOCKID( sock_id ) | (seq & SEQUENCE_MASK);

  uint16_t ts_net[ 2 ] = { static_cast<uint16_t>( htobe16( timestamp ) ),
                           static_cast<uint16_t>( htobe16( timestamp_reply ) ) };
  uint16_t flags_net = static_cast<uint16_t>( htobe16( flags ) );

  string timestamps = string( (char *)ts_net, 2 * sizeof( uint16_t ) );
  string flags_string = string( (char *)&flags_net, sizeof( uint16_t ) );

  return session->encrypt( Message( Nonce( direction_id_seq ), timestamps + flags_string + payload ) );
}

Packet Connection::new_packet( Socket *sock, uint16_t flags, string &s_payload )
{
  uint16_t outgoing_timestamp_reply = -1;

  uint64_t now = timestamp();

  if ( now - sock->saved_timestamp_received_at < 1000 ) { /* we have a recent received timestamp */
    /* send "corrected" timestamp advanced by how long we held it */
    outgoing_timestamp_reply = sock->saved_timestamp + (now - sock->saved_timestamp_received_at);
    sock->saved_timestamp = -1;
    sock->saved_timestamp_received_at = 0;
  }

  Packet p( sock->next_seq++, direction, timestamp16(), outgoing_timestamp_reply,
	    sock->sock_id, flags, s_payload );

  return p;
}

void Connection::hop_port( void )
{
  assert( !server );

  setup();
  assert( has_remote_addr() );

  if ( received_remote_addr.size() == 0 ) {
    /* The server probably didn't answer us the last time.  At least there should
       be its link local addresses. */
    send( ADDR_FLAG, string( "" ) );
  }

  int has_change = 0;
  std::set< Addr > addresses = host_addresses.get_host_addresses( &has_change );
  /* We should do something more clever: sorting Sockets by addresses, and then
     check which one can be rebound, and which one should be created.  For now,
     keep it "simple". */
  if ( has_change || rebind ) {
    rebind = false;
    while ( !socks.empty() ) {
      old_socks.push_back( socks.front() );
      socks.pop_front();
    }
    send_socket = NULL;
    refill_socks( addresses );

  } else {
    std::deque< Socket * > new_socks;

    while ( !socks.empty() ) {
      Socket *old_sock = socks.front();
      socks.pop_front();
      old_socks.push_back( old_sock );

      if ( send_socket == old_sock ) {
	send_socket = NULL;
      }
      try {
	Socket *tmp = new Socket( old_sock );
	new_socks.push_back( tmp );
	if ( !send_socket ) {
	  send_socket = tmp;
	}
      } catch ( NetworkException & e ) {
	log_dbg( LOG_DEBUG_COMMON, "Failed to rebind %d (%s -> %s) : %s.\n", (int)old_sock->sock_id,
		 old_sock->local_addr.tostring().c_str(), old_sock->remote_addr.tostring().c_str(),
		 strerror( e.the_errno ) );
      }
    }

    if ( !send_socket ) {
      /* This should never happen.  Refill (and probably die). */
      while ( !new_socks.empty() ) {
	Socket *tmp = new_socks.front();
	new_socks.pop_front();
	delete tmp;
      }
      refill_socks( addresses );
    } else {
      socks = new_socks;
    }
  }

  prune_sockets();
}

void Connection::prune_sockets( void )
{
  if ( old_socks.size() == 0 ) {
    return;
  }

  /* don't keep old sockets if the new socket has been working for long enough */
  if ( timestamp() - last_port_choice > MAX_OLD_SOCKET_AGE ) {
    while ( !old_socks.empty() ) {
      Socket *tmp = old_socks.front();
      old_socks.pop_front();
      delete tmp;
    }
  }

  /* make sure we don't have too many receive sockets open */
  if ( old_socks.size() > MAX_PORTS_OPEN ) {
    int num_to_kill = old_socks.size() - MAX_PORTS_OPEN * socks.size();
    for ( int i = 0; i < num_to_kill; i++ ) {
      Socket *tmp = old_socks.front();
      old_socks.pop_front();
      delete tmp;
    }
  }
}

Connection::Socket::Socket( Socket *old ) /* For port hoping, client only. */
    : _fd( socket( old->local_addr.sa.sa_family, SOCK_DGRAM, 0 ) ),
    MTU( old->MTU ),
    saved_timestamp( -1 ),
    saved_timestamp_received_at( 0 ),
    RTT_hit( false ),
    SRTT( old->SRTT ),
    RTTVAR( old->RTTVAR ),
    next_seq( old->next_seq ),
    sock_id( old->sock_id ),
    local_addr( old->local_addr ),
    remote_addr( old->local_addr )
{
  socket_init( 0, 0 );
}

Connection::Socket::Socket( Addr addr_to_bind, int lower_port, int higher_port, Addr remote_addr, uint16_t id )
    : _fd( socket( addr_to_bind.sa.sa_family, SOCK_DGRAM, 0 ) ),
    MTU( DEFAULT_SEND_MTU ),
    saved_timestamp( -1 ),
    saved_timestamp_received_at( 0 ),
    RTT_hit( false ),
    SRTT( 1000 ),
    RTTVAR( 500 ),
    next_seq( 0 ),
    sock_id( id ),
    local_addr( addr_to_bind ),
    remote_addr( remote_addr )
{
  socket_init( lower_port, higher_port );
}

void Connection::Socket::socket_init( int lower_port, int higher_port )
{
  socklen_t local_addr_len = 0;
  int family = local_addr.sa.sa_family;
  int rc;

  if ( sock_id >= 0x7FFF ) {
    fprintf( stderr, "Sockets exhausted, exiting for security reasons.\n" );
    throw;
  }

  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }

  /* Disable path MTU discovery */
#ifdef HAVE_IP_MTU_DISCOVER
  int level = family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6;
  int name  = family == AF_INET ? IP_MTU_DISCOVER : IPV6_MTU_DISCOVER;
  char flag = family == AF_INET ? IP_PMTUDISC_DONT : IPV6_PMTUDISC_DONT;
  socklen_t optlen = sizeof( flag );
  if ( setsockopt( _fd, level, name, &flag, optlen ) < 0 ) {
    throw NetworkException( "setsockopt", errno );
  }
#endif

  //  int dscp = 0x92; /* OS X does not have IPTOS_DSCP_AF42 constant */
  int dscp = 0x02; /* ECN-capable transport only */
  if ( setsockopt( _fd, IPPROTO_IP, IP_TOS, &dscp, sizeof (dscp)) < 0 ) {
    //    perror( "setsockopt( IP_TOS )" );
  }

  /* request explicit congestion notification on received datagrams */
#ifdef HAVE_IP_RECVTOS
  int tosflag = true;
  socklen_t tosoptlen = sizeof( tosflag );
  if ( setsockopt( _fd, IPPROTO_IP, IP_RECVTOS, &tosflag, tosoptlen ) < 0 ) {
    perror( "setsockopt( IP_RECVTOS )" );
  }
#endif

  /* If the local address is IPV6 and ADDR_ANY, make it hybrid. */
  if ( local_addr.sa.sa_family == AF_INET6 && IN6_IS_ADDR_UNSPECIFIED( &local_addr.sin6.sin6_addr) ) {
    int off = 0;
    if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off))) {
      perror("setsockopt( IPV6_V6ONLY off )");
    }
  }

  /* now, try to bind. */
  if ( family == AF_INET ) {
    local_addr_len = sizeof( struct sockaddr_in );
  } else if ( family == AF_INET6 ) {
    local_addr_len = sizeof( struct sockaddr_in6 );
  } else {
    throw NetworkException( "Unknown address family", 0 );
  }

  for ( int i = lower_port; i <= higher_port; i++ ) {
    if ( family == AF_INET ) {
      local_addr.sin.sin_port = htons( i );
    } else if ( family == AF_INET6 ) {
      local_addr.sin6.sin6_port = htons( i );
    }

    rc = bind( _fd, &local_addr.sa, local_addr_len );
    if ( rc == 0 ) {
      log_dbg( LOG_DEBUG_COMMON, "New Socket %d bound to %s for %s.\n", sock_id,
	       local_addr.tostring().c_str(), remote_addr.tostring().c_str() );
      return;
    }
  }
  /* error */
  int saved_errno = errno;
  close( _fd );
  char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
  int errcode = getnameinfo( &local_addr.sa, local_addr_len,
			     host, sizeof( host ), serv, sizeof( serv ),
			     NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
  if ( errcode != 0 ) {
    throw NetworkException( std::string( "bind: getnameinfo: " ) + gai_strerror( errcode ), 0 );
  }
  errno = saved_errno;
  log_msg( LOG_PERROR, "Failed binding to %s:%s", host, serv );
  throw NetworkException( "bind", saved_errno );
}

void Connection::setup( void )
{
  last_port_choice = timestamp();
}

const std::vector< int > Connection::fds( void ) const
{
  std::vector< int > ret;

  for ( std::deque< Socket* >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    ret.push_back( (*it)->fd() );
  }

  return ret;
}

class AddrInfo {
public:
  struct addrinfo *res;
  AddrInfo( const char *node, const char *service,
	    const struct addrinfo *hints ) :
    res( NULL ) {
    int errcode = getaddrinfo( node, service, hints, &res );
    if ( errcode != 0 ) {
      throw NetworkException( std::string( "Bad IP address (" ) + (node != NULL ? node : "(null)") + "): " + gai_strerror( errcode ), 0 );
    }
  }
  ~AddrInfo() { freeaddrinfo(res); }
private:
  AddrInfo(const AddrInfo &);
  AddrInfo &operator=(const AddrInfo &);
};

Connection::Connection( const char *desired_ip, const char *desired_port ) /* server */
  : socks(),
    old_socks(),
    next_sock_id( 0 ),
    send_socket( NULL ),
    remote_addr(),
    received_remote_addr(),
    host_addresses(),
    rebind( false ),
    server( true ),
    key(),
    session( key ),
    direction( TO_CLIENT ),
    expected_receiver_seq(),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_roundtrip_success( -1 ),
    have_send_exception( false ),
    send_exception()
{
  log_output = fopen("/tmp/mosh_server.log", "wa");
  if ( !log_output ) {
    assert( false );
    log_output = stderr;
  }
  setup();

  /* The mosh wrapper always gives an IP request, in order
     to deal with multihomed servers. The port is optional. */

  /* If an IP request is given, we try to bind to that IP, but we also
     try INADDR_ANY. If a port request is given, we bind only to that port. */

  /* convert port numbers */
  int desired_port_low = 0;
  int desired_port_high = 0;

  if ( desired_port && !parse_portrange( desired_port, desired_port_low, desired_port_high ) ) {
    throw NetworkException("Invalid port range", 0);
  }

  /* try to bind to desired IP first */
  if ( desired_ip ) {
    try {
      if ( try_bind( desired_ip, desired_port_low, desired_port_high ) ) { return; }
    } catch ( const NetworkException& e ) {
      fprintf( stderr, "Error binding to IP %s: %s: %s\n",
	       desired_ip,
	       e.function.c_str(), strerror( e.the_errno ) );
    }
  }

  /* now try any local interface */
  try {
    if ( try_bind( NULL, desired_port_low, desired_port_high ) ) { return; }
  } catch ( const NetworkException& e ) {
    fprintf( stderr, "Error binding to any interface: %s: %s\n",
	     e.function.c_str(), strerror( e.the_errno ) );
    throw; /* this time it's fatal */
  }

  assert( false );
  throw NetworkException( "Could not bind", errno );
}

bool Connection::try_bind( const char *addr, int port_low, int port_high )
{
  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
  AddrInfo ai( addr, "0", &hints );

  Addr local_addr;
  socklen_t local_addr_len = ai.res->ai_addrlen;
  memcpy( &local_addr.sa, ai.res->ai_addr, local_addr_len );

  int search_low = PORT_RANGE_LOW, search_high = PORT_RANGE_HIGH;

  if ( port_low != 0 ) { /* low port preference */
    search_low = port_low;
  }
  if ( port_high != 0 ) { /* high port preference */
    search_high = port_high;
  }

  Socket *sock_tmp = new Socket( local_addr, search_low, search_high, Addr(), next_sock_id++ );
  socks.push_back( sock_tmp );
  return true;
}

Connection::Connection( const char *key_str, const char *ip, const char *port ) /* client */
  : socks(),
    old_socks(),
    next_sock_id( 0 ),
    send_socket( NULL ),
    remote_addr(),
    received_remote_addr(),
    host_addresses(),
    rebind( false ),
    server( false ),
    key( key_str ),
    session( key ),
    direction( TO_SERVER ),
    expected_receiver_seq(),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_roundtrip_success( -1 ),
    have_send_exception( false ),
    send_exception()
{
  log_output = fopen("/tmp/mosh_client.log", "wa");
  if ( !log_output ) {
    assert( false );
    log_output = stderr;
  }
  setup();

  /* associate socket with remote host and port */
  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  AddrInfo ai( ip, port, &hints );
  fatal_assert( ai.res->ai_addrlen <= sizeof( struct sockaddr_storage ) );
  for ( struct addrinfo *it = ai.res; it != NULL; it = it->ai_next ) {
    remote_addr.push_back( Addr( *it->ai_addr, it->ai_addrlen ) );
  }

  std::set< Addr > addresses = host_addresses.get_host_addresses( NULL );
  refill_socks( addresses );

  /* Ask the server what are its addresses. */
  send( ADDR_FLAG, string( "" ) );
}

void Connection::refill_socks( std::set< Addr > &addresses )
{
  assert( !send_socket && socks.empty() && !remote_addr.empty() );

  std::vector< Addr >::const_iterator ra_it = remote_addr.begin();
  while ( true ) {
    if ( ra_it == remote_addr.end() ) {
      ra_it = received_remote_addr.begin();
    }
    if ( ra_it == received_remote_addr.end() ) {
      break;
    }

    log_dbg( LOG_DEBUG_COMMON,
	     "Trying to bind for the remote address: %s.\n",
	     ra_it->tostring().c_str() );

    bind_to_each( addresses, *ra_it);

    ra_it ++;
  }
}

void Connection::bind_to_each( std::set< Addr > &addresses, const Addr &remote_addr )
{
  for ( std::set< Addr >::const_iterator la_it = addresses.begin();
	la_it != addresses.end();
	la_it++ ) {
    if ( la_it->sa.sa_family != remote_addr.sa.sa_family ) {
      continue;
    }
    try {
      send_socket = new Socket( *la_it, 0, 0, remote_addr, next_sock_id );
      next_sock_id ++;
      socks.push_back( send_socket );
    } catch ( NetworkException & e ) {
      log_dbg( LOG_DEBUG_COMMON, "Failed to bind at %s (%s)\n", la_it->tostring().c_str(), strerror( e.the_errno ) );
    }
  }

  log_dbg( LOG_DEBUG_COMMON, "%d sockets successfully bound\n", (int)socks.size() );

  if ( !send_socket ) {
    fprintf( stderr, "Failed binding to any local address\n" );
    /* Try to continue with that; we will retry binding later... */
    Addr whatever;
    int family[2] = { AF_INET, AF_INET6 };
    memset( &whatever.ss, 0, sizeof( whatever.ss ) );
    for ( int i = 0; i < 2; i ++ ) {
      whatever.sa.sa_family = family[i];
      try {
	send_socket = new Socket( whatever, 0, 0, remote_addr, next_sock_id++ );
	break;
      }  catch ( NetworkException & e ) {
	log_dbg( LOG_DEBUG_COMMON, "Failed to bind whatever on IPv%c\n",
		 whatever.sa.sa_family == AF_INET ? '4' : '6' );
      }
    }
    socks.push_back( send_socket );
  }
}

void Connection::send_probes( void )
{
  bool has_fail = 0;
  if ( server ) {
    return;
  }
  for ( std::deque< Socket* >::iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    if ( *it != send_socket ) {
      bool rc = send_probe( *it, (*it)->remote_addr );
      has_fail = has_fail || rc;
    }
  }

  if ( has_fail ) {
    /* Mt: recheck interfaces. */
  }
}

void Connection::send_addresses( void )
{
  assert( server );
  string payload;
  std::set< Addr > addresses = host_addresses.get_host_addresses( NULL );
  for ( std::set< Addr >::const_iterator la_it = addresses.begin();
	la_it != addresses.end();
	la_it++ ) {
    if ( la_it->addrlen > 255 ) {
      continue;
    }
    Addr tmp = *la_it; /* because la_it is "const"... using a vector instead ? */
    log_dbg( LOG_DEBUG_COMMON, "Sending my address: %s.\n", la_it->tostring().c_str() );
    uint8_t addrlen = la_it->addrlen;
    /* Set our listening port. */
    if ( tmp.sa.sa_family == AF_INET ) {
      tmp.sin.sin_port = send_socket->local_addr.sin.sin_port;
    } else if ( tmp.sa.sa_family == AF_INET6 ) {
      tmp.sin6.sin6_port = send_socket->local_addr.sin6.sin6_port;
    }
    payload += string( (char *) &addrlen, 1 ) + string( (char *) &tmp.sa, addrlen );
  }
  send( ADDR_FLAG, payload );
}

void Connection::parse_received_addresses( string payload )
{
  int size = payload.size();
  const unsigned char *data = (const unsigned char*) payload.data();
  std::vector< Addr > addr;
  while( size > 0 ) {
    int addrlen = (int)data[0];
    if ( size < 1 + addrlen ) {
      log_dbg( LOG_DEBUG_COMMON, "Truncated message received.\n" );
      break;
    }
    addr.push_back( Addr( *(struct sockaddr *) (data + 1), addrlen ) );
    log_dbg( LOG_DEBUG_COMMON, "Remote address received: %s.\n", addr.back().tostring().c_str() );
    data += 1 + addrlen;
    size -= 1 + addrlen;
  }
  assert( size == 0 );

  /* don't retain addresses already registered in remote_addr */
  received_remote_addr.resize( addr.size() );
  std::sort( addr.begin(), addr.end() );
  std::sort( remote_addr.begin(), remote_addr.end() );
  std::vector< Addr >::const_iterator it;
  it = std::set_difference( addr.begin(), addr.end(),
			    remote_addr.begin(), remote_addr.end(),
			    received_remote_addr.begin() );
  received_remote_addr.resize( it - received_remote_addr.begin() );
  rebind = true;
}

bool Connection::send_probe( Socket *sock, Addr &addr )
{
  string empty("");
  Packet px = new_packet( sock, PROBE_FLAG, empty );

  string p = px.tostring( &session );

  log_dbg( LOG_DEBUG_COMMON, "Sending probe on %d (%s -> %s): ", (int)sock->sock_id,
	   sock->local_addr.tostring().c_str(), sock->remote_addr.tostring().c_str() );

  ssize_t bytes_sent = sendto( sock->fd(), p.data(), p.size(), MSG_DONTWAIT,
			       &addr.sa, addr.addrlen );
  if ( bytes_sent < 0 ) {
    send_socket->SRTT += 1000;
    log_dbg( LOG_PERROR, "failed" );
  } else {
    log_dbg( LOG_DEBUG_COMMON, "sucess.\n" );
  }

  return ( bytes_sent != static_cast<ssize_t>( p.size() ) );
}

void Connection::send( uint16_t flags, string s )
{
  if ( !has_remote_addr() ) {
    return;
  }

  Packet px = new_packet( send_socket, flags, s );

  string p = px.tostring( &session );

  std::sort( socks.begin(), socks.end(), Socket::srtt_order );
  ssize_t bytes_sent = -1;
  log_dbg( LOG_DEBUG_COMMON, "Sending data" );
  for ( std::deque< Socket* >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    Socket *sock = *it;
    bytes_sent = sendto( sock->fd(), p.data(), p.size(), MSG_DONTWAIT,
			 &sock->remote_addr.sa, sock->remote_addr.addrlen );
    if ( bytes_sent < 0 ) {
      sock->SRTT += 1000;
    } else {
      if ( send_socket != sock ) {
	log_dbg( LOG_DEBUG_COMMON,
		 ": done by switching from socket %d (%s -> %s, SRTT=%dms) to %d (%s -> %s, SRTT=%dms).\n",
		 (int)send_socket->sock_id, send_socket->local_addr.tostring().c_str(),
		 send_socket->remote_addr.tostring().c_str(), (int)send_socket->SRTT,
		 (int)sock->sock_id, sock->local_addr.tostring().c_str(),
		 sock->remote_addr.tostring().c_str(), (int)sock->SRTT );
	send_socket = sock;
      } else {
	log_dbg( LOG_DEBUG_COMMON, ": done on %d (%s).\n",
		 (int)send_socket->sock_id, send_socket->local_addr.tostring().c_str() );
      }
      break;
    }
  }

  if ( bytes_sent == static_cast<ssize_t>( p.size() ) ) {
    have_send_exception = false;
  } else {
    log_dbg( LOG_PERROR, " failed" );
    /* Notify the frontend on sendto() failure, but don't alter control flow.
       sendto() success is not very meaningful because packets can be lost in
       flight anyway. */
    have_send_exception = true;
    send_exception = NetworkException( "sendto", errno );

    if ( errno == EMSGSIZE ) {
      send_socket->MTU = 500; /* payload MTU of last resort */
    }
  }

  uint64_t now = timestamp();
  if ( server ) {
    if ( now - last_heard > SERVER_ASSOCIATION_TIMEOUT ) {
      send_socket = NULL;
      fprintf( stderr, "Server now detached from client.\n" );
    }
  } else { /* client */
    if ( ( ( now - last_port_choice > PORT_HOP_INTERVAL )
	   && ( now - last_roundtrip_success > PORT_HOP_INTERVAL ) ) || rebind ) {
      hop_port();
    }
  }
}

string Connection::recv( void )
{
  assert( !socks.empty() );
  for ( std::deque< Socket* >::iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    bool islast = (it + 1) == socks.end();
    string payload;
    try {
      payload = recv_one( *it, !islast );
    } catch ( NetworkException & e ) {
      if ( (e.the_errno == EAGAIN)
	   || (e.the_errno == EWOULDBLOCK) ) {
	assert( !islast );
	continue;
      } else {
	throw;
      }
    }

    /* succeeded */
    prune_sockets();
    return payload;
  }
  assert( false );
  return "";
}

string Connection::recv_one( Socket *sock, bool nonblocking )
{
  int sock_to_recv = sock->fd();
  /* receive source address, ECN, and payload in msghdr structure */
  Addr packet_remote_addr;
  struct msghdr header;
  struct iovec msg_iovec;

  char msg_payload[ Session::RECEIVE_MTU ];
  char msg_control[ Session::RECEIVE_MTU ];

  /* receive source address */
  header.msg_name = &packet_remote_addr.sa;
  header.msg_namelen = packet_remote_addr.addrlen;
  assert( packet_remote_addr.addrlen == sizeof( packet_remote_addr.ss ) );

  /* receive payload */
  msg_iovec.iov_base = msg_payload;
  msg_iovec.iov_len = Session::RECEIVE_MTU;
  header.msg_iov = &msg_iovec;
  header.msg_iovlen = 1;

  /* receive explicit congestion notification */
  header.msg_control = msg_control;
  header.msg_controllen = Session::RECEIVE_MTU;

  /* receive flags */
  header.msg_flags = 0;

  ssize_t received_len = recvmsg( sock_to_recv, &header, nonblocking ? MSG_DONTWAIT : 0 );
  packet_remote_addr.addrlen = header.msg_namelen;

  if ( received_len < 0 ) {
    throw NetworkException( "recvmsg", errno );
  }

  if ( header.msg_flags & MSG_TRUNC ) {
    throw NetworkException( "Received oversize datagram", errno );
  }

  /* receive ECN */
  bool congestion_experienced = false;

  struct cmsghdr *ecn_hdr = CMSG_FIRSTHDR( &header );
  if ( ecn_hdr
       && (ecn_hdr->cmsg_level == IPPROTO_IP)
       && (ecn_hdr->cmsg_type == IP_TOS) ) {
    /* got one */
    uint8_t *ecn_octet_p = (uint8_t *)CMSG_DATA( ecn_hdr );
    assert( ecn_octet_p );

    if ( (*ecn_octet_p & 0x03) == 0x03 ) {
      congestion_experienced = true;
    }
  }

  Packet p( string( msg_payload, received_len ), &session );

  dos_assert( p.direction == (server ? TO_SERVER : TO_CLIENT) ); /* prevent malicious playback to sender */

  if ( p.seq >= expected_receiver_seq[p.sock_id] ) { /* don't use out-of-order packets for timestamp or targeting */
    expected_receiver_seq[p.sock_id] = p.seq + 1; /* this is security-sensitive because a replay attack could otherwise
						     screw up the timestamp and targeting */

    if ( p.timestamp != uint16_t(-1) ) {
      sock->saved_timestamp = p.timestamp;
      sock->saved_timestamp_received_at = timestamp();

      if ( congestion_experienced ) {
	/* signal counterparty to slow down */
	/* this will gradually slow the counterparty down to the minimum frame rate */
	sock->saved_timestamp -= CONGESTION_TIMESTAMP_PENALTY;
	if ( server ) {
	  fprintf( stderr, "Received explicit congestion notification.\n" );
	}
      }
    }

    if ( p.timestamp_reply != uint16_t(-1) ) {
      uint16_t now = timestamp16();
      double R = timestamp_diff( now, p.timestamp_reply );

      if ( R < 5000 ) { /* ignore large values, e.g. server was Ctrl-Zed */
	if ( !sock->RTT_hit ) { /* first measurement */
	  sock->SRTT = R;
	  sock->RTTVAR = R / 2;
	  sock->RTT_hit = true;
	} else {
	  const double alpha = 1.0 / 8.0;
	  const double beta = 1.0 / 4.0;
	  
	  sock->RTTVAR = (1 - beta) * sock->RTTVAR + ( beta * fabs( sock->SRTT - R ) );
	  sock->SRTT = (1 - alpha) * sock->SRTT + ( alpha * R );
	}
      }
      if ( p.is_probe() ) {
	log_dbg( LOG_DEBUG_COMMON, "Probe received on sock %d (%s), RTT=%u, SRTT=%u\n",
		 (int) sock->sock_id, sock->local_addr.tostring().c_str(), (unsigned int)R, (unsigned int)sock->SRTT );
      }
    }

    /* auto-adjust to remote host */
    last_heard = timestamp();
    if ( p.is_probe() ) {
      if ( server ) {
	send_probe( sock, packet_remote_addr );
      }
      if ( ! p.payload.empty() ) {
	fprintf(stderr, "Strange: probe with payload received.\n");
      }
      return p.payload;
    }

    if ( server ) { /* only client can roam */
      send_socket = sock;
      if ( send_socket->remote_addr != packet_remote_addr ) {
	send_socket->remote_addr = packet_remote_addr;
	char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
	int errcode = getnameinfo( &send_socket->remote_addr.sa, send_socket->remote_addr.addrlen,
				   host, sizeof( host ), serv, sizeof( serv ),
				   NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
	if ( errcode != 0 ) {
	  throw NetworkException( std::string( "recv_one: getnameinfo: " ) + gai_strerror( errcode ), 0 );
	}
	fprintf( stderr, "Server now attached to client at %s:%s\n",
		 host, serv );
      }
    }

    if ( p.is_addr_msg() ) {
      if ( server ) {
	send_addresses();
	assert( p.payload.empty() );
      } else {
	parse_received_addresses( p.payload );
	p.payload = string("");
      }
    }
  }

  return p.payload; /* we do return out-of-order or duplicated packets to caller */
}

std::string Connection::port( void ) const
{
  Addr local_addr;
  socklen_t addrlen = sizeof( local_addr );

  if ( getsockname( sock()->fd(), &local_addr.sa, &addrlen ) < 0 ) {
    throw NetworkException( "getsockname", errno );
  }

  char serv[ NI_MAXSERV ];
  int errcode = getnameinfo( &local_addr.sa, addrlen,
			     NULL, 0, serv, sizeof( serv ),
			     NI_DGRAM | NI_NUMERICSERV );
  if ( errcode != 0 ) {
    throw NetworkException( std::string( "port: getnameinfo: " ) + gai_strerror( errcode ), 0 );
  }

  return std::string( serv );
}

uint64_t Network::timestamp( void )
{
  return frozen_timestamp();
}

uint16_t Network::timestamp16( void )
{
  uint16_t ts = timestamp() % 65536;
  if ( ts == uint16_t(-1) ) {
    ts++;
  }
  return ts;
}

uint16_t Network::timestamp_diff( uint16_t tsnew, uint16_t tsold )
{
  int diff = tsnew - tsold;
  if ( diff < 0 ) {
    diff += 65536;
  }
  
  assert( diff >= 0 );
  assert( diff <= 65535 );

  return diff;
}

uint64_t Connection::timeout( void ) const
{
  uint64_t RTO = lrint( ceil( sock()->SRTT + 4 * sock()->RTTVAR ) );
  if ( RTO < MIN_RTO ) {
    RTO = MIN_RTO;
  } else if ( RTO > MAX_RTO ) {
    RTO = MAX_RTO;
  }
  return RTO;
}

Connection::~Connection()
{
    for ( std::deque< Socket* >::iterator it = socks.begin();
	  it != socks.end();
	  it ++ ) {
      delete *it;
    }
}

Connection::Socket::~Socket()
{
  if ( close( _fd ) < 0 ) {
    throw NetworkException( "close", errno );
  }
}

Connection::Socket::Socket( const Socket & other )
  : _fd( dup( other._fd ) )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }
}

Connection::Socket & Connection::Socket::operator=( const Socket & other )
{
  if ( dup2( other._fd, _fd ) < 0 ) {
    throw NetworkException( "socket", errno );
  }

  return *this;
}

bool Connection::parse_portrange( const char * desired_port, int & desired_port_low, int & desired_port_high )
{
  /* parse "port" or "portlow:porthigh" */
  desired_port_low = desired_port_high = 0;
  char *end;
  long value;

  /* parse first (only?) port */
  errno = 0;
  value = strtol( desired_port, &end, 10 );
  if ( (errno != 0) || (*end != '\0' && *end != ':') ) {
    fprintf( stderr, "Invalid (low) port number (%s)\n", desired_port );
    return false;
  }
  if ( (value < 0) || (value > 65535) ) {
    fprintf( stderr, "(Low) port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_low = (int)value;
  if (*end == '\0') { /* not a port range */
    desired_port_high = desired_port_low;
    return true;
  }

  /* port range; parse high port */
  const char * cp = end + 1;
  errno = 0;
  value = strtol( cp, &end, 10 );
  if ( (errno != 0) || (*end != '\0') ) {
    fprintf( stderr, "Invalid high port number (%s)\n", cp );
    return false;
  }
  if ( (value < 0) || (value > 65535) ) {
    fprintf( stderr, "High port number %ld outside valid range [0..65535]\n", value );
    return false;
  }

  desired_port_high = (int)value;
  if ( desired_port_low > desired_port_high ) {
    fprintf( stderr, "Low port %d greater than high port %d\n", desired_port_low, desired_port_high );
    return false;
  }

  return true;
}
