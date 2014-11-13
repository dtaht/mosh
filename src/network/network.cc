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

#define __APPLE_USE_RFC_3542

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
const uint64_t FLOWID_MASK    = 0x7FFF000000000000;
const uint64_t SEQUENCE_MASK  = 0x0000FFFFFFFFFFFF;
#define TO_DIRECTION(d) (uint64_t( (d) == TO_CLIENT ) << 63)
#define TO_FLOWID(id) (uint64_t( id ) << 48)
#define GET_DIRECTION(nonce) ( ((nonce) & DIRECTION_MASK) ? TO_CLIENT : TO_SERVER )
#define GET_FLOWID(nonce) ( uint16_t( ( (nonce) & FLOWID_MASK ) >> 48 ) )
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
  flow_id = GET_FLOWID( message.nonce.val() );
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
  uint64_t direction_id_seq = TO_DIRECTION( direction ) | TO_FLOWID( flow_id ) | (seq & SEQUENCE_MASK);

  uint16_t ts_net[ 2 ] = { static_cast<uint16_t>( htobe16( timestamp ) ),
                           static_cast<uint16_t>( htobe16( timestamp_reply ) ) };
  uint16_t flags_net = static_cast<uint16_t>( htobe16( flags ) );

  string timestamps = string( (char *)ts_net, 2 * sizeof( uint16_t ) );
  string flags_string = string( (char *)&flags_net, sizeof( uint16_t ) );

  return session->encrypt( Message( Nonce( direction_id_seq ), timestamps + flags_string + payload ) );
}

Packet Connection::new_packet( Flow *flow, uint16_t flags, string &s_payload )
{
  uint16_t outgoing_timestamp_reply = -1;

  uint64_t now = timestamp();

  if ( now - flow->saved_timestamp_received_at < 1000 ) { /* we have a recent received timestamp */
    /* send "corrected" timestamp advanced by how long we held it */
    outgoing_timestamp_reply = flow->saved_timestamp + (now - flow->saved_timestamp_received_at);
    flow->saved_timestamp = -1;
    flow->saved_timestamp_received_at = 0;
  }

  Packet p( flow->next_seq++, direction, timestamp16(), outgoing_timestamp_reply,
	    flow->flow_id, flags, s_payload );

  return p;
}

void Connection::hop_port( void )
{
  assert( !server );
  log_dbg( LOG_DEBUG_COMMON, "Hop port!\n" );

  setup();
  assert( flows.size() != 0 );
  socks.push_back( Socket( PF_INET, 0, 0 ) );
  socks6.push_back( Socket( PF_INET6, 0, 0 ) );

  prune_sockets();
}

void Connection::prune_sockets( void ) {
  prune_sockets( socks );
  prune_sockets( socks6 );
}

void Connection::prune_sockets( std::deque< Socket > &socks_queue )
{
  /* don't keep old sockets if the new socket has been working for long enough */
  if ( socks_queue.size() > 1 ) {
    if ( timestamp() - last_port_choice > MAX_OLD_SOCKET_AGE ) {
      int num_to_kill = socks_queue.size() - 1;
      for ( int i = 0; i < num_to_kill; i++ ) {
	socks_queue.pop_front();
      }
    }
  } else {
    return;
  }

  /* make sure we don't have too many receive sockets open */
  if ( socks_queue.size() > MAX_PORTS_OPEN ) {
    int num_to_kill = socks_queue.size() - MAX_PORTS_OPEN;
    for ( int i = 0; i < num_to_kill; i++ ) {
      socks_queue.pop_front();
    }
  }
}

void Connection::check_remote_addr( void ) {
  uint64_t now = timestamp();
  if ( now - last_addr_request > MAX_ADDR_REQUEST_INTERVAL ) {
    last_addr_request = now;
    log_dbg( LOG_DEBUG_COMMON, "Asking server addresses.\n" );
    send( ADDR_FLAG, string( "" ) );
  }
}

bool Connection::flow_exists( const Addr &src, const Addr &dst ) {
  for ( std::map< uint16_t, Flow* >::iterator it = flows.begin();
	it != flows.end();
	it++ ) {
    if ( it->second->src == src && it->second->dst == dst ) {
      return true;
    }
  }
  return false;
}

/* Add new flows, if needed. */
void Connection::check_flows( bool remote_has_changed ) {
  assert( !server );
  int has_changed = 0;
  std::vector< Addr > addresses = host_addresses.get_host_addresses( &has_changed );
  /* this will allow the system to choose the source address on one flow. */
  addresses.push_back( Addr( AF_INET ) );
  addresses.push_back( Addr( AF_INET6 ) );

  if ( !has_changed && !remote_has_changed ) {
    return;
  }

  for ( std::vector< Addr >::const_iterator la_it = addresses.begin();
	la_it != addresses.end();
	la_it++ ) {
    for ( std::vector< Addr >::const_iterator ra_it = remote_addr.begin();
	  ra_it != remote_addr.end();
	  ra_it++ ) {
      if ( la_it->sa.sa_family == ra_it->sa.sa_family ) {
	if ( ! flow_exists( *la_it, *ra_it ) ) {
	  Flow *flow_info = new Flow( *la_it, *ra_it );
	  flows[ flow_info->flow_id ] = flow_info;
	}
      }
    }

    for ( std::vector< Addr >::const_iterator ra_it = received_remote_addr.begin();
	  ra_it != received_remote_addr.end();
	  ra_it++ ) {
      if ( la_it->sa.sa_family == ra_it->sa.sa_family ) {
	if ( ! flow_exists( *la_it, *ra_it ) ) {
	  Flow *flow_info = new Flow( *la_it, *ra_it );
	  flows[ flow_info->flow_id ] = flow_info;
	}
      }
    }
  }
}

uint16_t Connection::Flow::next_flow_id = 0;
const Connection::Flow Connection::Flow::defaults;

Connection::Flow::Flow( const Addr &s_src, const Addr &s_dst )
  : src( s_src ),
    dst( s_dst ),
    MTU( defaults.MTU ),
    next_seq( defaults.next_seq ),
    expected_receiver_seq( defaults.expected_receiver_seq ),
    saved_timestamp( defaults.saved_timestamp ),
    saved_timestamp_received_at( defaults.saved_timestamp_received_at ),
    RTT_hit( defaults.RTT_hit ),
    SRTT( defaults.SRTT ),
    RTTVAR( defaults.RTTVAR ),
    flow_id( next_flow_id++ )
{
  if ( flow_id == 0xFFFF ) {
    fprintf( stderr, "Max flow ID reached, exit before nonce be corrupted\n." );
    throw;
  }
}

Connection::Flow::Flow( const Addr &s_src, const Addr &s_dst, uint16_t id )
  : src( s_src ),
    dst( s_dst ),
    MTU( defaults.MTU ),
    next_seq( defaults.next_seq ),
    expected_receiver_seq( defaults.expected_receiver_seq ),
    saved_timestamp( defaults.saved_timestamp ),
    saved_timestamp_received_at( defaults.saved_timestamp_received_at ),
    RTT_hit( defaults.RTT_hit ),
    SRTT( defaults.SRTT ),
    RTTVAR( defaults.RTTVAR ),
    flow_id( id )
{
  assert( !next_flow_id ); /* The server should not have initialized any flow. */
}

Connection::Socket::Socket( int family, int lower_port, int higher_port )
  : _fd( socket( family, SOCK_DGRAM, 0 ) ),
    port( 0 )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }

  const int on = 1;

  /* In any case, we MUST bind the socket (even when client), otherwise, using
     sendmsg + IP_PKTINFO leads to kernel panic on Mac OS. */
  if ( family == PF_INET ) {
    try_bind( _fd, Addr( AF_INET ), lower_port, higher_port );

#ifdef HAVE_IP_MTU_DISCOVER
    int flag = IP_PMTUDISC_DONT;
    socklen_t optlen = sizeof( flag );
    if ( setsockopt( _fd, IPPROTO_IP, IP_MTU_DISCOVER, &flag, optlen ) < 0 ) {
      throw NetworkException( "setsockopt( MTU )", errno );
    }
#endif

    int dscp = 0x02; /* ECN-capable transport only */
    if ( setsockopt( _fd, IPPROTO_IP, IP_TOS, &dscp, sizeof( dscp )) < 0 ) {
      //    perror( "setsockopt( IP_TOS )" );
    }

#ifdef HAVE_IP_RECVTOS
    if ( setsockopt( _fd, IPPROTO_IP, IP_RECVTOS, &on, sizeof( on ) ) < 0 ) {
      perror( "setsockopt( IP_RECVTOS )" );
    }
#endif

    /* Tell me on which address the msg has been received. */
#ifdef IP_PKTINFO
    if ( setsockopt( _fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof( on ) ) < 0 ) {
      throw NetworkException( "setsockopt( IP_PKTINFO )", errno );
    }
#elif defined IP_RECVDSTADDR
    if ( setsockopt( _fd, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof( on ) ) < 0 ) {
      throw NetworkException( "setsockopt( IP_RECVDSTADDR )", errno );
    }
#else
#warning "Can't get my local address on packet reception."
#endif

  } else if (family == PF_INET6 ) {
    /* No hybrid socket. */
    if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof( on ) ) < 0 ) {
      throw NetworkException( "setsockopt( IPV6_V6ONLY off )", errno );
    }

    try_bind( _fd, Addr( AF_INET6 ), lower_port, higher_port );

    /* request explicit congestion notification on received datagrams */
    if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof( on ) ) < 0 ) {
      perror( "setsockopt( IPV6_RECVTCLASS on )" );
    }

    /* Tell me on which address the msg has been received. */
    if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof( on ) ) ) {
      perror( "setsockopt( IPV6_RECVPKTINFO on )" );
    }
  } else {
    throw NetworkException( "Unknown protocol family", 0 );
  }
}

void Connection::setup( void )
{
  last_port_choice = timestamp();
}

const std::vector< int > Connection::fds( void ) const
{
  std::vector< int > ret;

  for ( std::deque< Socket >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    ret.push_back( it->fd() );
  }

  for ( std::deque< Socket >::const_iterator it = socks6.begin();
	it != socks6.end();
	it++ ) {
    ret.push_back( it->fd() );
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
    socks6(),
    remote_addr(),
    received_remote_addr(),
    flows(),
    last_flow( NULL ),
    host_addresses(),
    server( true ),
    key(),
    session( key ),
    direction( TO_CLIENT ),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_addr_request( -1 ),
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

  /* We ignore the IP provided, because we will specify ourselves the source
     address.  The problem with multihomed server is solved by sending back
     packets answering with the last known local IP used to receive a packet.
     If a port request is given, we bind only to that port. */

  /* convert port numbers */
  int desired_port_low = 0;
  int desired_port_high = 0;

  if ( desired_port && !parse_portrange( desired_port, desired_port_low, desired_port_high ) ) {
    throw NetworkException("Invalid port range", 0);
  }

  /* try any local interface */
  int search_low = desired_port_low ? desired_port_low : PORT_RANGE_LOW;
  int search_high = desired_port_high ? desired_port_high : PORT_RANGE_HIGH;

  while ( search_low <= search_high ) {
    socks.push_back( Socket( PF_INET, search_low, search_high ) );
    try {
      socks6.push_back( Socket( PF_INET6, socks.back().port, socks.back().port ) );
      break;
    } catch ( const NetworkException& e ) {
      /* ok, try to bind both the sockets to the next port number. */
      search_low = socks.back().port + 1;
      socks.pop_back();
    }
  }

  if ( socks.empty() || socks6.empty() ) {
    fprintf( stderr, "Error binding to any interface\n" );
    throw; /* well, is there again some systems which doesn't support IPv6 ? */
  }
}

bool Connection::Socket::try_bind( int sock, Addr local_addr, int port_low, int port_high )
{
  for ( int i = port_low; i <= port_high; i++ ) {
    if ( local_addr.sa.sa_family == AF_INET ) {
      local_addr.sin.sin_port = htons( port = i );
    } else if ( local_addr.sa.sa_family == AF_INET6 ) {
      local_addr.sin6.sin6_port = htons( port = i );
    } else {
      throw NetworkException( "try_bind: Invalid address family specified", EINVAL );
      assert( false );
      return false;
    }

    if ( bind( sock, &local_addr.sa, local_addr.addrlen ) == 0 ) {
      if ( port == 0 ) { /* retreive the port when not specifying it (client) */
	socklen_t tmp = local_addr.addrlen;
	if ( getsockname( sock, &local_addr.sa, &tmp ) < 0 ) {
	  throw NetworkException( "bind - getsockname", errno );
	}
	local_addr.addrlen = tmp;
	if ( local_addr.sa.sa_family == AF_INET ) {
	  port = ntohs( local_addr.sin.sin_port );
	} else if ( local_addr.sa.sa_family == AF_INET6 ) {
	  port = ntohs( local_addr.sin6.sin6_port );
	}
      }
      log_dbg( LOG_DEBUG_COMMON, "New socket bound to %s.\n", local_addr.tostring().c_str() );
      return true;
    }
    if ( i == port_high ) { /* last port to search */
      int saved_errno = errno;
      char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
      int errcode = getnameinfo( &local_addr.sa, local_addr.addrlen,
				 host, sizeof( host ), serv, sizeof( serv ),
				 NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
      if ( errcode != 0 ) {
	throw NetworkException( std::string( "bind: getnameinfo: " ) + gai_strerror( errcode ), 0 );
      }
      log_msg( LOG_PERROR, "Failed binding to %s:%s", host, serv );
      throw NetworkException( "bind", saved_errno );
    }
  }

  assert( false );
  return false;
}

Connection::Connection( const char *key_str, const char *ip, const char *port ) /* client */
  : socks(),
    socks6(),
    remote_addr(),
    received_remote_addr(),
    flows(),
    last_flow( NULL ),
    host_addresses(),
    server( false ),
    key( key_str ),
    session( key ),
    direction( TO_SERVER ),
    last_heard( -1 ),
    last_port_choice( -1 ),
    last_addr_request( -1 ),
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

  std::vector< Addr > addresses = host_addresses.get_host_addresses( NULL );
  /* this will allow the system to choose the source address on one flow. */
  addresses.push_back( Addr( AF_INET ) );
  addresses.push_back( Addr( AF_INET6 ) );

  struct addrinfo hints;
  memset( &hints, 0, sizeof( hints ) );
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
  AddrInfo ai( ip, port, &hints );
  fatal_assert( ai.res->ai_addrlen <= sizeof( struct Addr ) );

  for ( struct addrinfo *ra_it = ai.res; ra_it != NULL; ra_it = ra_it->ai_next ) {
    if ( ra_it->ai_addr->sa_family == AF_INET || ra_it->ai_addr->sa_family == AF_INET6 ) {
      remote_addr.push_back( Addr( *ra_it->ai_addr, ra_it->ai_addrlen ) );
    }
  }

  check_flows( true );

  socks.push_back( Socket( PF_INET, 0, 0 ) );
  socks6.push_back( Socket( PF_INET6, 0, 0 ) );

  /* Ask the server what are its addresses. */
  send( ADDR_FLAG, string( "" ) );
  last_addr_request = timestamp();
  send_probes(); /* This should check all flows. */
}

void Connection::send_probes( void )
{
  assert( !server );
  for ( std::map< uint16_t, Flow* >::iterator it = flows.begin();
	it != flows.end();
	it++ ) {
    if ( it->second != last_flow ) {
      send_probe( it->second );
    }
  }
}

bool Connection::send_probe( Flow *flow )
{
  string empty("");
  Packet px = new_packet( flow, PROBE_FLAG, empty );

  string p = px.tostring( &session );

  log_dbg( LOG_DEBUG_COMMON, "Sending probe on %d seq %llu (%s -> %s, SRTT = %dms): ",
	   (int)flow->flow_id, (long long unsigned)flow->next_seq - 1,
	   flow->src.tostring().c_str(), flow->dst.tostring().c_str(), (int)flow->SRTT );

  ssize_t bytes_sent = sendfromto( flow->dst.sa.sa_family == AF_INET ? sock() : sock6(),
				   p.data(), p.size(), MSG_DONTWAIT, flow->src, flow->dst );
  if ( bytes_sent < 0 ) {
    flow->SRTT = MIN( flow->SRTT + 1000, 10000);
    log_dbg( LOG_PERROR, "failed (SRTT = %dms)", (int)flow->SRTT );
  } else {
    log_dbg( LOG_DEBUG_COMMON, "success.\n" );
  }

  return ( bytes_sent != static_cast<ssize_t>( p.size() ) );
}

void Connection::send_addresses( void )
{
  assert( server );
  string payload;
  std::vector< Addr > addresses = host_addresses.get_host_addresses( NULL );
  for ( std::vector< Addr >::const_iterator la_it = addresses.begin();
	la_it != addresses.end();
	la_it++ ) {
    uint8_t len;
    uint8_t family;
    uint16_t port = htons( socks.back().port );
    string addr;
    int addrlen;
    /* Set our listening port. */
    if ( la_it->sa.sa_family == AF_INET ) {
      addrlen = 4;
      family = 4; /* AF_INET6 is not standard. */
      addr = string( (char *) &la_it->sin.sin_addr, 4 );
    } else if ( la_it->sa.sa_family == AF_INET6 ) {
      addrlen = 16;
      family = 6;
      addr = string( (char *) &la_it->sin6.sin6_addr, 16 );
    } else {
      continue;
    }
    len = 1 + 2 + addrlen; /* "len" is not considered */
    log_dbg( LOG_DEBUG_COMMON, "Sending my address: %s.\n", la_it->tostring().c_str() );
    payload += string( (char *) &len, 1 ) +
      string( (char *) &family, 1 ) +
      string( (char *) &port, 2 ) +
      addr;
  }
  send( ADDR_FLAG, payload );
}

ssize_t Connection::sendfromto( int sock, const char *buffer, size_t size, int flags, Addr from, Addr to )
{
  struct msghdr msghdr;
  struct cmsghdr *cmsghdr;
  struct iovec iov;
  char cmsg[256];
  const int family = to.sa.sa_family;

  iov.iov_base = (void*) buffer;
  iov.iov_len = size;

  memset( &msghdr, 0, sizeof( msghdr ) );
  msghdr.msg_iov = &iov;
  msghdr.msg_iovlen = 1;
  msghdr.msg_name = (void*) &to.sa;
  msghdr.msg_namelen = to.addrlen;
  msghdr.msg_control = cmsg;
  msghdr.msg_controllen = 0;

  /* fill message control */
  cmsghdr = (struct cmsghdr *)cmsg;
  memset( cmsghdr, 0, sizeof( *cmsghdr ) );
  if ( family == AF_INET ) {

#ifdef IP_PKTINFO
    struct in_pktinfo *info;
    cmsghdr->cmsg_level = IPPROTO_IP;
    cmsghdr->cmsg_type = IP_PKTINFO;
    cmsghdr->cmsg_len = CMSG_LEN( sizeof( *info ) );
    info = (struct in_pktinfo *)CMSG_DATA( cmsghdr );
    memset( info, 0, sizeof( *info ) );
    info->ipi_spec_dst = from.sin.sin_addr;
    msghdr.msg_controllen += CMSG_SPACE( sizeof( *info ) );
#elif defined IP_SENDSRCADDR
    struct in_addr *info;
    cmsghdr->cmsg_level = IPPROTO_IP;
    cmsghdr->cmsg_type = IP_SENDSRCADDR;
    cmsghdr->cmsg_len = CMSG_LEN( sizeof( *info ) );
    info = (struct in_addr *)CMSG_DATA( cmsghdr );
    *info = from.sin.sin_addr;
    msghdr.msg_controllen += CMSG_SPACE( sizeof( *info ) );

#else
#warning "Can't choose the source address of outgoing packets."
#endif

  } else if ( family == AF_INET6 ) {
    struct in6_pktinfo *info;
    cmsghdr->cmsg_level = IPPROTO_IPV6;
    cmsghdr->cmsg_type = IPV6_PKTINFO;
    cmsghdr->cmsg_len = CMSG_LEN( sizeof( *info ) );
    info = (struct in6_pktinfo *)CMSG_DATA( cmsghdr );
    memset( info, 0, sizeof( *info ) );
    memcpy( &info->ipi6_addr, &from.sin6.sin6_addr, sizeof( from.sin6.sin6_addr ) );
    msghdr.msg_controllen += CMSG_SPACE( sizeof( *info ) );

  } else {
    assert( false );
  }

  if ( msghdr.msg_controllen == 0 ) {
    msghdr.msg_control = NULL;
  }
  /* send the message ! */
  return sendmsg( sock, &msghdr, flags );
}

void Connection::send( string s )
{
  send( 0, s);
}

void Connection::send( uint16_t flags, string s )
{
  if ( server && !last_flow ) {
    return;
  }

  have_send_exception = true;

  log_dbg( LOG_DEBUG_COMMON, "timestamp = %llu\n", (long long unsigned)timestamp() );

  ssize_t bytes_sent = -1;
  if ( server ) {
    Packet px = new_packet( last_flow, flags, s );

    string p = px.tostring( &session );

    log_dbg( LOG_DEBUG_COMMON, "Sending data on %hu seq %llu (%s -> %s, SRTT = %dms)",
	     last_flow->flow_id, (long long unsigned) last_flow->next_seq - 1, last_flow->src.tostring().c_str(),
	     last_flow->dst.tostring().c_str(), (int)last_flow->SRTT );

    bytes_sent = sendfromto( last_flow->dst.sa.sa_family == AF_INET ? sock() : sock6(),
			     p.data(), p.size(), MSG_DONTWAIT, last_flow->src, last_flow->dst );
    if ( bytes_sent == static_cast<ssize_t>( p.size() ) ) {
      log_dbg( LOG_DEBUG_COMMON, ": success\n" );
      have_send_exception = false;
    } else {
      if ( errno == EADDRNOTAVAIL ) {
	/* This should not append, since we just receive a message on this address ! */
      }
      log_dbg( LOG_PERROR, " failed" );
    }

  } else if ( UNLIKELY( last_flow == NULL ) ) { /* First send. */
    for ( std::map< uint16_t, Flow* >::iterator it = flows.begin();
	  it != flows.end();
	  it++ ) {
      Flow *flow = it->second;
      Packet px = new_packet( flow, flags, s );
      string p = px.tostring( &session );
      log_dbg( LOG_DEBUG_COMMON, "Sending data on %hu seq %llu (%s -> %s, SRTT = %dms)",
	       flow->flow_id, (long long unsigned) flow->next_seq - 1, flow->src.tostring().c_str(),
	       flow->dst.tostring().c_str(), (int)flow->SRTT );
      bytes_sent = sendfromto( flow->dst.sa.sa_family == AF_INET ? sock() : sock6(),
			       p.data(), p.size(), MSG_DONTWAIT, flow->src, flow->dst );
      if ( bytes_sent < 0 ) {
	flow->SRTT = MIN( flow->SRTT + 1000, 10000);
 	log_dbg( LOG_PERROR, " failed" );
      } else if ( bytes_sent == static_cast<ssize_t>( p.size() ) ) {
	have_send_exception = false;
	log_dbg( LOG_DEBUG_COMMON, ": success.\n" );
	last_flow = flow;
      } else {
	log_dbg( LOG_DEBUG_COMMON, ": failed (partial).\n" );
      }
    }

  } else {
    std::vector< std::pair< uint16_t, Flow* > > flows_vect( flows.begin(), flows.end() );
    std::sort( flows_vect.begin(), flows_vect.end(), Flow::srtt_order );
    for ( std::vector< std::pair< uint16_t, Flow* > >::const_iterator it = flows_vect.begin();
	  it != flows_vect.end();
	  it ++ ) {
      Flow *flow = it->second;
      Packet px = new_packet( flow, flags, s );
      string p = px.tostring( &session );
      log_dbg( LOG_DEBUG_COMMON, "Sending data on %hu seq %llu (%s -> %s, SRTT = %dms)",
	       flow->flow_id, (long long unsigned) flow->next_seq - 1, flow->src.tostring().c_str(),
	       flow->dst.tostring().c_str(), (int)flow->SRTT );
      bytes_sent = sendfromto( flow->dst.sa.sa_family == AF_INET ? sock() : sock6(),
			       p.data(), p.size(), MSG_DONTWAIT, flow->src, flow->dst );
      if ( bytes_sent < 0 ) {
	flow->SRTT = MIN( flow->SRTT + 1000, 10000);
      } else if ( bytes_sent == static_cast<ssize_t>( p.size() ) ){
	have_send_exception = false;
	if ( last_flow != flow ) {
	  log_dbg( LOG_DEBUG_COMMON, ": switching from %hu.\n", last_flow->flow_id );
	  last_flow = flow;
	} else {
	  log_dbg( LOG_DEBUG_COMMON, ": success.\n" );
	}
	break;
      } else {
	log_dbg( LOG_DEBUG_COMMON, ": failed (partial).\n" );
      }
    }

    send_probes();
  }

  if ( have_send_exception ) {
    if ( !server ) {
      check_flows( false );
    }
    /* Notify the frontend on sendmsg() failure, but don't alter control flow.
       sendmsg() success is not very meaningful because packets can be lost in
       flight anyway. */
    send_exception = NetworkException( "sendmsg", errno );

    if ( errno == EMSGSIZE ) {
      last_flow->MTU = 500; /* payload MTU of last resort */
    }
  }

  uint64_t now = timestamp();
  if ( server ) {
    if ( now - last_heard > SERVER_ASSOCIATION_TIMEOUT ) {
      last_flow = NULL;
      fprintf( stderr, "Server now detached from client.\n" );
    }
  } else { /* client */
    if ( ( now - last_port_choice > PORT_HOP_INTERVAL )
	 && ( now - last_roundtrip_success > PORT_HOP_INTERVAL ) ) {
      hop_port();
    }
    check_remote_addr();
  }
}

string Connection::recv( void )
{
  assert( !socks.empty() && !socks6.empty() );
  std::deque< Socket >::const_iterator it = socks.begin();
  while ( true ) {
    if ( it == socks.end() ) {
      it = socks6.begin();
      if ( socks6.size() == 0 ) continue;
    } else if ( it == socks6.end() ) {
      break;
    }

    string payload;
    try {
      payload = recv_one( it->fd() );
      prune_sockets();
      return payload;
    } catch ( NetworkException & e ) {
      if ( (e.the_errno != EAGAIN)
	   && (e.the_errno != EWOULDBLOCK) ) {
	throw;
      }
    }
    it++;
  }
  assert( false );
  return "";
}

string Connection::recv_one( int sock_to_recv )
{
  /* receive source address, ECN, and payload in msghdr structure */
  Addr packet_remote_addr; /* == src of the IP packet */
  Addr packet_local_addr;  /* == dst of the IP packet */
  struct msghdr header;
  struct iovec msg_iovec;

  char msg_payload[ Session::RECEIVE_MTU ];
  char msg_control[ Session::RECEIVE_MTU ];

  /* receive source address */
  header.msg_name = &packet_remote_addr.sa;
  header.msg_namelen = packet_remote_addr.addrlen;

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

  ssize_t received_len = recvmsg( sock_to_recv, &header, MSG_DONTWAIT );

  if ( received_len < 0 ) {
    throw NetworkException( "recvmsg", errno );
  }

  if ( header.msg_flags & MSG_TRUNC ) {
    throw NetworkException( "Received oversize datagram", errno );
  }

  /* receive ECN and local address targeted by the packet */
  bool congestion_experienced = false;

  struct cmsghdr *cmsghdr;
  for ( cmsghdr = CMSG_FIRSTHDR( &header ); cmsghdr != NULL; cmsghdr = CMSG_NXTHDR( &header, cmsghdr ) ) {
    if ( cmsghdr->cmsg_level == IPPROTO_IP ) {
      if ( cmsghdr->cmsg_type == IP_TOS ) {
	uint8_t *ecn_octet_p = (uint8_t *)CMSG_DATA( cmsghdr );
	assert( ecn_octet_p );
	if ( (*ecn_octet_p & 0x03) == 0x03 ) {
	  congestion_experienced = true;
	}

#ifdef IP_PKTINFO
      } else if ( cmsghdr->cmsg_type == IP_PKTINFO ) {
	struct in_pktinfo *info = (struct in_pktinfo *)CMSG_DATA( cmsghdr );
	packet_local_addr.sin.sin_addr = info->ipi_addr;
	packet_local_addr.sin.sin_family = AF_INET;
	packet_local_addr.sin.sin_port = socks.back().port;

#elif defined IP_RECVDSTADDR
      } else if ( cmsghdr->cmsg_type == IP_RECVDSTADDR ) {
	struct in_addr *info = (struct in_addr *)CMSG_DATA( cmsghdr );
	packet_local_addr.sin.sin_addr = *info;
	packet_local_addr.sin.sin_family = AF_INET;
	packet_local_addr.sin.sin_port = socks.back().port;

#endif
      }
    } else if ( cmsghdr->cmsg_level == IPPROTO_IPV6 ) {
      if ( cmsghdr->cmsg_type == IPV6_PKTINFO ) {
	struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA( cmsghdr );
	memcpy( &packet_local_addr.sin6.sin6_addr, &info->ipi6_addr, sizeof( struct in6_addr ) );
	packet_local_addr.sa.sa_family = AF_INET6;
	packet_local_addr.sin6.sin6_port = socks6.back().port;
      } else if ( cmsghdr->cmsg_type == IPV6_TCLASS ) {
	uint8_t tclass = *(uint8_t *)CMSG_DATA( cmsghdr );
	if ( (tclass & 0x03) == 0x03 ) {
	  congestion_experienced = true;
	}
      }
    }
  }

  packet_remote_addr.addrlen = header.msg_namelen;

  Packet p( string( msg_payload, received_len ), &session );

  Flow *flow_info = flows[ p.flow_id ];
  log_dbg( LOG_DEBUG_COMMON, "Receiving message on flow %d seq %llu (%s <- %s): ", (int) p.flow_id,
	   (long long unsigned)p.seq, packet_local_addr.tostring().c_str(), packet_remote_addr.tostring().c_str() );
  if ( !flow_info ) {
    fatal_assert( server ); /* if client, then server answers with an unknown flow ID. This is terrific. */
    flow_info = new Flow( packet_local_addr, packet_remote_addr, p.flow_id );
    flows[ p.flow_id ] = flow_info;
  }

  dos_assert( p.direction == (server ? TO_SERVER : TO_CLIENT) ); /* prevent malicious playback to sender */

  if ( p.seq >= flow_info->expected_receiver_seq ) { /* don't use out-of-order packets for timestamp or targeting */
    flow_info->expected_receiver_seq = p.seq + 1; /* this is security-sensitive because a replay attack could otherwise
						     screw up the timestamp and targeting */

    if ( p.timestamp != uint16_t(-1) ) {
      flow_info->saved_timestamp = p.timestamp;
      flow_info->saved_timestamp_received_at = timestamp();

      if ( congestion_experienced ) {
	/* signal counterparty to slow down */
	/* this will gradually slow the counterparty down to the minimum frame rate */
	flow_info->saved_timestamp -= CONGESTION_TIMESTAMP_PENALTY;
	if ( server ) {
	  fprintf( stderr, "Received explicit congestion notification.\n" );
	}
      }
    }

    if ( p.is_probe() ) {
      log_dbg( LOG_DEBUG_COMMON, "probe, " );
    } else {
      log_dbg( LOG_DEBUG_COMMON, "data, " );
    }

    if ( p.timestamp_reply != uint16_t(-1) ) {
      uint16_t now = timestamp16();
      double R = timestamp_diff( now, p.timestamp_reply );

      if ( R < 5000 ) { /* ignore large values, e.g. server was Ctrl-Zed */
	if ( !flow_info->RTT_hit ) { /* first measurement */
	  flow_info->SRTT = R;
	  flow_info->RTTVAR = R / 2;
	  flow_info->RTT_hit = true;
	} else {
	  const double alpha = 1.0 / 8.0;
	  const double beta = 1.0 / 4.0;
	  
	  flow_info->RTTVAR = (1 - beta) * flow_info->RTTVAR + ( beta * fabs( flow_info->SRTT - R ) );
	  flow_info->SRTT = (1 - alpha) * flow_info->SRTT + ( alpha * R );
	}
      }
      log_dbg( LOG_DEBUG_COMMON, "RTT = %ums, SRTT = %ums.\n", (unsigned int)R, (unsigned int)flow_info->SRTT );
    } else {
      log_dbg( LOG_DEBUG_COMMON, "no timestamp reply.\n" );
    }

    /* auto-adjust to remote host */
    last_heard = timestamp();

    if ( server ) { /* only client can roam */
      bool has_roam = last_flow != flow_info;
      if ( p.is_probe() ) {
	if ( UNLIKELY( !last_flow ) ) { /* This should only occurs once. */
	  last_flow = flow_info;
	}
	send_probe( flow_info );
	return p.payload;
      }
      last_flow = flow_info;

      if ( has_roam ) {
	char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
	int errcode = getnameinfo( &last_flow->dst.sa, last_flow->dst.addrlen,
				   host, sizeof( host ), serv, sizeof( serv ),
				   NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
	if ( errcode != 0 ) {
	  throw NetworkException( std::string( "recv_one: getnameinfo: " ) + gai_strerror( errcode ), 0 );
	}
	fprintf( stderr, "Server now attached to client at %s:%s\n",
		 host, serv );
      }
    }
  } else {
    log_dbg( LOG_DEBUG_COMMON, "out-of-order.\n" );
  }

  if ( p.is_addr_msg() ) {
    if ( server ) {
      send_addresses();
      assert( p.payload.empty() );
    } else {
      parse_received_addresses( p.payload );
      check_flows( true );
      p.payload = string("");
    }
  }

  return p.payload; /* we do return out-of-order or duplicated packets to caller */
}

void Connection::parse_received_addresses( string payload )
{
  int size = payload.size();
  const unsigned char *data = (const unsigned char*) payload.data();
  std::vector< Addr > addr;
  while( size > 0 ) {
    int len = (int)data[0];
    if ( size < 1 + len ) {
      log_dbg( LOG_DEBUG_COMMON, "Truncated message received.\n" );
      break;
    }
    Addr tmp;
    uint8_t family = data[1];
    if ( family == 4 ) {
      tmp = Addr( AF_INET );
      memcpy(&tmp.sin.sin_port, data + 2, 2);
      memcpy(&tmp.sin.sin_addr, data + 4, 4);
    } else if ( family == 6 ) {
      tmp = Addr( AF_INET6 );
      memcpy(&tmp.sin6.sin6_port, data + 2, 2);
      memcpy(&tmp.sin6.sin6_addr, data + 4, 16);
    }
    addr.push_back( tmp );
    log_dbg( LOG_DEBUG_COMMON, "Remote address received: %s.\n", tmp.tostring().c_str() );
    data += 1 + len;
    size -= 1 + len;
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
}

std::string Connection::port( void ) const
{
  Addr local_addr;
  socklen_t addrlen = sizeof( local_addr );

  /* Remark that sock && sock6 are bound at the same port number. (server only.) */
  if ( getsockname( sock(), &local_addr.sa, &addrlen ) < 0 ) {
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
  const Flow *flow = last_flow ? last_flow : &Flow::defaults;
  uint64_t RTO = lrint( ceil( flow->SRTT + 4 * flow->RTTVAR ) );
  if ( RTO < MIN_RTO ) {
    RTO = MIN_RTO;
  } else if ( RTO > MAX_RTO ) {
    RTO = MAX_RTO;
  }
  return RTO;
}

Connection::Socket::~Socket()
{
  if ( close( _fd ) < 0 ) {
    throw NetworkException( "close", errno );
  }
}

Connection::Socket::Socket( const Socket & other )
  : _fd( dup( other._fd ) ),
    port( other.port )
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
