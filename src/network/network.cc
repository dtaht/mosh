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

  setup();

  assert( remote_addr.addrlen != 0 );
  socks.push_back( Socket() );

  prune_sockets();
}

void Connection::prune_sockets( void )
{
  /* don't keep old sockets if the new socket has been working for long enough */
  if ( socks.size() > 1 ) {
    if ( timestamp() - last_port_choice > MAX_OLD_SOCKET_AGE ) {
      int num_to_kill = socks.size() - 1;
      for ( int i = 0; i < num_to_kill; i++ ) {
	socks.pop_front();
      }
    }
  } else {
    return;
  }

  /* make sure we don't have too many receive sockets open */
  if ( socks.size() > MAX_PORTS_OPEN ) {
    int num_to_kill = socks.size() - MAX_PORTS_OPEN;
    for ( int i = 0; i < num_to_kill; i++ ) {
      socks.pop_front();
    }
  }
}

uint16_t Connection::Flow::next_flow_id = 0;
const Connection::Flow Connection::Flow::defaults = Flow( true );

Connection::Flow::Flow( void )
  : MTU( defaults.MTU ),
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

Connection::Socket::Socket( void )
  : _fd( socket( PF_INET6, SOCK_DGRAM, 0 ) )
{
  if ( _fd < 0 ) {
    throw NetworkException( "socket", errno );
  }

  const int on = 1;
  const int off = 0;

  /* Hybrid socket. */
  if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof( off ) ) < 0 ) {
    throw NetworkException( "setsockopt( IPV6_V6ONLY off )", errno );
  }

#ifdef HAVE_IPV6_MTU_DISCOVER
  /* Disable path MTU discovery */
  char flag = IPV6_PMTUDISC_DONT;
  socklen_t optlen = sizeof( flag );
  if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &flag, optlen ) < 0 ) {
    throw NetworkException( "setsockopt( MTU_DISCOVER don't )", errno );
  }
#endif

  /* request explicit congestion notification on received datagrams */
  if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_RECVTCLASS, &on, sizeof( on ) ) < 0 ) {
    perror( "setsockopt( IPV6_RECVTCLASS on )" );
  }

  /* Tell me on which address the msg has been received. */
  if ( setsockopt( _fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof( on ) ) ) {
    perror( "setsockopt( IPV6_RECVPKTINFO on )" );
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
    has_remote_addr( false ),
    remote_addr(),
    flows(),
    last_flow_key( Addr(), Addr() ),
    last_flow( NULL ),
    server( true ),
    key(),
    session( key ),
    direction( TO_CLIENT ),
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

  /* We ignore the IP provided, because anyway, we bind to a hybrid (dual-stack)
     socket.  The problem with multihomed server is solved by sending back
     packets answering with the last known local IP used to receive a packet.
     If a port request is given, we bind only to that port. */

  /* convert port numbers */
  int desired_port_low = 0;
  int desired_port_high = 0;

  if ( desired_port && !parse_portrange( desired_port, desired_port_low, desired_port_high ) ) {
    throw NetworkException("Invalid port range", 0);
  }

  /* try any local interface */
  try {
    if ( try_bind( desired_port_low, desired_port_high ) ) { return; }
  } catch ( const NetworkException& e ) {
    fprintf( stderr, "Error binding to any interface: %s: %s\n",
	     e.function.c_str(), strerror( e.the_errno ) );
    throw; /* this time it's fatal */
  }

  assert( false );
  throw NetworkException( "Could not bind", errno );
}

bool Connection::try_bind( int port_low, int port_high )
{
  Addr local_addr( AF_INET6 );

  int search_low = PORT_RANGE_LOW, search_high = PORT_RANGE_HIGH;

  if ( port_low != 0 ) { /* low port preference */
    search_low = port_low;
  }
  if ( port_high != 0 ) { /* high port preference */
    search_high = port_high;
  }

  socks.push_back( Socket() );
  for ( int i = search_low; i <= search_high; i++ ) {
    local_addr.sin6.sin6_port = htons( i );

    if ( bind( sock(), &local_addr.sa, local_addr.addrlen ) == 0 ) {
      return true;
    } else if ( i == search_high ) { /* last port to search */
      int saved_errno = errno;
      socks.pop_back();
      char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
      int errcode = getnameinfo( &local_addr.sa, local_addr.addrlen,
				 host, sizeof( host ), serv, sizeof( serv ),
				 NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
      if ( errcode != 0 ) {
	throw NetworkException( std::string( "bind: getnameinfo: " ) + gai_strerror( errcode ), 0 );
      }
      fprintf( stderr, "Failed binding to %s:%s\n",
	       host, serv );
      throw NetworkException( "bind", saved_errno );
    }
  }

  assert( false );
  return false;
}

Connection::Connection( const char *key_str, const char *ip, const char *port ) /* client */
  : socks(),
    has_remote_addr( false ),
    remote_addr(),
    flows(),
    last_flow_key( Addr(), Addr() ),
    last_flow( NULL ),
    server( false ),
    key( key_str ),
    session( key ),
    direction( TO_SERVER ),
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
  fatal_assert( ai.res->ai_addrlen <= sizeof( remote_addr ) );
  remote_addr.addrlen = ai.res->ai_addrlen;
  memcpy( &remote_addr.sa, ai.res->ai_addr, remote_addr.addrlen );

  has_remote_addr = true;

  last_flow_key = flow_key( Addr(), remote_addr );
  last_flow = new Flow();
  flows[ last_flow_key ] = last_flow;

  socks.push_back( Socket() );
}

ssize_t Connection::sendfromto( int sock, const char *buffer, size_t size, int flags, const Addr &from, const Addr &to )
{
  struct msghdr msghdr;
  struct cmsghdr *cmsghdr;
  struct in6_pktinfo *info;
  struct iovec iov;
  char cmsg[256];

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
  cmsghdr->cmsg_level = IPPROTO_IPV6;
  cmsghdr->cmsg_type = IPV6_PKTINFO;
  cmsghdr->cmsg_len = CMSG_LEN( sizeof( *info ) );
  info = (struct in6_pktinfo *)CMSG_DATA( cmsghdr );
  memset( info, 0, sizeof( *info ) );
  memcpy( &info->ipi6_addr, &from.sin6.sin6_addr, sizeof( from.sin6.sin6_addr ) );
  msghdr.msg_controllen += CMSG_SPACE( sizeof( *info ) );

  /* send the message ! */
  return sendmsg( sock, &msghdr, flags );
}

void Connection::send( string s )
{
  if ( !has_remote_addr ) {
    return;
  }

  Packet px = new_packet( last_flow, 0, s );

  string p = px.tostring( &session );

  ssize_t bytes_sent = sendto( sock(), p.data(), p.size(), MSG_DONTWAIT,
			       &remote_addr.sa, remote_addr.addrlen );

  if ( bytes_sent == static_cast<ssize_t>( p.size() ) ) {
    have_send_exception = false;
  } else {
    /* Notify the frontend on sendto() failure, but don't alter control flow.
       sendto() success is not very meaningful because packets can be lost in
       flight anyway. */
    have_send_exception = true;
    send_exception = NetworkException( "sendto", errno );

    if ( errno == EMSGSIZE ) {
      last_flow->MTU = 500; /* payload MTU of last resort */
    }
  }

  uint64_t now = timestamp();
  if ( server ) {
    if ( now - last_heard > SERVER_ASSOCIATION_TIMEOUT ) {
      has_remote_addr = false;
      fprintf( stderr, "Server now detached from client.\n" );
    }
  } else { /* client */
    if ( ( now - last_port_choice > PORT_HOP_INTERVAL )
	 && ( now - last_roundtrip_success > PORT_HOP_INTERVAL ) ) {
      hop_port();
    }
  }
}

string Connection::recv( void )
{
  assert( !socks.empty() );
  for ( std::deque< Socket >::const_iterator it = socks.begin();
	it != socks.end();
	it++ ) {
    bool islast = (it + 1) == socks.end();
    string payload;
    try {
      payload = recv_one( it->fd(), !islast );
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

string Connection::recv_one( int sock_to_recv, bool nonblocking )
{
  /* receive source address, ECN, and payload in msghdr structure */
  Addr packet_remote_addr;
  Addr packet_local_addr;
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

  ssize_t received_len = recvmsg( sock_to_recv, &header, nonblocking ? MSG_DONTWAIT : 0 );

  if ( received_len < 0 ) {
    throw NetworkException( "recvmsg", errno );
  }

  if ( header.msg_flags & MSG_TRUNC ) {
    throw NetworkException( "Received oversize datagram", errno );
  }

  packet_remote_addr.addrlen = header.msg_namelen;

  /* receive ECN and local address targeted by the packet */
  bool congestion_experienced = false;

  struct cmsghdr *cmsghdr;
  for ( cmsghdr = CMSG_FIRSTHDR( &header ); cmsghdr != NULL; cmsghdr = CMSG_NXTHDR( &header, cmsghdr ) ) {
    if ( (cmsghdr->cmsg_level == IPPROTO_IP)
	 && (cmsghdr->cmsg_type == IP_TOS) ) {
      uint8_t *ecn_octet_p = (uint8_t *)CMSG_DATA( cmsghdr );
      assert( ecn_octet_p );

      if ( (*ecn_octet_p & 0x03) == 0x03 ) {
	congestion_experienced = true;
      }

    } else if ( cmsghdr->cmsg_level == IPPROTO_IPV6 ) {
      if ( cmsghdr->cmsg_type == IPV6_PKTINFO ) {
	struct in6_pktinfo *info = (struct in6_pktinfo *)CMSG_DATA( cmsghdr );
	memcpy( &packet_local_addr.sin6.sin6_addr, &info->ipi6_addr, sizeof( struct in6_addr ) );
	packet_local_addr.sa.sa_family = AF_INET6;
      } else if ( cmsghdr->cmsg_type == IPV6_TCLASS ) {
	uint8_t tclass = *(uint8_t *)CMSG_DATA( cmsghdr );
	if ( (tclass & 0x03) == 0x03 ) {
	  congestion_experienced = true;
	}
      }
    }
  }

  Packet p( string( msg_payload, received_len ), &session );

  dos_assert( p.direction == (server ? TO_SERVER : TO_CLIENT) ); /* prevent malicious playback to sender */

  if ( p.seq >= last_flow->expected_receiver_seq ) { /* don't use out-of-order packets for timestamp or targeting */
    last_flow->expected_receiver_seq = p.seq + 1; /* this is security-sensitive because a replay attack could otherwise
						     screw up the timestamp and targeting */

    if ( p.timestamp != uint16_t(-1) ) {
      last_flow->saved_timestamp = p.timestamp;
      last_flow->saved_timestamp_received_at = timestamp();

      if ( congestion_experienced ) {
	/* signal counterparty to slow down */
	/* this will gradually slow the counterparty down to the minimum frame rate */
	last_flow->saved_timestamp -= CONGESTION_TIMESTAMP_PENALTY;
	if ( server ) {
	  fprintf( stderr, "Received explicit congestion notification.\n" );
	}
      }
    }

    if ( p.timestamp_reply != uint16_t(-1) ) {
      uint16_t now = timestamp16();
      double R = timestamp_diff( now, p.timestamp_reply );

      if ( R < 5000 ) { /* ignore large values, e.g. server was Ctrl-Zed */
	if ( !last_flow->RTT_hit ) { /* first measurement */
	  last_flow->SRTT = R;
	  last_flow->RTTVAR = R / 2;
	  last_flow->RTT_hit = true;
	} else {
	  const double alpha = 1.0 / 8.0;
	  const double beta = 1.0 / 4.0;
	  
	  last_flow->RTTVAR = (1 - beta) * last_flow->RTTVAR + ( beta * fabs( last_flow->SRTT - R ) );
	  last_flow->SRTT = (1 - alpha) * last_flow->SRTT + ( alpha * R );
	}
      }
    }

    /* auto-adjust to remote host */
    has_remote_addr = true;
    last_heard = timestamp();

    if ( server ) { /* only client can roam */
      last_flow_key = flow_key( packet_local_addr, packet_remote_addr );

      if ( (socklen_t)remote_addr.addrlen != header.msg_namelen ||
	   memcmp( &remote_addr, &packet_remote_addr, remote_addr.addrlen ) != 0 ) {
	remote_addr = packet_remote_addr;
	char host[ NI_MAXHOST ], serv[ NI_MAXSERV ];
	int errcode = getnameinfo( &remote_addr.sa, remote_addr.addrlen,
				   host, sizeof( host ), serv, sizeof( serv ),
				   NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV );
	if ( errcode != 0 ) {
	  throw NetworkException( std::string( "recv_one: getnameinfo: " ) + gai_strerror( errcode ), 0 );
	}
	fprintf( stderr, "Server now attached to client at %s:%s\n",
		 host, serv );
      }
    }
  }

  return p.payload; /* we do return out-of-order or duplicated packets to caller */
}

std::string Connection::port( void ) const
{
  Addr local_addr;
  socklen_t addrlen = sizeof( local_addr );

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
