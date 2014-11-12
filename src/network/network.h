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

#ifndef NETWORK_HPP
#define NETWORK_HPP

#include <stdint.h>
#include <deque>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include <math.h>
#include <vector>
#include <assert.h>

#include "crypto.h"
#include "addresses.h"

using namespace Crypto;

namespace Network {
  static const unsigned int MOSH_PROTOCOL_VERSION = 2; /* bumped for echo-ack */

  uint64_t timestamp( void );
  uint16_t timestamp16( void );
  uint16_t timestamp_diff( uint16_t tsnew, uint16_t tsold );

  class NetworkException {
  public:
    string function;
    int the_errno;
    NetworkException( string s_function, int s_errno ) : function( s_function ), the_errno( s_errno ) {}
    NetworkException() : function( "<none>" ), the_errno( 0 ) {}
  };

  enum Direction {
    TO_SERVER = 0,
    TO_CLIENT = 1
  };

  class Packet {
  public:
    uint64_t seq;
    Direction direction;
    uint16_t timestamp, timestamp_reply;
    uint16_t flow_id;
    uint16_t flags;
    string payload;
    
    Packet( uint64_t s_seq, Direction s_direction,
	    uint16_t s_timestamp, uint16_t s_timestamp_reply,
            uint16_t s_flow_id, uint16_t s_flags, string s_payload )
      : seq( s_seq ), direction( s_direction ),
	timestamp( s_timestamp ), timestamp_reply( s_timestamp_reply ),
        flow_id( s_flow_id ), flags( s_flags ), payload( s_payload )
    {}
    
    Packet( string coded_packet, Session *session );
    
    bool is_probe( void );
    bool is_addr_msg( void );
    string tostring( Session *session );
  };

  class Connection {
  private:
    static const int DEFAULT_SEND_MTU = 1300;
    static const uint64_t MIN_RTO = 50; /* ms */
    static const uint64_t MAX_RTO = 1000; /* ms */

    static const int PORT_RANGE_LOW  = 60001;
    static const int PORT_RANGE_HIGH = 60999;

    static const unsigned int SERVER_ASSOCIATION_TIMEOUT = 40000;
    static const unsigned int PORT_HOP_INTERVAL          = 10000;
    static const unsigned int MAX_ADDR_REQUEST_INTERVAL  = 10000;

    static const unsigned int MAX_PORTS_OPEN             = 10;
    static const unsigned int MAX_OLD_SOCKET_AGE         = 60000;

    static const int CONGESTION_TIMESTAMP_PENALTY = 500; /* ms */

    class Flow {
    private:
      static uint16_t next_flow_id;
      Flow( void )
	: src( Addr() ), dst( Addr() ), MTU( DEFAULT_SEND_MTU ), next_seq( 0 ),
	expected_receiver_seq( 0 ), saved_timestamp( -1 ), saved_timestamp_received_at( 0 ),
	RTT_hit( false ), SRTT( 1000 ), RTTVAR( 500 ), flow_id( 0 )
      {}

    public:
      static const Flow defaults; /* for default values only */
      Addr src;
      Addr dst;
      int MTU;
      uint64_t next_seq;
      uint64_t expected_receiver_seq;
      uint16_t saved_timestamp;
      uint64_t saved_timestamp_received_at;
      bool RTT_hit;
      double SRTT;
      double RTTVAR;
      const uint16_t flow_id;

      static bool srtt_order( std::pair< uint16_t, Flow* > const &f1,
			      std::pair< uint16_t, Flow* > const &f2 ) {
	return f1.second->SRTT < f2.second->SRTT;
      }

      Flow( const Addr &src, const Addr &dst ); /* client only */
      Flow( const Addr &src, const Addr &dst, uint16_t id ); /* server only */
    };

    class Socket
    {
    private:
      int _fd;

    public:
      int port; /* host byte order */
      int fd( void ) const { return _fd; }
      bool try_bind( int sock, Addr addrToBind, int port_low, int port_high );

      Socket( int family, int lower_port, int higher_port );
      ~Socket();

      Socket( const Socket & other );
      Socket & operator=( const Socket & other );
    };

    std::deque< Socket > socks;
    std::deque< Socket > socks6;
    bool has_remote_addr;
    std::vector< Addr > remote_addr;
    std::vector< Addr > received_remote_addr;
    std::map< uint16_t, Flow* > flows; /* do NEVER remove flows when server, for security reason. */
    Flow *last_flow;
    Addresses host_addresses;

    bool server;

    Base64Key key;
    Session session;

    void setup( void );

    Direction direction;

    uint64_t last_heard;
    uint64_t last_port_choice;
    uint64_t last_addr_request;
    uint64_t last_roundtrip_success; /* transport layer needs to tell us this */

    /* Exception from send(), to be delivered if the frontend asks for it,
       without altering control flow. */
    bool have_send_exception;
    NetworkException send_exception;

    Packet new_packet( Flow *flow, uint16_t flags, string &s_payload );

    void hop_port( void );
    void check_remote_addr( void );
    bool flow_exists( const Addr &src, const Addr &dst );
    void check_flows( bool remote_has_changed );

    int sock( void ) const { assert( !socks.empty() ); return socks.back().fd(); }
    int sock6( void ) const { assert( !socks6.empty() ); return socks6.back().fd(); }

    void prune_sockets( void );
    void prune_sockets( std::deque< Socket > &socks_vect );

    void send( uint16_t flags, string s );
    void send_probes( void );
    bool send_probe( Flow *flow );
    void send_addresses( void );
    ssize_t sendfromto( int sock, const char *buffer, size_t size, int flags, Addr from, Addr to );
    string recv_one( int sock_to_recv );
    void parse_received_addresses( string payload );

  public:
    Connection( const char *desired_ip, const char *desired_port ); /* server */
    Connection( const char *key_str, const char *ip, const char *port ); /* client */

    void send( string s );
    string recv( void );
    const std::vector< int > fds( void ) const;
    int get_MTU( void ) const { return last_flow ? last_flow->MTU : DEFAULT_SEND_MTU; }

    std::string port( void ) const;
    string get_key( void ) const { return key.printable_key(); }
    bool get_has_remote_addr( void ) const { return has_remote_addr; }

    uint64_t timeout( void ) const;
    double get_SRTT( void ) const { return last_flow ? last_flow->SRTT : 1000; }

    const Addr &get_remote_addr( void ) const { return last_flow ? last_flow->dst : remote_addr.back(); }
    socklen_t get_remote_addr_len( void ) const { return last_flow ? last_flow->dst.addrlen : 0; }

    const NetworkException *get_send_exception( void ) const
    {
      return have_send_exception ? &send_exception : NULL;
    }

    void set_last_roundtrip_success( uint64_t s_success ) { last_roundtrip_success = s_success; }

    static bool parse_portrange( const char * desired_port_range, int & desired_port_low, int & desired_port_high );
  };
}

#endif
