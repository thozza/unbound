/*
 * services/listen_dnsport.h - listen on port 53 for incoming DNS queries.
 *
 * Copyright (c) 2007, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file has functions to get queries from clients.
 */

#ifndef LISTEN_DNSPORT_H
#define LISTEN_DNSPORT_H

#include "util/netevent.h"
struct listen_list;
struct config_file;
struct addrinfo;

/**
 * Listening for queries structure.
 * Contains list of query-listen sockets.
 */
struct listen_dnsport {
	/** Base for select calls */
	struct comm_base* base;

	/** buffer shared by UDP connections, since there is only one
	    datagram at any time. */
	ldns_buffer* udp_buff;

	/** list of comm points used to get incoming events */
	struct listen_list* cps;
};

/**
 * Single linked list to store event points.
 */
struct listen_list {
	/** next in list */
	struct listen_list* next;
	/** event info */
	struct comm_point* com;
};

/**
 * type of ports
 */
enum listen_type {
	/** udp type */
	listen_type_udp,
	/** tcp type */
	listen_type_tcp,
	/** udp ipv6 (v4mapped) for use with ancillary data */
	listen_type_udpancil
};

/**
 * Single linked list to store shared ports that have been 
 * opened for use by all threads.
 */
struct listen_port {
	/** next in list */
	struct listen_port* next;
	/** file descriptor, open and ready for use */
	int fd;
	/** type of file descriptor, udp or tcp */
	enum listen_type ftype;
};

/**
 * Create shared listening ports
 * Getaddrinfo, create socket, bind and listen to zero or more 
 * interfaces for IP4 and/or IP6, for UDP and/or TCP.
 * On the given port number. It creates the sockets.
 * @param cfg: settings on what ports to open.
 * @return: linked list of ports or NULL on error.
 */
struct listen_port* listening_ports_open(struct config_file* cfg);

/**
 * Close and delete the (list of) listening ports.
 */
void listening_ports_free(struct listen_port* list);

/**
 * Create commpoints with for this thread for the shared ports.
 * @param base: the comm_base that provides event functionality.
 *	for default all ifs.
 * @param ports: the list of shared ports.
 * @param bufsize: size of datagram buffer.
 * @param tcp_accept_count: max number of simultaneous TCP connections 
 * 	from clients.
 * @param cb: callback function when a request arrives. It is passed
 *	  the packet and user argument. Return true to send a reply.
 * @param cb_arg: user data argument for callback function.
 * @return: the malloced listening structure, ready for use. NULL on error.
 */
struct listen_dnsport* listen_create(struct comm_base* base,
	struct listen_port* ports, size_t bufsize, int tcp_accept_count,
	comm_point_callback_t* cb, void* cb_arg);

/**
 * Stop listening to the dnsports. Ports are still open but not checked
 * for readability - performs pushback of the load.
 * @param listen: the listening structs to stop listening on. Note that
 *    udp and tcp-accept handlers stop, but ongoing tcp-handlers are kept
 *    going, since its rude to 'reset connection by peer' them, instead,
 *    we keep them and the callback will be called when its ready. It can
 *    be dropped at that time. New tcp and udp queries can be served by 
 *    other threads.
 */
void listen_pushback(struct listen_dnsport* listen);

/**
 * Start listening again to the dnsports.
 * Call after the listen_pushback has been called.
 * @param listen: the listening structs to stop listening on.
 */
void listen_resume(struct listen_dnsport* listen);

/**
 * delete the listening structure
 * @param listen: listening structure.
 */
void listen_delete(struct listen_dnsport* listen);

/**
 * delete listen_list of commpoints. Calls commpointdelete() on items.
 * This may close the fds or not depending on flags.
 * @param list: to delete.
 */
void listen_list_delete(struct listen_list* list);

/**
 * get memory size used by the listening structs
 * @param listen: listening structure.
 * @return: size in bytes.
 */
size_t listen_get_mem(struct listen_dnsport* listen);

/**
 * Create and bind nonblocking UDP socket
 * @param family: for socket call.
 * @param socktype: for socket call.
 * @param addr: for bind call.
 * @param addrlen: for bind call.
 * @param v6only: if enabled, IP6 sockets get IP6ONLY option set.
 * 	if enabled with value 2 IP6ONLY option is disabled.
 * @param inuse: on error, this is set true if the port was in use.
 * @param noproto: on error, this is set true if cause is that the
	IPv6 proto (family) is not available.
 * @return: the socket. -1 on error.
 */
int create_udp_sock(int family, int socktype, struct sockaddr* addr, 
	socklen_t addrlen, int v6only, int* inuse, int* noproto);

/**
 * Create and bind TCP listening socket
 * @param addr: address info ready to make socket.
 * @param v6only: enable ip6 only flag on ip6 sockets.
 * @param noproto: if error caused by lack of protocol support.
 * @return: the socket. -1 on error.
 */
int create_tcp_accept_sock(struct addrinfo *addr, int v6only, int* noproto);

#endif /* LISTEN_DNSPORT_H */