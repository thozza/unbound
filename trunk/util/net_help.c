/*
 * util/net_help.c - implementation of the network helper code
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
 * Implementation of net_help.h.
 */

#include "config.h"
#include "util/net_help.h"
#include "util/log.h"
#include "util/data/dname.h"
#include "util/module.h"
#include "util/regional.h"
#include <fcntl.h>

/** max length of an IP address (the address portion) that we allow */
#define MAX_ADDR_STRLEN 128 /* characters */

/* returns true is string addr is an ip6 specced address */
int
str_is_ip6(const char* str)
{
	if(strchr(str, ':'))
		return 1;
	else    return 0;
}

int 
write_socket(int s, const void *buf, size_t size)
{
	const char* data = (const char*)buf;
	size_t total_count = 0;

	fd_set_block(s);
	while (total_count < size) {
		ssize_t count
			= write(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				fd_set_nonblock(s);
				return 0;
			} else {
				continue;
			}
		}
		total_count += count;
	}
	fd_set_nonblock(s);
	return 1;
}

int 
fd_set_nonblock(int s) 
{
#ifdef HAVE_FCNTL
	int flag;
	if((flag = fcntl(s, F_GETFL)) == -1) {
		log_err("can't fcntl F_GETFL: %s", strerror(errno));
		flag = 0;
	}
	flag |= O_NONBLOCK;
	if(fcntl(s, F_SETFL, flag) == -1) {
		log_err("can't fcntl F_SETFL: %s", strerror(errno));
		return 0;
	}
#elif defined(HAVE_IOCTLSOCKET)
	unsigned long on = 1;
	if(ioctlsocket(s, FIONBIO, &on) != 0) {
		log_err("can't ioctlsocket FIONBIO on: %s", 
			wsa_strerror(WSAGetLastError()));
	}
#endif
	return 1;
}

int 
fd_set_block(int s) 
{
#ifdef HAVE_FCNTL
	int flag;
	if((flag = fcntl(s, F_GETFL)) == -1) {
		log_err("cannot fcntl F_GETFL: %s", strerror(errno));
		flag = 0;
	}
	flag &= ~O_NONBLOCK;
	if(fcntl(s, F_SETFL, flag) == -1) {
		log_err("cannot fcntl F_SETFL: %s", strerror(errno));
		return 0;
	}
#elif defined(HAVE_IOCTLSOCKET)
	unsigned long off = 0;
	if(ioctlsocket(s, FIONBIO, &off) != 0) {
		log_err("can't ioctlsocket FIONBIO off: %s", 
			wsa_strerror(WSAGetLastError()));
	}
#endif	
	return 1;
}

int 
is_pow2(size_t num)
{
	if(num == 0) return 1;
	return (num & (num-1)) == 0;
}

void* 
memdup(void* data, size_t len)
{
	void* d;
	if(!data) return NULL;
	if(len == 0) return NULL;
	d = malloc(len);
	if(!d) return NULL;
	memcpy(d, data, len);
	return d;
}

void
log_addr(enum verbosity_value v, const char* str, 
	struct sockaddr_storage* addr, socklen_t addrlen)
{
	uint16_t port;
	const char* family = "unknown";
	char dest[100];
	int af = (int)((struct sockaddr_in*)addr)->sin_family;
	void* sinaddr = &((struct sockaddr_in*)addr)->sin_addr;
	if(verbosity < v)
		return;
	switch(af) {
		case AF_INET: family="ip4"; break;
		case AF_INET6: family="ip6";
			sinaddr = &((struct sockaddr_in6*)addr)->sin6_addr;
			break;
		case AF_UNIX: family="unix"; break;
		default: break;
	}
	if(inet_ntop(af, sinaddr, dest, (socklen_t)sizeof(dest)) == 0) {
		strncpy(dest, "(inet_ntop error)", sizeof(dest));
	}
	dest[sizeof(dest)-1] = 0;
	port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	if(verbosity >= 4)
		verbose(v, "%s %s %s port %d (len %d)", str, family, dest, 
			(int)port, (int)addrlen);
	else	verbose(v, "%s %s port %d", str, dest, (int)port);
}

int 
extstrtoaddr(const char* str, struct sockaddr_storage* addr,
	socklen_t* addrlen)
{
	char* s;
	int port = UNBOUND_DNS_PORT;
	if((s=strchr(str, '@'))) {
		char buf[MAX_ADDR_STRLEN];
		if(s-str >= MAX_ADDR_STRLEN) {
			return 0;
		}
		strncpy(buf, str, MAX_ADDR_STRLEN);
		buf[s-str] = 0;
		port = atoi(s+1);
		if(port == 0 && strcmp(s+1,"0")!=0) {
			return 0;
		}
		return ipstrtoaddr(buf, port, addr, addrlen);
	}
	return ipstrtoaddr(str, port, addr, addrlen);
}


int 
ipstrtoaddr(const char* ip, int port, struct sockaddr_storage* addr,
	socklen_t* addrlen)
{
	uint16_t p;
	if(!ip) return 0;
	p = (uint16_t) port;
	if(str_is_ip6(ip)) {
		struct sockaddr_in6* sa = (struct sockaddr_in6*)addr;
		*addrlen = (socklen_t)sizeof(struct sockaddr_in6);
		memset(sa, 0, *addrlen);
		sa->sin6_family = AF_INET6;
		sa->sin6_port = (in_port_t)htons(p);
		if(inet_pton((int)sa->sin6_family, ip, &sa->sin6_addr) <= 0) {
			return 0;
		}
	} else { /* ip4 */
		struct sockaddr_in* sa = (struct sockaddr_in*)addr;
		*addrlen = (socklen_t)sizeof(struct sockaddr_in);
		memset(sa, 0, *addrlen);
		sa->sin_family = AF_INET;
		sa->sin_port = (in_port_t)htons(p);
		if(inet_pton((int)sa->sin_family, ip, &sa->sin_addr) <= 0) {
			return 0;
		}
	}
	return 1;
}

int netblockstrtoaddr(const char* str, int port, struct sockaddr_storage* addr,
        socklen_t* addrlen, int* net)
{
	char* s = NULL;
	*net = (str_is_ip6(str)?128:32);
	if((s=strchr(str, '/'))) {
		if(atoi(s+1) > *net) {
			log_err("netblock too large: %s", str);
			return 0;
		}
		*net = atoi(s+1);
		if(*net == 0 && strcmp(s+1, "0") != 0) {
			log_err("cannot parse netblock: '%s'", str);
			return 0;
		}
		if(!(s = strdup(str))) {
			log_err("out of memory");
			return 0;
		}
		*strchr(s, '/') = '\0';
	}
	if(!ipstrtoaddr(s?s:str, port, addr, addrlen)) {
		free(s);
		log_err("cannot parse ip address: '%s'", str);
		return 0;
	}
	if(s) {
		free(s);
		addr_mask(addr, *addrlen, *net);
	}
	return 1;
}

void
log_nametypeclass(enum verbosity_value v, const char* str, uint8_t* name, 
	uint16_t type, uint16_t dclass)
{
	char buf[LDNS_MAX_DOMAINLEN+1];
	char t[12], c[12];
	const char *ts, *cs; 
	if(verbosity < v)
		return;
	dname_str(name, buf);
	if(type == LDNS_RR_TYPE_TSIG) ts = "TSIG";
	else if(type == LDNS_RR_TYPE_IXFR) ts = "IXFR";
	else if(type == LDNS_RR_TYPE_AXFR) ts = "AXFR";
	else if(type == LDNS_RR_TYPE_MAILB) ts = "MAILB";
	else if(type == LDNS_RR_TYPE_MAILA) ts = "MAILA";
	else if(type == LDNS_RR_TYPE_ANY) ts = "ANY";
	else if(ldns_rr_descript(type) && ldns_rr_descript(type)->_name)
		ts = ldns_rr_descript(type)->_name;
	else {
		snprintf(t, sizeof(t), "TYPE%d", (int)type);
		ts = t;
	}
	if(ldns_lookup_by_id(ldns_rr_classes, (int)dclass) &&
		ldns_lookup_by_id(ldns_rr_classes, (int)dclass)->name)
		cs = ldns_lookup_by_id(ldns_rr_classes, (int)dclass)->name;
	else {
		snprintf(c, sizeof(c), "CLASS%d", (int)dclass);
		cs = c;
	}
	log_info("%s <%s %s %s>", str, buf, ts, cs);
}

void log_name_addr(enum verbosity_value v, const char* str, uint8_t* zone, 
	struct sockaddr_storage* addr, socklen_t addrlen)
{
	uint16_t port;
	const char* family = "unknown_family ";
	char namebuf[LDNS_MAX_DOMAINLEN+1];
	char dest[100];
	int af = (int)((struct sockaddr_in*)addr)->sin_family;
	void* sinaddr = &((struct sockaddr_in*)addr)->sin_addr;
	if(verbosity < v)
		return;
	switch(af) {
		case AF_INET: family=""; break;
		case AF_INET6: family="";
			sinaddr = &((struct sockaddr_in6*)addr)->sin6_addr;
			break;
		case AF_UNIX: family="unix_family "; break;
		default: break;
	}
	if(inet_ntop(af, sinaddr, dest, (socklen_t)sizeof(dest)) == 0) {
		strncpy(dest, "(inet_ntop error)", sizeof(dest));
	}
	dest[sizeof(dest)-1] = 0;
	port = ntohs(((struct sockaddr_in*)addr)->sin_port);
	dname_str(zone, namebuf);
	if(af != AF_INET && af != AF_INET6)
		verbose(v, "%s <%s> %s%s#%d (addrlen %d)",
			str, namebuf, family, dest, (int)port, (int)addrlen);
	else	verbose(v, "%s <%s> %s%s#%d",
			str, namebuf, family, dest, (int)port);
}

int
sockaddr_cmp(struct sockaddr_storage* addr1, socklen_t len1, 
	struct sockaddr_storage* addr2, socklen_t len2)
{
	struct sockaddr_in* p1_in = (struct sockaddr_in*)addr1;
	struct sockaddr_in* p2_in = (struct sockaddr_in*)addr2;
	struct sockaddr_in6* p1_in6 = (struct sockaddr_in6*)addr1;
	struct sockaddr_in6* p2_in6 = (struct sockaddr_in6*)addr2;
	if(len1 < len2)
		return -1;
	if(len1 > len2)
		return 1;
	log_assert(len1 == len2);
	if( p1_in->sin_family < p2_in->sin_family)
		return -1;
	if( p1_in->sin_family > p2_in->sin_family)
		return 1;
	log_assert( p1_in->sin_family == p2_in->sin_family );
	/* compare ip4 */
	if( p1_in->sin_family == AF_INET ) {
		/* just order it, ntohs not required */
		if(p1_in->sin_port < p2_in->sin_port)
			return -1;
		if(p1_in->sin_port > p2_in->sin_port)
			return 1;
		log_assert(p1_in->sin_port == p2_in->sin_port);
		return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
	} else if (p1_in6->sin6_family == AF_INET6) {
		/* just order it, ntohs not required */
		if(p1_in6->sin6_port < p2_in6->sin6_port)
			return -1;
		if(p1_in6->sin6_port > p2_in6->sin6_port)
			return 1;
		log_assert(p1_in6->sin6_port == p2_in6->sin6_port);
		return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr, 
			INET6_SIZE);
	} else {
		/* eek unknown type, perform this comparison for sanity. */
		return memcmp(addr1, addr2, len1);
	}
}

int
sockaddr_cmp_addr(struct sockaddr_storage* addr1, socklen_t len1, 
	struct sockaddr_storage* addr2, socklen_t len2)
{
	struct sockaddr_in* p1_in = (struct sockaddr_in*)addr1;
	struct sockaddr_in* p2_in = (struct sockaddr_in*)addr2;
	struct sockaddr_in6* p1_in6 = (struct sockaddr_in6*)addr1;
	struct sockaddr_in6* p2_in6 = (struct sockaddr_in6*)addr2;
	if(len1 < len2)
		return -1;
	if(len1 > len2)
		return 1;
	log_assert(len1 == len2);
	if( p1_in->sin_family < p2_in->sin_family)
		return -1;
	if( p1_in->sin_family > p2_in->sin_family)
		return 1;
	log_assert( p1_in->sin_family == p2_in->sin_family );
	/* compare ip4 */
	if( p1_in->sin_family == AF_INET ) {
		return memcmp(&p1_in->sin_addr, &p2_in->sin_addr, INET_SIZE);
	} else if (p1_in6->sin6_family == AF_INET6) {
		return memcmp(&p1_in6->sin6_addr, &p2_in6->sin6_addr, 
			INET6_SIZE);
	} else {
		/* eek unknown type, perform this comparison for sanity. */
		return memcmp(addr1, addr2, len1);
	}
}

int
addr_is_ip6(struct sockaddr_storage* addr, socklen_t len)
{
	if(len == (socklen_t)sizeof(struct sockaddr_in6) &&
		((struct sockaddr_in6*)addr)->sin6_family == AF_INET6)
		return 1;
	else    return 0;
}

void
addr_mask(struct sockaddr_storage* addr, socklen_t len, int net)
{
	uint8_t mask[8] = {0x0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe};
	int i, max;
	uint8_t* s;
	if(addr_is_ip6(addr, len)) {
		s = (uint8_t*)&((struct sockaddr_in6*)addr)->sin6_addr;
		max = 128;
	} else {
		s = (uint8_t*)&((struct sockaddr_in*)addr)->sin_addr;
		max = 32;
	}
	if(net >= max)
		return;
	for(i=net/8+1; i<max/8; i++) {
		s[i] = 0;
	}
	s[net/8] &= mask[net&0x7];
}

int
addr_in_common(struct sockaddr_storage* addr1, int net1,
	struct sockaddr_storage* addr2, int net2, socklen_t addrlen)
{
	int min = (net1<net2)?net1:net2;
	int i, to;
	int match = 0;
	uint8_t* s1, *s2;
	if(addr_is_ip6(addr1, addrlen)) {
		s1 = (uint8_t*)&((struct sockaddr_in6*)addr1)->sin6_addr;
		s2 = (uint8_t*)&((struct sockaddr_in6*)addr2)->sin6_addr;
		to = 16;
	} else {
		s1 = (uint8_t*)&((struct sockaddr_in*)addr1)->sin_addr;
		s2 = (uint8_t*)&((struct sockaddr_in*)addr2)->sin_addr;
		to = 4;
	}
	/* match = bits_in_common(s1, s2, to); */
	for(i=0; i<to; i++) {
		if(s1[i] == s2[i]) {
			match += 8;
		} else {
			uint8_t z = s1[i]^s2[i];
			log_assert(z);
			while(!(z&0x80)) {
				match++;
				z<<=1;
			}
			break;
		}
	}
	if(match > min) match = min;
	return match;
}

void 
addr_to_str(struct sockaddr_storage* addr, socklen_t addrlen, 
	char* buf, size_t len)
{
	int af = (int)((struct sockaddr_in*)addr)->sin_family;
	void* sinaddr = &((struct sockaddr_in*)addr)->sin_addr;
	if(addr_is_ip6(addr, addrlen))
		sinaddr = &((struct sockaddr_in6*)addr)->sin6_addr;
	if(inet_ntop(af, sinaddr, buf, (socklen_t)len) == 0) {
		snprintf(buf, len, "(inet_ntop_error)");
	}
}

int 
addr_is_ip4mapped(struct sockaddr_storage* addr, socklen_t addrlen)
{
	/* prefix for ipv4 into ipv6 mapping is ::ffff:x.x.x.x */
	const uint8_t map_prefix[16] = 
		{0,0,0,0,  0,0,0,0, 0,0,0xff,0xff, 0,0,0,0};
	uint8_t* s;
	if(!addr_is_ip6(addr, addrlen))
		return 0;
	/* s is 16 octet ipv6 address string */
	s = (uint8_t*)&((struct sockaddr_in6*)addr)->sin6_addr;
	return (memcmp(s, map_prefix, 12) == 0);
}

void sock_list_insert(struct sock_list** list, struct sockaddr_storage* addr,
	socklen_t len, struct regional* region)
{
	struct sock_list* add = (struct sock_list*)regional_alloc(region,
		sizeof(*add));
	if(!add) {
		log_err("out of memory in socketlist insert");
		return;
	}
	log_assert(list);
	add->next = *list;
	add->len = len;
	memcpy(&add->addr, addr, len);
	*list = add;
}

void sock_list_prepend(struct sock_list** list, struct sock_list* add)
{
	struct sock_list* last = add;
	if(!last) 
		return;
	while(last->next)
		last = last->next;
	last->next = *list;
	*list = add;
}

int sock_list_find(struct sock_list* list, struct sockaddr_storage* addr,
        socklen_t len)
{
	while(list) {
		if(len == list->len) {
			if(len == 0 || sockaddr_cmp_addr(addr, len, 
				&list->addr, list->len) == 0)
				return 1;
		}
		list = list->next;
	}
	return 0;
}
