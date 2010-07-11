/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/

#include "usi++/usi++.h"
#include "config.h"
#include <string>
#include <errno.h>
#include <new>
#include <vector>
#include <iostream>

namespace usipp {


IP6::IP6(const struct in6_addr &in6, u_int8_t proto)
	: Layer2(new Pcap, new TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;

	iph.version = 6;
	iph.nexthdr = proto;
	iph.hop_limit = 64;
	set_dst(in6);
}


IP6::IP6(const char *hostname, u_int8_t proto)
	: Layer2(new Pcap, new TX_IP6)
{
	memset(&iph, 0, sizeof(iph));
	memset(&saddr, 0, sizeof(saddr));
	saddr.sin6_family = AF_INET6;

	iph.version = 6;
	iph.nexthdr = proto;
	set_dst(hostname);
}


IP6::IP6(const IP6 &rhs)
	: Layer2(rhs)
{
	if (this == &rhs)
		return;
	iph = rhs.iph;
}

IP6::~IP6()
{
	return;
}

struct in6_addr IP6::get_src()
{
	return iph.saddr;
}

struct in6_addr IP6::get_dst()
{
	return iph.daddr;
}

int IP6::set_src(const char *src)
{
	struct hostent *he = NULL;
	struct in6_addr in6;

	if (inet_pton(AF_INET6, src, &in6) < 0) {
		if ((he = gethostbyname2(src, AF_INET6)) == NULL)
			die("IP6::set_src: gethostbyname2", HERROR, 1);
		memcpy(&iph.saddr, he->h_addr, 16);
	} else
		iph.saddr = in6;
	return 0;
}

int IP6::set_dst(const char *dst)
{
	struct hostent *he = NULL;
	struct in6_addr in6;

	if (inet_pton(AF_INET6, dst, &in6) < 0) {
		if ((he = gethostbyname2(dst, AF_INET6)) == NULL)
			die("IP6::set_src: gethostbyname2", HERROR, 1);
		memcpy(&iph.daddr, he->h_addr, 16);
		memcpy(&saddr.sin6_addr,  he->h_addr, 16);
	} else {
		iph.daddr = in6;
		memcpy(&saddr.sin6_addr, &in6, sizeof(in6));
	}
	return 0;
}


int IP6::set_dst(const struct in6_addr &dst)
{
	memcpy(&saddr.sin6_addr, &dst, 16);
	iph.daddr = dst;
	return 0;
}


int IP6::set_src(const struct in6_addr &src)
{
	iph.saddr = src;
	return 0;
}


int IP6::set_hoplimit(u_int8_t hl)
{
	iph.hop_limit = hl;
	return 0;
}


u_int8_t IP6::get_hoplimit()
{
	return iph.hop_limit;
}


u_int16_t IP6::get_payloadlen()
{
	return ntohs(iph.payload_len);
}


int IP6::sendpack(void *payload, size_t paylen)
{
	size_t len = sizeof(iph) + paylen;
	char *s = new char[len];

	iph.payload_len = htons(paylen);

	memcpy(s, &iph, sizeof(iph));
	memcpy(s+sizeof(iph), payload, paylen);
	int r = Layer2::sendpack(s, len, (struct sockaddr*)&saddr);
	delete [] s;

	return r;

}

};

