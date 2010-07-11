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
#include <netinet/in.h>
#include <string.h>

namespace usipp {

ICMP6::ICMP6(const char *dst)
	: IP6(dst, IPPROTO_ICMPV6)
{
	memset(&icmp6hdr, 0, sizeof(icmp6hdr));
}


ICMP6::~ICMP6()
{
}


int ICMP6::set_type(u_int8_t t)
{
	icmp6hdr.icmp6_type = t;
	return 0;
}


u_int8_t ICMP6::get_type()
{
	return icmp6hdr.icmp6_type;
}


int ICMP6::set_code(u_int8_t code)
{
	icmp6hdr.icmp6_code = code;
	return 0;
}


u_int8_t ICMP6::get_code()
{
	return icmp6hdr.icmp6_code;
}


u_int32_t ICMP6::get_data()
{
	return icmp6hdr.icmp6_dataun.icmp6_un_data32[0];
}


int ICMP6::set_data(u_int32_t d)
{
	icmp6hdr.icmp6_dataun.icmp6_un_data32[0] = d;
	return 0;
}



int ICMP6::sendpack(void *payload, size_t paylen)
{
	size_t len = sizeof(icmp6hdr) + paylen;
	char *s = new char[len];
	memset(s, 0, len);

	memcpy(s, &icmp6hdr, sizeof(icmp6hdr));
	memcpy(s+sizeof(icmp6hdr), payload, paylen);

	icmp6_hdr *i = (icmp6_hdr*)s;
	if (i->icmp6_cksum == 0) {
		unsigned char *c = new unsigned char[
		2*sizeof(in6_addr)+3*sizeof(u_int32_t)+len], *cptr = c;
		in6_addr i6 = get_src();
		memcpy(cptr, &i6, sizeof(i6));
		cptr += sizeof(i6);
		i6 = get_dst();
		memcpy(cptr, &i6, sizeof(i6));
		cptr += sizeof(i6);
		u_int32_t razia[2] = {htonl(len), htonl(IPPROTO_ICMPV6)};
		memcpy(cptr, razia, sizeof(razia));
		cptr += sizeof(razia);
		memcpy(cptr, s, len); cptr += len;
		i->icmp6_cksum = in_cksum((unsigned short*)c, cptr - c, 0);
		delete [] c;
	}


	int r = IP6::sendpack(s, len);
	delete [] s;
	return r;
}

}

