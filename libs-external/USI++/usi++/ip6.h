#ifndef _IP6_H_
#define _IP6_H_

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"

#include <sys/types.h>

namespace usipp {


class IP6 : public Layer2 {

public:
	IP6(const struct in6_addr &, u_int8_t);

	IP6(const char *, u_int8_t);

	IP6(const IP6&);

	virtual ~IP6();

	struct in6_addr get_src();

	struct in6_addr get_dst();

	int set_src(const struct in6_addr &); 

	int set_src(const char *);

	int set_dst(const struct in6_addr &);

	int set_dst(const char *);

	u_int8_t get_hoplimit();

	int set_hoplimit(u_int8_t);

	u_int16_t get_payloadlen();

	virtual int sendpack(void *, size_t);

private:
	struct ip6_hdr iph;
	struct sockaddr_in6 saddr;

};

};

#endif

