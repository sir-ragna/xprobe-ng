#ifndef _ICMP6_H_
#define _ICMP6_H_

#include "usi-structs.h"
#include "datalink.h"
#include "Layer2.h"
#include "ip6.h"

#include <sys/types.h>

namespace usipp {

class ICMP6 : public IP6 {
private:
	struct icmp6_hdr icmp6hdr;
	
public:
	ICMP6(const char *);

	virtual ~ICMP6();

	//ICMP6(const ICMP6 &);

	//ICMP &operator=(const ICMP6 &);

	int set_code(u_int8_t);

	u_int8_t get_code();

	int set_type(u_int8_t);

	u_int8_t get_type();

	u_int32_t get_data();

	int set_data(u_int32_t);

	virtual int sendpack(void *, size_t);
	
};

}

#endif

