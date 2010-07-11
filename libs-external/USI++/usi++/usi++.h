/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/


#ifndef _USIPP_H_
#define _USIPP_H_

#ifndef USI_VERSION
#define USI_VERSION 195
#endif

#include "config.h"
#include "usi++/usi-structs.h"
#include "usi++/config.h"
#include "usi++/datalink.h"
//#include "arp.h"
#include "usi++/Layer2.h"
#include "usi++/ip.h"
#include "usi++/icmp.h"
#include "usi++/udp.h"
#include "usi++/tcp.h"
#include "usi++/TX.h"
#include "usi++/TX_IP.h"
#include "usi++/RX.h"
#include "usi++/ip6.h"
#include "usi++/TX_IP6.h"
#include "usi++/icmp6.h"
#include <string>

using namespace std;

namespace usipp {

using namespace std;

class usifault {
	string fault;
public:
   	usifault(const char *s = "undef") : fault(s) {}
        ~usifault() {}
	const char *why() { return fault.c_str(); }
};

/* For error-handling.
 */
typedef enum {
	PERROR = 0,
	HERROR,
	PCAP,
	STDERR
} errorFuncs;

extern unsigned short in_cksum(unsigned short *ptr, int len, bool may_pad);
extern bool exceptions;
extern int useException(bool);
extern void die(const char *, errorFuncs, int);
extern char *getMAC(const char *, char *, int);
extern char *setMAC(const char *, char *);

} // namespace usipp

using namespace usipp;

#endif // _USIPP_H_
