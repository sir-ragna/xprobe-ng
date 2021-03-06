/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#ifndef _TX_IP6_H_
#define _TX_IP6_H_

#include "config.h"
#include "usi++/usi-structs.h"
#include "TX.h"
#include <stdio.h>

namespace usipp {

/*! \class TX_IP6
 *	This sends IP6 datagrams over
 *  a raw socket */
class TX_IP6 : public TX {
private:
	int rawfd;
public:
	TX_IP6() : rawfd(-1) {}

	virtual ~TX_IP6() {}

	/*! Send a packet on raw socket (starting with IP-hdr) */
	virtual int sendpack(void *, size_t, struct sockaddr*);

	/*! Enable broadcast option on socket */
	virtual int broadcast();

};

}	// namespace
#endif

