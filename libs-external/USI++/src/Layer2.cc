/*** This Programs/Libraries are (C)opyright by Sebastian Krahmer.
 *** You may use it under the terms of the GPL. You should have
 *** already received the file COPYING that shows you your rights.
 *** Please look at COPYING for further license-details.
 ***  
 *** THERE IS ABSOLUTELY NO WARRANTY. SO YOU USE IT AT YOUR OWN RISK.
 *** IT WAS WRITTEN IN THE HOPE THAT IT WILL BE USEFULL. I AM NOT RESPONSIBLE
 *** FOR ANY DAMAGE YOU MAYBE GET DUE TO USING MY PROGRAMS.
 ***/
#include "config.h"
#include "usi++/usi-structs.h"
#include "usi++/RX.h"
#include "usi++/TX.h"
#include "usi++/Layer2.h"
#include "usi++/datalink.h"
#include "usi++/TX_IP.h"
#include <stdio.h>
#include <string.h>

namespace usipp {

Layer2::Layer2(RX *r, TX *t)
	: clean_rx(0), clean_tx(0)
{
	if (!r) {
		d_rx = new Pcap;
		clean_rx = 1;
	} else
		d_rx = r;
		
	if (!t) {
		d_tx = new TX_IP;
		clean_tx = 1;
	} else
		d_tx = t;
}


int Layer2::sendpack(void *buf, size_t len, struct sockaddr *s)
{
	return d_tx->sendpack(buf, len, s);
}

// delegate sniff request to the receiver
int Layer2::sniffpack(void *buf, size_t len)
{
	return d_rx->sniffpack(buf, len);
}

int Layer2::setfilter(char *fstring)
{
	return d_rx->setfilter(fstring);
}

int Layer2::init_device(char *dev, int p, size_t snaplen)
{
	return d_rx->init_device(dev, p, snaplen);
}

int Layer2::timeout(struct timeval tv)
{
	return d_rx->timeout(tv);
}

bool Layer2::timeout()
{
	return d_rx->timeout();
}

} // namespace usipp
