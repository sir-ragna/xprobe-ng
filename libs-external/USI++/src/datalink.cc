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
#include "usi++/usi++.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifdef IMMEDIATE
#include <net/bpf.h>
#endif

#include <iostream>

namespace usipp {

Pcap::Pcap()
    : RX()
{
        // Initialize
	memset(d_filter_string, 0, sizeof(d_filter_string));
	d_pd = NULL;
	memset(&d_tv, 0, sizeof(d_tv));

	memset(d_dev, 0, sizeof(d_dev));
	d_timeout = false;

}

/* This constructor should be used to
 *  initialize raw-d_datalink-objects, means not IP/TCP/ICMP etc.
 *  We need this b/c unlike in derived classes, d_datalink::init_device()
 *  cannot set a filter!
 */
Pcap::Pcap(char *filterStr)
{
        // Initialize
	memset(d_filter_string, 0, sizeof(d_filter_string));
        strncpy(d_filter_string, filterStr, sizeof(d_filter_string));
        d_pd = NULL;

	memset(d_dev, 0, sizeof(d_dev));


}

Pcap::~Pcap()
{
	if (d_pd != NULL)
		pcap_close(d_pd);
}

Pcap::Pcap(const Pcap &rhs)
{
	if (this == &rhs)
		return;
	d_datalink = rhs.d_datalink;
	d_framelen = rhs.d_framelen;
	d_filter = rhs.d_filter;
	d_phdr = rhs.d_phdr;

	d_ether = rhs.d_ether;
	strncpy(d_filter_string, rhs.d_filter_string, sizeof(d_filter_string));
	strncpy(d_dev, rhs.d_dev, sizeof(d_dev));
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	if (rhs.d_pd)
		init_device(d_dev, d_has_promisc, d_snaplen);

	return;
}

Pcap &Pcap::operator=(const Pcap &rhs)
{
	if (this == &rhs)
		return *this;
	d_datalink = rhs.d_datalink;
	d_framelen = rhs.d_framelen;
	d_filter = rhs.d_filter;
	d_phdr = rhs.d_phdr;

	d_ether = rhs.d_ether;
	strncpy(d_filter_string, rhs.d_filter_string, sizeof(d_filter_string));
	strncpy(d_dev, rhs.d_dev, sizeof(d_dev));
	d_has_promisc = rhs.d_has_promisc;
	d_snaplen = rhs.d_snaplen;

	if (rhs.d_pd) {
		if (d_pd)
			pcap_close(d_pd);
		init_device(d_dev, d_has_promisc, d_snaplen);
	}

	return *this;
}

/*  Return the actual d_datalink of the object.
 */
int Pcap::get_datalink()
{
   	return d_datalink;
}

/*  Return the actual framlen of the object.
 *  (d_framelen depends on d_datalink)
 */
int Pcap::get_framelen()
{
	return d_framelen;
}


/*  Fill buffer with src-hardware-adress of actuall packet,
 *  use 'd_datalink' to determine what HW the device is.
 *  Now only ethernet s supportet, but it's extensinable.
 */
char *Pcap::get_hwsrc(char *hwaddr, size_t len)
{
        unsigned char *s;
	memset(hwaddr, 0, len);

	switch (d_datalink) {
	case DLT_EN10MB:
		if (len < 2*ETH_ALEN)
           		return NULL;
    		s = d_ether.ether_shost;
    		sprintf(hwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (u_char)*s,
	               (u_char)*(s+1), (u_char)*(s+2), (u_char)*(s+3),
		       (u_char)*(s+4), (u_char)*(s+5));
		break;
	default:
		return NULL;
	}
	return hwaddr;
}

/*  Fill buffer with dst-hardware-adress of actuall packet,
 *  use 'd_datalink' to determine what HW the device is.
 *  Now only ethernet s supportet.
 */
char *Pcap::get_hwdst(char *hwaddr, size_t len)
{
   	unsigned char *s;

	memset(hwaddr, 0, len);
        switch (d_datalink) {
        case DLT_EN10MB:
           	if (len < 2*ETH_ALEN)
           	       return NULL;
                s = d_ether.ether_dhost;
                sprintf(hwaddr, "%02x:%02x:%02x:%02x:%02x:%02x", (u_char)*s,
	               (u_char)*(s+1), (u_char)*(s+2), (u_char)*(s+3),
		       (u_char)*(s+4), (u_char)*(s+5));
                break;
        default:
           	return NULL;
        }
	return hwaddr;
}

/*  Get protocol-type of ethernet-frame
 *  Maybe moves to ethernet-class in future?
 */
u_int16_t Pcap::get_etype()
{
   	return ntohs(d_ether.ether_type);
}

/*  Initialize a device ("eth0" for example) for packet-
 *  capturing. It MUST be called before sniffpack() is launched.
 *  Set 'promisc' to 1 if you want the device running in promiscous mode.
 *  Fetch at most 'd_snaplen' bytes per call.
 */
int Pcap::init_device(char *dev, int promisc, size_t d_snaplen)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	memset(ebuf, 0, PCAP_ERRBUF_SIZE);

        if ((d_pd = pcap_open_live(dev, d_snaplen, promisc, 1000, ebuf)) == NULL) {
           	die(ebuf, STDERR, 1);
        }

// Ehem, BSD workarounnd. BSD won't timeout on select()
// unless we force immediate return for read() (in pcap)
// for uncomplete packets (queue not full?)
#ifdef IMMEDIATE
	int v = 1;
        if (ioctl(pcap_fileno(d_pd), BIOCIMMEDIATE, &v) < 0) {
        	snprintf(ebuf, sizeof(ebuf),
			"Pcap::init_device::ioctl(..., BIOCIMMEDIATE, 1) %s",
			strerror(errno));
		die(ebuf, STDERR, 1);
	}
#endif
        if (pcap_lookupnet(dev, &d_localnet, &d_netmask, ebuf) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::init_device::pcap_lookupnet: %s\n",
			pcap_geterr(d_pd));
		die(ebuf, STDERR, 1);
        }


	/* The d_filter_string must be filled by derived classes, such
	 * as IP, where the virtual init_device() simply sets d_filter_string
	 * to "ip" and then calls Pcap::init_device().
	 */
        if (pcap_compile(d_pd, &d_filter, d_filter_string, 1, d_netmask) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::init_device::pcap_compile: %s\n",
			pcap_geterr(d_pd));
		die(ebuf, STDERR, 1);
        }
        if (pcap_setfilter(d_pd, &d_filter) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::init_device::pcap_setfilter: %s\n",
			pcap_geterr(d_pd));
		die(ebuf, STDERR, 1);
        }
        if ((d_datalink = pcap_datalink(d_pd)) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::init_device::pcap_d_datalink: %s\n",
			pcap_geterr(d_pd));
                die(ebuf, STDERR, 1);
        }

        // turn d_datalink into d_framelen
        switch (d_datalink) {
        case DLT_EN10MB:
		d_framelen = sizeof(d_ether);
                break;
        case DLT_PPP:
		d_framelen = 4;
                break;
	case DLT_PPP_BSDOS:
		d_framelen = 24;
		break;
        case DLT_SLIP:
		d_framelen = 24;
                break;
	case DLT_RAW:
           	d_framelen = 0;
		break;
	// loopback
	case DLT_NULL:
		d_framelen = 4;
		break;
	case DLT_LINUX_SLL:
		d_framelen = 16;
		break;
        default:
		printf("%d %d\n", d_datalink, DLT_RAW);
           	die("Pcap::init_device: Unknown d_datalink.\n", STDERR, 1);
        }

	strncpy(d_dev, dev, sizeof(d_dev));
	d_has_promisc = promisc;
	d_snaplen = d_snaplen;
        return 0;
}


/*  set a new filter for capturing
 */
int Pcap::setfilter(char *s)
{
	char ebuf[PCAP_ERRBUF_SIZE];
	memset(ebuf, 0, PCAP_ERRBUF_SIZE);

	if (!d_pd)
		die("Pcap::setfilter: Device not initialized.\n", STDERR, 1);

   	memset(d_filter_string, 0, sizeof(d_filter_string));
	snprintf(d_filter_string, sizeof(d_filter_string), "%s", s);

        if (pcap_compile(d_pd, &d_filter, d_filter_string, 1, d_netmask) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::setfilter::pcap_compile: %s\n", pcap_geterr(d_pd));
		die(ebuf, STDERR, 1);
        }

        if (pcap_setfilter(d_pd, &d_filter) < 0) {
           	snprintf(ebuf, sizeof(ebuf), "Pcap::setfilter::pcap_setfilter: %s\n", pcap_geterr(d_pd));
		die(ebuf, STDERR, 1);
        }
        return 0;
}

int Pcap::sniffpack(void *s, size_t len)
{
   	char *tmp;

	memset(s, 0, len);

	d_timeout = false;
	if (!d_pd)
		die("Pcap::sniffpack: Device not initialized.\n", STDERR, 1);

	if (d_tv.tv_sec != 0 || d_tv.tv_usec != 0) {	// TO was set
		while (1) {
			fd_set rset;
			FD_ZERO(&rset);
			int fd = pcap_fileno(d_pd);
			FD_SET(fd, &rset);
			timeval tmp = d_tv;

			// wait for packet
			int sr;
			if ((sr=select(fd+1, &rset, NULL, NULL, &tmp)) < 0) {
				if (errno == EINTR)
					continue;
				else
					return -1;
			} else if (sr == 0) { // timed out
				d_timeout = true;
				return 0;
			} else		// got packet
				break;
		}
	}

        while ((tmp = (char*)pcap_next(d_pd, &d_phdr)) == NULL);

        switch (d_datalink) {
        case DLT_EN10MB:
                memcpy(&d_ether, tmp, d_framelen);
                break;
        case DLT_PPP:
                break;
	case DLT_PPP_BSDOS:
		break;
        case DLT_SLIP:
                break;
	case DLT_RAW:
		break;
	case DLT_LINUX_SLL:
		break;
        default:
           	die("Pcap::sniffpack: Unknown d_datalink.\n", STDERR, 1);
        }
#ifdef USI_DEBUG
       	cerr<<"Pcap::d_phdr.len="<<d_phdr.len<<endl;
 	cerr<<"Pcap::d_framelen="<<d_framelen<<endl;
#endif
	// d_framelen was already calculated by init_device
        memcpy(s, (tmp + d_framelen),
	       d_phdr.len - d_framelen < len ? d_phdr.len - d_framelen : len);
        return (d_phdr.len - d_framelen);
}


// give back layer2 frame
void *Pcap::get_frame(void *hwframe, size_t len)
{

        // switch over the hardware-layer of the packet
	switch (d_datalink) {
   	case DLT_EN10MB:
                memcpy(hwframe, &d_ether, (len<sizeof(d_ether)?len:sizeof(d_ether)));
                break;
        default:
           	return NULL;
        }
        return hwframe;
}

int Pcap::timeout(struct timeval tv)
{
	d_tv = tv;
	d_timeout = false;
	return 0;
}

bool Pcap::timeout()
{
	return d_timeout;
}

} // namespace usipp
