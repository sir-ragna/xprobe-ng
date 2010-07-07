#include <usi++/usi++.h>
#include <iostream>
#include <string>
#include <vector>
#include <tinythread.h>

#define MAXDATALEN 1500


using namespace std;
using namespace tthread;

void Sniffer(void *arg) {

 TCP *sn = new TCP("0.0.0.0");

        char **ar = (char **)arg;
        sn->init_device(ar[1], 1, MAXDATALEN);
        char buf[MAXDATALEN];

        while (1) {
            cout << "getting packs\n";
            memset(buf, 0, MAXDATALEN);
           	int l = sn->sniffpack(buf, 1500);
            cout << "Got packet\n";

        }


}

int main(int argc, char **argv)
{

        if (argc < 2) {
           	cout<<argv[0]<<" [intf]\n";
		exit(1);
        }
        thread t(Sniffer, argv);
        while (1) {
        cout << "I am sending stuff\n";
        sleep(1);
        }
        t.join();

}
