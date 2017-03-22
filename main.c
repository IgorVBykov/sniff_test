#include <pcap.h>
#include <stdio.h>
#include "packet.h"

int main(int argc, char **argv)
{

    char *devName = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *sessionHandler;

    char filterExpr[] = "";
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (argc == 2) {
        devName = argv[1];
    }
    else if (argc > 2) {
        printf("Bad usage\n");
        return -1;
    }
    else {
        devName = pcap_lookupdev(errbuf);
        if (devName == NULL) {
            printf("Bad device!\n");
            return -1;
        }
    }

    // Открываем устройство
    sessionHandler = pcap_open_live(devName, FRAME_MAX_LENGTH, 1, 1000, errbuf);
    if (sessionHandler == NULL) {
        printf("Can't open device\n");
        return -1;
    }
    // Удостоверяемся в том, что открываемое устройство относится к ethernet
    if (pcap_datalink(sessionHandler) != DLT_EN10MB) {
        printf("Device is not an Ethernet\n");
        return -1;
    }
    // Подготавливаем фильтр
    if (pcap_compile(sessionHandler, &fp, filterExpr, 0, net) == -1) {
        printf("Can't parse filter\n");
        return -1;
    }
    // Устанавливаем фильтр
    if (pcap_setfilter(sessionHandler, &fp) == -1) {
        printf("Can't install filter\n");
        return -1;
    }
    pcap_loop(sessionHandler, -1, handlePacket, NULL);
    pcap_freecode(&fp);
    pcap_close(sessionHandler);
    return 0;
}
