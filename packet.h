#ifndef PACKET_H
#define PACKET_H
#define _BSD_SOURCE
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ctype.h>

#define FRAME_MAX_LENGTH    1518
#define ETHERNET_HDR_SIZE   14
#define ETHERNET_ADDR_LENGTH    6
#define FCS_SIZE    4
#define ARP_LENGTH 28
#define PSD_HEADER_LENGTH 12
#define IP_CRC_OFFSET 10
#define TCP_CRC_OFFSET 16
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_RARP 0x8035

struct ARPFame {
    u_int16_t htype;
    u_int16_t ptype;
    u_char hlen;
    u_char plen;
    u_int16_t oper;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
};

struct EthernetFrame {
    u_char  ether_dhost[ETHERNET_ADDR_LENGTH];    /* destination host address */
    u_char  ether_shost[ETHERNET_ADDR_LENGTH];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

struct IPPacket {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
    #define IP_RF 0x8000            /* reserved fragment flag */
    #define IP_DF 0x4000            /* dont fragment flag */
    #define IP_MF 0x2000            /* more fragments flag */
    #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct TCPPacket {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
    #define TH_FIN  0x01
    #define TH_SYN  0x02
    #define TH_RST  0x04
    #define TH_PUSH 0x08
    #define TH_ACK  0x10
    #define TH_URG  0x20
    #define TH_ECE  0x40
    #define TH_CWR  0x80
    #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct TCPPseudoHDR {
    struct in_addr ip_src;
    struct in_addr ip_dst;
    uint8_t zeroes;
    uint8_t protocol;
    uint16_t length;
};

struct UDPPacket {
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_length;
    u_short uh_crc;
};

void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void printPayload(const u_char *payload, int len);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void printFrameFragment(const u_char *payload, int len);
u_int16_t calcCRC(const u_int16_t *packet, int length);
u_int16_t calcTCP_CRC(const u_char *packet);
u_int16_t calcIP_CRC(const u_char *packet);

#endif
