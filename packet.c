#include "packet.h"

void handlePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct EthernetFrame *ethernet;
    struct IPPacket *ip;
    struct TCPPacket *tcp;
    const struct UDPPacket *udp;
    const u_char *payload;
    const u_char* ch;

    u_int16_t crc16;

    size_t ipHDRSize, ipPacketSize, tcpPayloadSize, udpPacketSize;
    int tcpHDRSize;
    int payloadSize;

    struct  in_addr* ptpa;
    struct  in_addr* pspa;

    ethernet = (struct EthernetFrame*)(packet);
    pspa = (struct in_addr*)(packet + ETHERNET_HDR_SIZE + 14);
    ptpa = (struct in_addr*)(packet + ETHERNET_HDR_SIZE + 24);
    //  Выводим ARP и RARP
    if((ntohs(ethernet->ether_type) == ETHERTYPE_ARP)||(ntohs(ethernet->ether_type) == ETHERTYPE_RARP)) {
        printf("ARP(RARP) packet.\n");
        printf("SPA: %s\n", inet_ntoa(*pspa));
        printf("TPA: %s\n", inet_ntoa(*ptpa));
        payload = (u_char *)(packet);
        payloadSize = ETHERNET_HDR_SIZE + ARP_LENGTH;
        printf("   Payload (%d bytes):\n", payloadSize);
        printPayload(payload, payloadSize + FCS_SIZE + 20);
    }
    /* define/compute ip header offset */
    ip = (struct IPPacket*)(packet + ETHERNET_HDR_SIZE);
    ipHDRSize = IP_HL(ip)*4;
    ipPacketSize = ntohs(ip->ip_len);
    if (ipHDRSize < 20) {
        printf("Invalid IP header length: %u bytes\n", (unsigned int)ipHDRSize);
        return;
    }
    switch(ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP:\n");
            tcp = (struct TCPPacket*)(packet + ETHERNET_HDR_SIZE + ipHDRSize);
            tcpHDRSize = TH_OFF(tcp)*4;
            tcpPayloadSize = ipPacketSize - (ipHDRSize + tcpHDRSize);
            if (tcpHDRSize < 20) {
                printf("Invalid TCP header length: %u bytes\n", tcpHDRSize);
                return;
            }
            printf("IP packet size: ");
            printf("%d\n", (int)ipPacketSize);
            printf("Attached IP CRC: ");
            ch = (const u_char*)(packet + ETHERNET_HDR_SIZE + IP_CRC_OFFSET);
            for(int i = 0; i < 2; ++i) {
                printf("%02x ", *ch);
                ++ch;
            }
            printf("\n");
            printf("Attached TCP CRC: ");
            ch = (const u_char*)(packet + ETHERNET_HDR_SIZE + ipHDRSize + TCP_CRC_OFFSET);
            for(int i = 0; i < 2; ++i) {
                printf("%02x ", *ch);
                ++ch;
            }
            printf("\n");
            ip->ip_sum = 0;
            printf("Calculated IP CRC: ");
            crc16 = calcIP_CRC(packet);
            ch = (const u_char*)&crc16;
            printf("%02x ", *ch++); printf("%02x\n", *ch);
            tcp->th_sum = 0;
            printf("Calculated TCP CRC: ");
            crc16 = calcTCP_CRC(packet);
            ch = (const u_char*)&crc16;
            printf("%02x ", *ch++); printf("%02x\n", *ch);
            payload = (u_char *)(packet);
            payloadSize = ETHERNET_HDR_SIZE + ipPacketSize;
            printf("From: %s\n", inet_ntoa(ip->ip_src));
            printf("To: %s\n", inet_ntoa(ip->ip_dst));
            printf("Src port: %d\n", ntohs(tcp->th_sport));
            printf("Dst port: %d\n", ntohs(tcp->th_dport));
            if (payloadSize > 0) {
//                printf("Frame size (%d bytes):\n", payloadSize);
                printPayload(payload, payloadSize);
//                printf("Ethernet header(%d): \n\n", ETHERNET_HDR_SIZE);
//                printFrameFragment(payload, ETHERNET_HDR_SIZE);
//                printf("IP header(%d): \n", (int)ipHDRSize);
//                printFrameFragment(payload + ETHERNET_HDR_SIZE, ipHDRSize);
//                printf("TCP header(%d): \n", tcpHDRSize);
//                printFrameFragment(payload + ETHERNET_HDR_SIZE + ipHDRSize, tcpHDRSize);
//                printf("TCP payload(%d): \n", (int)tcpPayloadSize);
//                printFrameFragment(payload + ETHERNET_HDR_SIZE + ipHDRSize + tcpHDRSize, tcpPayloadSize);
//                printf("Ethernet FCS(4): \n");
//                printFrameFragment(payload + ETHERNET_HDR_SIZE + ipHDRSize + tcpHDRSize + tcpPayloadSize, FCS_SIZE);
            }
            else {
                printf("No payload.\n");
            }
            return;
        case IPPROTO_UDP:
            udp = (struct UDPPacket*)(packet + ETHERNET_HDR_SIZE + ipHDRSize);
            udpPacketSize = ntohs(udp->uh_length);
            printf("UDP:\n");
            printf("From: %s\n", inet_ntoa(ip->ip_src));
            printf("To: %s\n", inet_ntoa(ip->ip_dst));
            printf("Src port: %d\n", ntohs(udp->uh_sport));
            printf("Dst port: %d\n", ntohs(udp->uh_dport));
            if (payloadSize > 0) {
                printPayload((u_char *)udp, udpPacketSize);
            }
            else {
                printf("No payload.\n");
            }
            return;
        case IPPROTO_ICMP:
            printf("ICMP:\n");
            payload = (const u_char*)(packet + ETHERNET_HDR_SIZE + ipHDRSize);
            payloadSize = ipPacketSize - ipHDRSize;
            if(payloadSize) {
                printPayload(payload, payloadSize);
            }
            return;
        case IPPROTO_IP:
            printf("IP:\n");
            printf("From: %s\n", inet_ntoa(ip->ip_src));
            printf("To: %s\n", inet_ntoa(ip->ip_dst));
            payloadSize = ipPacketSize - ipHDRSize;
            payload = (u_char *)(packet + ETHERNET_HDR_SIZE + ipHDRSize);
            if(payloadSize > 0) {
                printPayload(payload, payloadSize);
            }
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
    return;
}

void printFrameFragment(const u_char *payload, int len)
{
    const u_char *ch;
    ch = payload;
    for(int i = 0; i < len; ++i) {
        printf("%02x ", *ch);
        ++ch;
    }
    printf("\n\n");
}

void printPayload(const u_char *payload, int len)
{
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;
    if (len <= 0)
        return;
    /* data fits on one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    /* data spans multiple lines */
    for ( ;; ) {
        /* compute current line length */
        line_len = line_width % len_rem;
        /* print line */
        print_hex_ascii_line(ch, line_len, offset);
        /* compute total remaining */
        len_rem = len_rem - line_len;
        /* shift pointer to remaining bytes to print */
        ch = ch + line_len;
        /* add offset */
        offset = offset + line_width;
        /* check if we have line width chars or less */
        if (len_rem <= line_width) {
            /* print last line and get out */
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
    printf("\n");

return;
}

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;

    /* offset */
    printf("%05d   ", offset);

    /* hex */
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
        /* print extra space after 8th byte for visual aid */
        if (i == 7)
            printf(" ");
    }
    /* print space to handle line less than 8 bytes */
    if (len < 8)
        printf(" ");

    /* fill hex gap with spaces if not full line */
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    /* ascii (if printable) */
    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }

    printf("\n");

return;
}

u_int16_t calcCRC(const u_int16_t *packet, int length)
{
    uint32_t cksum = 0;
    while(length > 1)
    {
//        cksum += ntohs(*packet);
//        ++packet;
//        length -=sizeof(u_int16_t);
        cksum += *packet++;
        length -= 2;
    }
    if(length) {
        cksum += *(u_char*)packet;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    cksum = ~cksum;
    return (uint16_t)(cksum);
}

u_int16_t calcTCP_CRC(const u_char *packet)
{
    uint16_t csum;
    size_t ipHDRSize;
    size_t ipPacketSize;
    size_t ipPayloadSize;
    const struct IPPacket * ip;
    const struct TCPPacket * tcp;
    struct TCPPseudoHDR psdHeader;
    ip = (const struct IPPacket *)(packet + ETHERNET_HDR_SIZE);
    ipHDRSize = IP_HL(ip)*4;
    ipPacketSize = ntohs(ip->ip_len);
    ipPayloadSize = ipPacketSize - ipHDRSize;
    tcp = (const struct TCPPacket *)((const u_char *)ip + ipHDRSize);
    psdHeader.ip_src = ip->ip_src;
    psdHeader.ip_dst = ip->ip_dst;
    psdHeader.zeroes = 0;
    psdHeader.protocol = IPPROTO_TCP;
    psdHeader.length = htons(ipPayloadSize);

    char tcpBuf[65536];
    memcpy(tcpBuf, &psdHeader, PSD_HEADER_LENGTH);
    memcpy(tcpBuf + PSD_HEADER_LENGTH, tcp, ipPayloadSize);
    csum = calcCRC((uint16_t *)tcpBuf, ipPayloadSize + PSD_HEADER_LENGTH);
    return csum;
}

u_int16_t calcIP_CRC(const u_char *packet)
{
    uint16_t csum;
    size_t ipHDRSize;
    const struct IPPacket * ip;
    ip = (const struct IPPacket *)(packet + ETHERNET_HDR_SIZE);
    ipHDRSize = IP_HL(ip)*4;
    csum = calcCRC((uint16_t *)ip, ipHDRSize);
    return csum;
}
