#include <stdio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <pcap.h>

#pragma once

#pragma pack(push,1)
struct ethernet
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};
#pragma pack(pop)

#pragma pack(push,1)
struct arp
{
    uint16_t HW_type;
    uint16_t proto_type;
    uint8_t HW_length;
    uint8_t proto_length;
    uint16_t op;
    uint8_t sender_HW_addr[6];
    uint8_t sender_proto_addr[4];
    uint8_t target_HW_addr[6];
    uint8_t target_proto_addr[4];
};
#pragma pack(pop)

#pragma pack(push,1)
struct arp_packet
{
    struct ethernet ethernet_packet;
    struct arp arp_packet;
};
#pragma pack(pop)

#pragma pack(push,1)
struct ip
{
    uint8_t header_length : 4;
    uint8_t version : 4;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t identification;
    uint8_t x_flag : 1;
    uint8_t D_flag : 1;
    uint8_t M_flag : 1;
    uint16_t fragment_offset : 13;
    uint8_t TTL;
    uint8_t protocol;
    uint16_t header_chksum;
    uint8_t src_addr[4];
    uint8_t dst_addr[4];
};
#pragma pack(pop)

#pragma pack(push,1)
struct ip_packet
{
    struct ethernet ethernet_packet;
    struct ip ip_packet;
};
#pragma pack(pop)

#pragma pack(push,1)
struct address_set
{
    u_int8_t sender_ip[4];
    u_int8_t sender_mac[6];
    u_int8_t target_ip[4];
    u_int8_t target_mac[6];
    u_int8_t request_packet_to_sender[42];
    u_int8_t request_packet_to_target[42];
    u_int8_t spoofed_reply_packet_to_sender[42];

};
#pragma pack(pop)

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define SEND_REQUEST_MESSAGE_TO_GET_SENDER_MAC 1
#define SEND_REQUEST_MESSAGE_TO_GET_TARGET_MAC 2

void get_ip_address (const char * dev, unsigned char *ip);
void get_mac_address(char* dev, unsigned char *mac);
void str_ip2int_ip(char *str_ip, uint8_t *int_ip);
void make_arp_request_packet_get_mac(uint8_t *attacker_mac, uint8_t *attacker_ip, uint8_t *sender_ip, uint8_t *packet);
void make_arp_reply_spoofed_packet_for_attack(uint8_t *attacker_mac, uint8_t * target_ip, uint8_t *sender_mac, uint8_t * sender_ip, uint8_t *packet);
void pcap_relaypacket(pcap_t* handle, uint8_t* attacker_mac, uint8_t* target_mac_1, const u_char* packet);
int monitoring_packet(uint8_t *sender_mac, uint8_t *attacker_mac, uint8_t *target_mac, const u_char *packet);
int send_request_packet_for_get_mac(pcap_t* handle, char* dev, struct address_set *set, int id);
