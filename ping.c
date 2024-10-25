#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>

#define ICMP_HDRLEN 8
#define ICMP_PAYLOAD_LEN 56
#define ICMP_PACKET_SIZE 64

#define SOCKET int
#define ISVALIDSOCKET(s) ((s) >= 0)

#define RECV_TIMEOUT 1          // timeout for receiving packets (in seconds)
#define PING_SLEEP_RATE 1000000 // ping sleep rate (in microseconds)

struct addrinfo *get_address(char *hostname)
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    struct addrinfo *peer_address;
    if (getaddrinfo(hostname, NULL, &hints, &peer_address))
    {
        fprintf(stderr, "getaddrinfo() failed. (%s)\n", strerror(errno));
        exit(1);
    }

    return peer_address;
}

char *print_address(char *hostname, struct addrinfo *peer_address)
{
    char address_buffer[100];
    getnameinfo(peer_address->ai_addr, peer_address->ai_addrlen, address_buffer, sizeof(address_buffer), 0, 0, NI_NUMERICHOST);
    printf("PING %s (%s)\n", hostname, address_buffer);

    char *ipaddress = (char *)malloc(100);
    memccpy(ipaddress, &address_buffer, 0, 100);
    return ipaddress;
}

#define packet_t char *

uint16_t calculate_checksum(packet_t packet)
{
    long sum = 0;
    uint8_t *end = (uint8_t *)packet + ICMP_PACKET_SIZE;

    // iterate through 16 bit chunks
    uint16_t *chunk = (uint16_t *)packet;
    while ((uint8_t *)chunk < end)
    {
        sum += *chunk;
        chunk += 1;
    }

    uint16_t c_sum = ~(uint16_t)((sum & 0xFFFF) + ((sum >> 16) & 0xFFFF));

    return c_sum;
}

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

packet_t create_echo_request(uint16_t seq)
{
    packet_t packet = (packet_t)malloc(ICMP_PACKET_SIZE); // 64 bytes
    memset(packet, 0, ICMP_PACKET_SIZE);

    // build echo request header
    struct icmp *icmp_hdr = (struct icmp *)packet;
    icmp_hdr->icmp_type = ICMP_ECHO;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_id = getpid() & 0xFFFF;
    icmp_hdr->icmp_seq = seq;
    icmp_hdr->icmp_cksum = 0;

    // construct payload
    char payload[ICMP_PAYLOAD_LEN];
    int i;
    for (i = 0; i < ICMP_PAYLOAD_LEN - 1; i++)
        payload[i] = i + '0';
    payload[i] = 0;
    memcpy(packet + ICMP_HDRLEN, payload, ICMP_PAYLOAD_LEN);

    icmp_hdr->icmp_cksum = checksum(packet, ICMP_PACKET_SIZE);

    return packet;
}

void address_to_string(struct sockaddr *client_address, socklen_t client_len, char *address_buffer)
{
    getnameinfo(client_address, client_len, address_buffer, sizeof(address_buffer), 0, 0, NI_NUMERICHOST);
}

void reverse_dns(struct sockaddr *client_address, socklen_t client_len, char *address_buffer)
{
    getnameinfo(client_address, client_len, address_buffer, sizeof(address_buffer), 0, 0, 0);
}

void send_ping(struct addrinfo *peer_address, char *hostname, char *ipaddress)
{
    // initialize socket
    SOCKET socket_peer = socket(peer_address->ai_family, peer_address->ai_socktype, peer_address->ai_protocol);
    if (!ISVALIDSOCKET(socket_peer))
    {
        fprintf(stderr, "socket() failed. (%s)\n", strerror(errno));
        exit(1);
    }
    // set time to live
    int ttl_val = 59;
    if (setsockopt(socket_peer, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0)
    {
        fprintf(stderr, "setsockopt() failed. (%s)\n", strerror(errno));
        exit(1);
    }
    // sets timeout
    struct timeval timeout;
    timeout.tv_sec = RECV_TIMEOUT;
    timeout.tv_usec = 0;
    if (setsockopt(socket_peer, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) != 0)
    {
        fprintf(stderr, "setsockopt() 2 failed. (%s)\n", strerror(errno));
        exit(1);
    }

    // start echo sequence
    uint16_t sequence_count = 0;
    char buffer[128];

    struct timeval start, end;
    long seconds, useconds;
    double elapsed_time;

    while (sequence_count < 10)
    {
        packet_t packet = create_echo_request(sequence_count);

        usleep(PING_SLEEP_RATE);

        gettimeofday(&start, NULL);

        int bytes_sent = sendto(socket_peer, packet, ICMP_PACKET_SIZE, 0, peer_address->ai_addr, peer_address->ai_addrlen);
        if (bytes_sent <= 0)
        {
            fprintf(stderr, "sendto() failed. (%s)\n", strerror(errno));
            free(packet);
            goto cleanup;
        }

        // receive answer
        struct sockaddr_storage client_address;
        socklen_t client_len = sizeof(client_address);
        int bytes_received = recvfrom(socket_peer, buffer, 128, 0, (struct sockaddr *)&client_address, &client_len);
        if (bytes_received < 0)
        {
            printf("Packet receive failed\n");
        }
        else
        {
            gettimeofday(&end, NULL);
            seconds = end.tv_sec - start.tv_sec;
            useconds = end.tv_usec - start.tv_usec;

            elapsed_time = (seconds * 1000.0) + (useconds / 1000.0);

            printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%fms\n", bytes_received, hostname, ipaddress, sequence_count, ttl_val, elapsed_time);
        }
        free(packet);
        sequence_count++;
    }

cleanup:
    close(socket_peer);
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        fprintf(stderr, "usage: ping hostname\n");
        return 1;
    }

    struct addrinfo *peer_address = get_address(argv[1]);
    char *ipaddress = print_address(argv[1], peer_address);

    send_ping(peer_address, argv[1], ipaddress);

    freeaddrinfo(peer_address);
    free(ipaddress);
}