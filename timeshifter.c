// https://www.anfractuosity.com/projects/timeshifter/
 
#include <stdint.h>
#include <time.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/timex.h>
#include <math.h>
 
#define NF_IP_PRE_ROUTING   0
#define NF_IP_LOCAL_IN      1
#define NF_IP_FORWARD       2
#define NF_IP_LOCAL_OUT     3
#define NF_IP_POST_ROUTING  4
#define NF_IP_NUMHOOKS      5
#define ERR_INIT            -1
 
int first = 1;
struct timeval start, elapsed;
 
int startp = -1;
char buff[1];
 
int zerothreshold = -1;
long long onesleep = -1;
 
unsigned char getbit(unsigned char *bits, unsigned long n) {
    return (bits[n / 8] & (unsigned char)pow(2, n % 8)) >> n % 8;
}
 
void setbit(unsigned char *bits, unsigned long n, unsigned char val) {
    bits[n / 8] =
        (bits[n / 8] & ~(unsigned char)pow(2, n % 8)) | ((unsigned char)
                                 pow(2,
                                 n % 8) * val);
}
 
static int difference_micro(struct timeval *before, struct timeval *after) {
    return (signed long long)after->tv_sec * 1000000ll +
        (signed long long)after->tv_usec -
        (signed long long)before->tv_sec * 1000000ll -
        (signed long long)before->tv_usec;
}
 
static uint32_t nfqueue_packet_get_id(struct nfq_data *packet) {
    uint32_t id = -1;
    struct nfqnl_msg_packet_hdr *packetHeader;
 
    if ((packetHeader = nfq_get_msg_packet_hdr(packet)) != NULL)
        id = ntohl(packetHeader->packet_id);
 
    return id;
}
 
static uint32_t nfqueue_packet_get_hook(struct nfq_data *packet) {
 
    uint32_t hook = -1;
    struct nfqnl_msg_packet_hdr *packetHeader;
 
    if ((packetHeader = nfq_get_msg_packet_hdr(packet)) != NULL)
        hook = packetHeader->hook;
 
    return hook;
}
 
static int manage_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
             struct nfq_data *nfa, void *data2) {
 
    uint32_t hook = nfqueue_packet_get_hook(nfa);
    uint32_t id = nfqueue_packet_get_id(nfa);
 
    switch (hook) {
        case NF_IP_LOCAL_IN:
 
            if (first) {
                printf("Reciever...\n");
                gettimeofday(&start, 0x0);
                first = 0;
                startp = 0;
            } else {
                gettimeofday(&elapsed, 0x0);
 
                long ms =
                    difference_micro(&start, &elapsed) / 1000;
 
                if (startp == 0)
                    printf("BYTE: ");
                 
                if (ms <= zerothreshold) {
                    printf("0");
                    setbit(buff, startp, 0);
                } else {
                    printf("1");
                    setbit(buff, startp, 1);
 
                }
 
                fflush(stdout);
                startp++;
 
                if (startp % 8 == 0) {
                    printf(" (%c) \n", buff[0]);
                    startp = 0;
                }
 
                start.tv_sec = elapsed.tv_sec;
                start.tv_usec = elapsed.tv_usec;
            }
 
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 
        case NF_IP_FORWARD:
 
            puts("capturing packet from FORWARD iptables hook");
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 
        case NF_IP_LOCAL_OUT:{
 
                if (startp == -1) {
                    printf("Transmitter...\n");
 
                    int b = fgetc(stdin);
                    if (b == EOF)
                        b = 0;
 
                    buff[0] = b;
                    startp = 0;
 
                    return nfq_set_verdict(qh, id,
                                   NF_ACCEPT, 0,
                                   NULL);
                }
 
                unsigned char bit = getbit(buff, startp);
 
                if (startp == 0) {
                    printf("BYTE: ");
                }
 
                if (bit == 0) {
                    printf("0");
                } else if (bit == 1) {
                    printf("1");
                    int seconds = onesleep / 1000;
                    long long milliseconds =
                        (((double)onesleep / (double)1000) -
                         (double)seconds) * 1000 * 1000000;
                    nanosleep((struct timespec[]) { {
                          seconds, milliseconds}},
                          NULL);
                }
 
                fflush(stdout);
 
                startp++;
 
                if (startp % 8 == 0) {
                    printf(" (%c)\n", buff[0]);
 
                    int b = fgetc(stdin);
                    if (b == EOF)
                        b = 0;
 
                    buff[0] = b;
                    startp = 0;
                }
 
                return nfq_set_verdict(qh, id, NF_ACCEPT, 0,
                               NULL);
            }
 
        default:
            puts("error: capturing packet from an iptables hook we shouldn't");
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 
    }
 
}
 
int main(int argc, char **argv) {
    struct nfq_handle *handle;
    struct nfq_q_handle *queue;
    struct nfnl_handle *netlink_handle;
    uint32_t nfqueue_fd;
 
    if (argc != 4) {
        printf("Argument: queue_number zerothreshold onesleep\n");
        printf("Times are to be represented in milliseconds.\n");
        return -1;
    }
 
    int16_t queuenum = atoi(argv[1]);
    zerothreshold = atoi(argv[2]);
    onesleep = atoi(argv[3]);
 
    handle = nfq_open();
 
    if (!handle) {
        perror("Error: during nfq_open()");
        return ERR_INIT;
    }
 
    if (nfq_unbind_pf(handle, AF_INET) < 0) {
        perror("Error: during nfq_unbind_pf()");
        return ERR_INIT;
    }
 
    if (nfq_bind_pf(handle, AF_INET) < 0) {
        perror("Error: during nfq_bind_pf()");
        return ERR_INIT;
    }
 
    queue = nfq_create_queue(handle, queuenum, &manage_packet, NULL);
 
    if (!queue) {
        perror("Error: during nfq_create_queue()");
        return ERR_INIT;
    }
 
    if (nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("Error: can't set packet_copy mode");
        return ERR_INIT;
    }
 
    netlink_handle = nfq_nfnlh(handle);
    nfqueue_fd = nfnl_fd(netlink_handle);
 
    char buf[4096] __attribute__ ((aligned));
    int received;
 
    while (1) {
        if ((received = recv(nfqueue_fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(handle, buf, received);
        }
    }
 
    if (!queue)
        nfq_destroy_queue(queue);
 
    if (!handle)
        nfq_close(handle);
 
    return 0;
}
