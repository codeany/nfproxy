#ifndef NF_H_
#define NF_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <netinet/ip.h>     // Internet Protocol
#include <netinet/tcp.h>    // Transmission Control Protocol


#ifndef bool
typedef enum { false, true } bool;
#endif

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#ifndef uint32
typedef unsigned int uint32;
#endif

#ifndef uint16
typedef unsigned short uint16;
#endif

#ifndef uchar
typedef unsigned char uchar;
#endif

#define TCPSYN_LEN 20

/* pseudoheader of tcp - used to calculate TCP checksum */
typedef struct pseudoheader {
  uint32 src;
  uint32 dst;
  uchar  zero;
  uchar  protocol;
  uint16 tcplen;
} tcp_phdr_t;

int init_nfq(struct nfq_handle **qh, struct nfq_q_handle **qqh, void *data);

int init_nfct(struct nfct_handle **cth);

int nfct_create_dnat(struct nfct_handle *cth, uchar *packet);

int nfct_dnat_packet(uchar *packet);

int send_tcp_syn(uint32 seq, uint32 src_ip, uint32 dst_ip, uint16 src_prt, uint16 dst_prt);

#endif
