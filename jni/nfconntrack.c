#include "nf.h"

/**
 * init netfilter conn-track - return 0 on success
 */
int init_nfct(struct nfct_handle **h)
{
  printf("opening nfct library handle..\n");
  *h = nfct_open(CONNTRACK, 0);
  if (!(*h)) {
    printf("error during nfct_open()\n");
    return -1;
  }
  printf("nfct library handle opened\n");

  return 0;
}

static int nfct_buildct(unsigned char *packet, struct nf_conntrack *ct) {
  printf("build ct\n");
  struct ip *iphdr = (struct ip*) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));

  /* build tuple */
  nfct_set_attr_u8(ct, ATTR_L3PROTO, AF_INET);
  nfct_set_attr_u32(ct, ATTR_IPV4_SRC, iphdr->ip_src.s_addr);
  nfct_set_attr_u32(ct, ATTR_IPV4_DST, iphdr->ip_dst.s_addr);

  nfct_set_attr_u8(ct, ATTR_L4PROTO, IPPROTO_TCP);
  nfct_set_attr_u16(ct, ATTR_PORT_SRC, tcp->source);
  nfct_set_attr_u16(ct, ATTR_PORT_DST, tcp->dest);

  return 0;
}

int nfct_create_dnat(struct nfct_handle *cth, unsigned char *packet)
{
  int ret;
  struct nf_conntrack *ct = nfct_new();
  if (!ct) {
    printf("error during nfct_new()\n");
	return -1;
  }

  nfct_buildct(packet, ct);
/*
  printf("destroying old entry...\n");
  ret = nfct_query(cth, NFCT_Q_DESTROY, ct);
  if (ret == -1) {
	printf("failed to destroy old entry(%d)(%s)\n", ret, strerror(errno));
	printf("ignoring...\n");
  }
*/
  printf("setting up an dnat entry --> 127.0.0.1:7080\n");
  nfct_setobjopt(ct, NFCT_SOPT_SETUP_REPLY);
  nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_SYN_SENT);
  //nfct_set_attr_u8(ct, ATTR_TCP_STATE, TCP_CONNTRACK_ESTABLISHED);
  nfct_set_attr_u32(ct, ATTR_TIMEOUT, 100);

  nfct_set_attr_u32(ct, ATTR_DNAT_IPV4, inet_addr("127.0.0.1"));
  nfct_set_attr_u16(ct, ATTR_DNAT_PORT, htons(7080));

  printf("creating conntrack dnat...\n");
  ret = nfct_query(cth, NFCT_Q_CREATE, ct);
  if (ret == -1)
    printf("(%d)(%s)\n", ret, strerror(errno));
  else
    printf("(OK)\n");

  nfct_destroy(ct);
  return ret;
}

static unsigned short in_cksum(unsigned short *addr, int len) {
  int sum = 0;
  unsigned short answer = 0;
  unsigned short *w = addr;
  int nleft = len;

  while (nleft > 1) {
    sum += *w++;
    nleft -=2;
  }

  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(unsigned char *)w;
    sum += answer;
  }

  // add back carry outs from top 16 bits to low 16 bits
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

int nfct_dnat_packet(unsigned char *packet) {
  /* It will point to start of the packet buffer */
  struct ip *ipheader = (struct ip *)packet;

  /* It will point to the end of the IP header in packet buffer */
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip));

  int tcp_hdr_len = tcpheader->doff * 4;

  /* TPC Pseudoheader (used in checksum)    */
  tcp_phdr_t pseudohdr;

  /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  char tcpcsumblock[ sizeof(tcp_phdr_t) + tcp_hdr_len ];

  memset(&pseudohdr,0,sizeof(tcp_phdr_t));

  /* IP header */
  ipheader->ip_dst.s_addr = inet_addr("127.0.0.1");

  /* Tcp header */
  tcpheader->dest = htons(7080);

  /* Fill the pseudoheader so we can compute the TCP checksum*/
  pseudohdr.src = ipheader->ip_src.s_addr;
  pseudohdr.dst = ipheader->ip_dst.s_addr;
  pseudohdr.zero = 0;
  pseudohdr.protocol = ipheader->ip_p;
  pseudohdr.tcplen = htons( sizeof(struct tcphdr) );

  /* Copy header and pseudoheader to a buffer to compute the checksum */
  memcpy(tcpcsumblock, &pseudohdr, sizeof(tcp_phdr_t));
  memcpy(tcpcsumblock+sizeof(tcp_phdr_t),tcpheader, sizeof(struct tcphdr));

  /* Compute the TCP checksum as the standard says (RFC 793) */
  tcpheader->check = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));

  /* Compute the IP checksum as the standard says (RFC 791) */
  ipheader->ip_sum = in_cksum((unsigned short *)ipheader, sizeof(struct ip));

  return 0;
}
