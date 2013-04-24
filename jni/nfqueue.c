#include "nf.h"

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);

	fputc('\n', stdout);

	return id;
}

// return 0 if it is a tcp-syn & it's destination
// ip/port is not 127.0.0.1/7080
static bool is_sync_pkt(unsigned char *packet)
{
  printf("is_sync_pkt called\n");
  // get ip header
  struct ip *iphdr = (struct ip*) packet;
  int pkt_len = ntohs(iphdr->ip_len);
  printf("protocol: %d, pkt_len: %d\n", iphdr->ip_p, pkt_len);

  // it's a tcp packet, get tcp header
  if (iphdr->ip_p == 6) {
	printf("it's a tcp packet\n");
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));

    // it's a tcp syn and not to our listen socket
    if (tcp->syn == 1 && tcp->ack == 0 && pkt_len == (20 + tcp->doff * 4) &&
        /*iphdr->ip_dst.s_addr == "127.0.0.1" &&*/ tcp->dest != htons(7080)) {
      printf("it's an outgoing syn packet to %d, nat it...\n", ntohs(tcp->dest));
      return true;
    }
  }
  return false;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
  printf("entering callback\n");
  unsigned char *packet;
  u_int32_t id = print_pkt(nfa);
  struct nfct_handle *cth = (struct nfct_handle*) data;
  int len = nfq_get_payload(nfa, &packet);

  if (len > 40 && is_sync_pkt(packet)) {
    // create a conntrack dnat (-->127.0.0.1:7080)
	if (nfct_create_dnat(cth, packet) != -1) {
	  // dnat the packet
	  nfct_dnat_packet(packet);
	  // accept the modified packet
	  return nfq_set_verdict(qh, id, NF_ACCEPT, len, packet);
	} else {
	  printf("create dnat failed\n");
	}
  }
  // accept the packet
  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

/**
 * init nfq_handle - return 0 on success
 */
int init_nfq(struct nfq_handle **h, struct nfq_q_handle **qh, void *data) {
  printf("opening nfq library handle...\n");
  *h = nfq_open();
  if (!(*h)) {
    fprintf(stderr, "error during nfq_open()\n");
    return -1;
    //exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(*h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    return -1;
    //exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(*h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    return -1;
    //exit(1);
  }

  printf("binding this socket to queue '0'\n");
  *qh = nfq_create_queue(*h,  0, &cb, data);
  if (!(*qh)) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    return -1;
    //exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    return -1;
    //exit(1);
  }

  return 0;
}
