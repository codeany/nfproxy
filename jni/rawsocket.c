
#include "nf.h"

/* send_tcp_syn(): Crafts a TCP packet with the SYN flag set using the supplied */
/* values and sends the packet through a raw socket.                            */
int send_tcp_syn(uint32 seq, uint32 src_ip, uint32 dst_ip, uint16 src_prt, uint16 dst_prt)
{
  static int i=0;
  int one=1; /* R.Stevens says we need this variable for the setsockopt call */

  /* Raw socket file descriptor */
  int rawsocket=0;

  /* Buffer for the TCP/IP SYN Packets */
  char packet[ sizeof(struct tcphdr) + sizeof(struct ip) +1 ];

  /* It will point to start of the packet buffer */
  struct ip *ipheader = (struct ip *)packet;

  /* It will point to the end of the IP header in packet buffer */
  struct tcphdr *tcpheader = (struct tcphdr *) (packet + sizeof(struct ip));

  /* TPC Pseudoheader (used in checksum)    */
  tcp_phdr_t pseudohdr;

  /* TCP Pseudoheader + TCP actual header used for computing the checksum */
  char tcpcsumblock[ sizeof(tcp_phdr_t) + TCPSYN_LEN ];

  /* Although we are creating our own IP packet with the destination address */
  /* on it, the sendto() system call requires the sockaddr_in structure */
  struct sockaddr_in dstaddr;

  memset(&pseudohdr,0,sizeof(tcp_phdr_t));
  memset(&packet, 0, sizeof(packet));
  memset(&dstaddr, 0, sizeof(dstaddr));

  dstaddr.sin_family = AF_INET;     /* Address family: Internet protocols */
  dstaddr.sin_port = dst_prt;      /* Leave it empty */
  dstaddr.sin_addr.s_addr = dst_ip; /* Destination IP */



  /* Get a raw socket to send TCP packets */
 if ( (rawsocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("TCP_RST_send():socket()");
        exit(1);
  }

  /* We need to tell the kernel that we'll be adding our own IP header */
  /* Otherwise the kernel will create its own. The ugly "one" variable */
  /* is a bit obscure but R.Stevens says we have to do it this way ;-) */
  if( setsockopt(rawsocket, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        perror("TCP_RST_send():setsockopt()");
        exit(1);
   }


  /* IP Header */
  ipheader->ip_hl = 5;     /* Header lenght in octects                       */
  ipheader->ip_v = 4;      /* Ip protocol version (IPv4)                     */
  ipheader->ip_tos = 0;    /* Type of Service (Usually zero)                 */
  ipheader->ip_len = htons( sizeof (struct ip) + sizeof (struct tcphdr) );
  ipheader->ip_off = 0;    /* Fragment offset. We'll not use this            */
  ipheader->ip_ttl = 64;   /* Time to live: 64 in Linux, 128 in Windows...   */
  ipheader->ip_p = 6;      /* Transport layer prot. TCP=6, UDP=17, ICMP=1... */
  ipheader->ip_sum = 0;    /* Checksum. It has to be zero for the moment     */
  ipheader->ip_id = htons( 1337 );
  ipheader->ip_src.s_addr = src_ip;  /* Source IP address                    */
  ipheader->ip_dst.s_addr = dst_ip;  /* Destination IP address               */

  /* TCP Header */
  tcpheader->source  = src_prt;  /* Source Port                              */
  tcpheader->dest    = dst_prt;  /* Destination Port                         */
  tcpheader->seq     = seq;      /* Sequence Number                          */
  tcpheader->ack_seq = 0;        /* Acknowledgment Number                   */
  tcpheader->doff    = 5;        /* Segment offset (Lenght of the header)    */
  tcpheader->res1    = 0;        /* Reserved bytes 1                         */
  tcpheader->cwr     = 0;
  tcpheader->ece     = 0;
  tcpheader->urg     = 0;        /* TCP Flags.                               */
  tcpheader->ack     = 0;
  tcpheader->psh     = 0;
  tcpheader->rst     = 0;
  tcpheader->syn     = 1;        /* only set SYN flag                        */
  tcpheader->fin     = 0;
  tcpheader->window  = htons(4500) + rand()%1000; /* Window size             */
  tcpheader->urg_ptr = 0;        /* Urgent pointer.                          */
  tcpheader->check   = 0;        /* Checksum. (Zero until computed)          */

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

  /* Send it through the raw socket */
  if ( sendto(rawsocket, packet, ntohs(ipheader->ip_len), 0,
                  (struct sockaddr *) &dstaddr, sizeof (dstaddr)) < 0){
        return -1;
    }

  printf("Sent RST Packet:\n");
  printf("   SRC: %s:%d\n", inet_ntoa(ipheader->ip_src), ntohs(tcpheader->source));
  printf("   DST: %s:%d\n", inet_ntoa(ipheader->ip_dst), ntohs(tcpheader->dest));
  printf("   Seq=%u\n", ntohl(tcpheader->seq));
  printf("   Ack=%d\n", ntohl(tcpheader->ack_seq));
  printf("   TCPsum: %02x\n",  tcpheader->check);
  printf("   IPsum: %02x\n", ipheader->ip_sum);

  close(rawsocket);

return 0;


} /* End of IP_Id_send() */
