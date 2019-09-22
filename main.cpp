#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <pcap.h>

#define HEXMACLEN 17
#define MAXPAYLEN 32

#define IPSZ(ip)          ((ip->ip_hl) * 4)
#define TCPSZ(tcp)        ((tcp->th_off) * 4)
#define ETHERNET(pkt)     ((struct ethhdr*)(pkt))
#define IP(pkt)           ((struct ip*)(pkt + ETH_HLEN))
#define TCP(pkt)          ((struct tcphdr*)(pkt + ETH_HLEN + IPSZ(IP(pkt))))
#define PAYLOAD(pkt)      ((char *)(pkt + ETH_HLEN + IPSZ(IP(pkt)) + TCPSZ(TCP(pkt))))

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

/*
 Name: parse_mac
 Type: function
 Description:
  Parse src/dst MAC addresses from ethernet header, and save it into argument buffers.
 Args:
  struct ethhdr* ethernet : ptr of ethernet
  char* src_mac : source mac address buffer
  char* dst_mac : destination mac address buffer
 Change log:
  Replace bad use of strlen()
*/
void parse_mac(struct ethhdr* ethernet, char* src_mac, char* dst_mac){
  int len=0;

  for(int i=0; i<ETH_ALEN; i++){
    sprintf(src_mac+len,"%02X",ethernet->h_source[i]);
    sprintf(dst_mac+len,"%02X",ethernet->h_dest[i]);
    
    if(i != ETH_ALEN-1){
      strcat(src_mac,":");
      strcat(dst_mac,":");
    }
    
    len += 3;
  }
}

/*
 Name: print_hex
 Type: function
 Description:
  Print data of buffer encoded in hex form.
 Args:
  char *buf: target buffer of print
  int buf_len: length of buffer
  int maxlen: max print length
 Change log:
  Replace bad use of strlen()
*/
void print_hex(char *buf, int buf_len, int maxlen){
  int len = buf_len < maxlen ? buf_len : maxlen;

  for(int i=1; i<=len; i++){
    printf("%02X ",buf[i-1]);
    if(i%0x10 == 0)
      printf("\n");
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    struct ethhdr* ethernet;
    struct ip* ip;
    struct tcphdr* tcp;
    char src_mac[HEXMACLEN+1], dst_mac[HEXMACLEN+1];
    char *payload;
    char *src_ip, *dst_ip;
    int ip_size, tcp_size, payload_size;

    // Nullify arrays
    memset(src_mac, 0, HEXMACLEN+1);
    memset(dst_mac, 0, HEXMACLEN+1);

    // Capture packet
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    // ETHERNET: parse source mac address and destination mac address
    ethernet = ETHERNET(packet);
    parse_mac(ethernet, src_mac, dst_mac);
    printf("Ethernet(src_mac/dst_mac): %s / %s\n", src_mac, dst_mac);

    // Check if packet has IP layer
    if(ethernet->h_proto != ntohs(ETH_P_IP))
      goto next;

    // IP: parse source IP address and destination IP address
    ip = IP(packet);
    ip_size = IPSZ(ip);
    src_ip = inet_ntoa(ip->ip_src);
    dst_ip = inet_ntoa(ip->ip_dst);
    printf("IP(src ip/dst ip): %s / %s\n", src_ip, dst_ip);

    // Check if packet has TCP layer
    if(ip->ip_p != IPPROTO_TCP)
      goto next;
    
    // TCP: parse source port, destination port and payload.
    tcp = TCP(packet);
    tcp_size = TCPSZ(tcp);
    printf("TCP(src port/dst port): %hu / %hu\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    payload_size = ntohs(ip->ip_len) - (ip_size + tcp_size);

    if(payload_size != 0){
      payload = PAYLOAD(packet);
      printf("Payload: \n");
      print_hex(payload, payload_size, MAXPAYLEN);
    }

    next:
      printf("\n");
  }

  pcap_close(handle);
  return 0;
}
