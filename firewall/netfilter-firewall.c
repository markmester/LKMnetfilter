/*************************************************************************************************
 * Simple netfilter example for mangling IP traffic -- drops all traffic on "lo" interface, all traffic coming
 * from the 208.80.154.0/24 (wikipedia), all ping requests/responses, and all dns traffic.
 ************************************************************************************************/
#define DEBUG
#define UDP_HDR_LEN 8

/* standard includes */
#include <linux/module.h>  // Needed by all kernel modules
#include <linux/kernel.h>  // Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.)
#include <linux/init.h>    // Needed for __init and __exit macros.

/* netfliter specific includes */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h> 
#include <linux/net.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* ===============================================================================================
 * globals
 * * ===============================================================================================*/
static int blocked_ip[4] = {208, 80, 154, 240};         // Using the 1st 3 octets to block /24 subnet
static unsigned int blocked_subnet;                     // int representation of calculated /24 subnet
static char *blocked_interface = "lo";                  // interface we're blocking traffic on
struct sk_buff *sock_buff;                              // struct to copy packet over to
struct udphdr *udp_header;                              // struct to copy udp header over to
struct iphdr *ip_header;                                // struct to copy ip header over to
struct tcphdr *tcp_header;                              // struct to copy tcp header over to
unsigned int sport, dport, saddr, daddr;                // source/dest addresses/ports of ip header
char source_addr[16], dest_addr[16];                    //string rep. of source/dest addresses

/* ===============================================================================================
 * module functions
 * ===============================================================================================*/

/*Function for accesing payload of skb
 * @param sk: sk_buff struct
 * */
static void recv_tcpdata(struct sk_buff* skb) {
    unsigned char *user_data;   // TCP data begin pointer
    unsigned char *tail;        // TCP data end pointer
    unsigned char *it;          // TCP data iterator
    int tcpdatalen;             // TCP payload length
    
    /* Calculate pointers for begin and end of TCP packet data */
    user_data = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
    tail = skb_tail_pointer(skb);
    
    /* Calculate TCP payload size and init. payload char array */
    tcpdatalen = ntohs(ip_header->tot_len) - (tcp_header->doff * 4) - (ip_header->ihl * 4);

    /* Print HTTP packet payload */
    if (user_data[0] == 'H' && user_data[1] == 'T' && user_data[2] == 'T' && user_data[3] == 'P') {
        printk(KERN_INFO "---------------HTTP Data-------------------\n");
        for(it = user_data; it != tail; ++it) {
            char c = *(char *)it;
            
            printk(KERN_INFO "%c", c);

            if(c == '\0') { 
                break; 
            };
        }
    }
}

/* Function for getting int representation of subnet we're blocking
 *@param ip: int array consisting of ip used to claculate int subnet
 *@param size: size of blocked_ip int array
 * */
unsigned int calc_subnet(int ip[], int size) {
    /* convert ip address to int representing it's /24 subnet */
    unsigned int subnet = ip[0];
    int i;

    for(i=1;i<(size - 1);i++) { // don't include last octet
        subnet = (subnet << 8) ^ ip[i];
    }
    subnet = subnet << 8; // shift left for last zeroed-out octet

    return subnet;
}

/* Function for logging route of recieved packed
 * @param sport: source port
 * @param dport: dest. port
 * @param saddr: source address
 * @param daddr: dest. address
 * @param type: type of traffic e.g. TCP, UDP, etc.
 * */
void print_route(unsigned int sport, unsigned int dport, char *saddr, char *daddr, char *type) {
#ifdef DEBUG
    printk(KERN_INFO ">>> %s route: %s:%d -> %s:%d\n", type, source_addr, sport, dest_addr, dport);
#endif
    return;
}
/* Hook function for packets of interest.
 * @param priv:
 * @param skb: pointer to the sk_buff structure with the packet to be handled.
 * @param nf_hook_state: 
 */
unsigned int hook_func(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    ) 
{
    
    
    /* Drop packets recieved on lo interface
    if(strcmp((char*)state->in, blocked_interface) == 0) {
        printk(KERN_INFO ">>> Dropping packet recieved on interface: %s\n", (char *)state->in); 

         return NF_DROP;
    }
    */

    /* copy packet and grab network header */
    sock_buff = skb;

    /* ip_header = (struct iphdr *)skb_network_header(sock_buff); */
    ip_header = ip_hdr(sock_buff);

    /* check for valid sk_buff and validate IP packet */
    if(!sock_buff || !ip_header) { return NF_ACCEPT; }    

    /* get source and destination pf packet */
    snprintf(source_addr, 16, "%pI4", &ip_header->saddr);
    snprintf(dest_addr, 16, "%pI4", &ip_header->daddr);


    switch(ip_header->protocol) {
        case IPPROTO_TCP: // TCP Packet Handling

            /* first log some routing info */
            tcp_header = tcp_hdr(sock_buff);
            sport = htons((unsigned short int) tcp_header->source);
            dport = htons((unsigned short int) tcp_header->dest);
            print_route(sport, dport, source_addr, dest_addr, "TCP");

            /* now drop any packets recived from 208.80.154.0/24 (wikipedia)        
             * first convert host byte order to network byte order and zero out last octet */
            saddr = htonl((ip_header->saddr)) >> 8 << 8;

            if(saddr == blocked_subnet) {
                printk(KERN_INFO ">>> Dropping packet recieved from Wikipedia\n");
                
                return NF_DROP;
            }

            /* Print out http payload for fun :-) */
            recv_tcpdata(sock_buff);
        
        return NF_ACCEPT; 
    
    case IPPROTO_UDP: // UDP packet handling
        udp_header = udp_hdr(sock_buff);
        sport = htons((unsigned short int) udp_header->source);
        dport = htons((unsigned short int) udp_header->dest);
        print_route(sport, dport, source_addr, dest_addr, "UDP");
            
            if(sport == 53 || dport == 53) {
                printk(KERN_INFO ">>> Discovered DNS packet...\n");
            }

            return NF_DROP;
        
        case IPPROTO_ICMP: // ICMP packet handling
            printk(KERN_INFO "Dropping packet with ICMP protocol\n");
            
            return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = {      // struct holding set of hook function options
    .hook       = hook_func,            //function to call when conditions below met
    .hooknum    = NF_INET_PRE_ROUTING,  //called right after packet recieved, first hook in Netfilter
    .pf         = PF_INET,              // IPV4 packets
    .priority   = NF_IP_PRI_FIRST       // set highest priority over all other hook fuctions
};

/* ================================================================================================
 * entry function
 * ================================================================================================*/
static int __init onload(void) {
    /* get int representation of subnet we're blocking */
    blocked_subnet = calc_subnet(blocked_ip, sizeof(blocked_ip)/sizeof(blocked_ip[0]));

    /* register hook */
    nf_register_hook(&nfho);

    printk(KERN_EMERG "Loadable module initialized\n"); 

    return 0;
}


/* ================================================================================================
 * exit function
 * ================================================================================================*/
static void __exit onunload(void) {
    nf_unregister_hook(&nfho);
    printk(KERN_EMERG "Loadable module removed\n");
}


/* ================================================================================================
 * register entry/exit functions
 * ================================================================================================*/
module_init(onload);
module_exit(onunload);


/* ================================================================================================
 * metadata
 * ================================================================================================*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mark Mester <mmester@parrylabs.com>");
MODULE_DESCRIPTION("A simple skeleton for a loadable Linux kernel module");

// EOF
