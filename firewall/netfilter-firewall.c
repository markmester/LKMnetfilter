/*************************************************************************************************
 * Another Simple netfilter example -- drops all traffic on "lo" interface, drop all traffic coming
 * from the 208.80.154.0/24 (wikipedia, drops all ping requests/responses, and finally modifies all dns
 * resolutions for google to point to yahoo
 ************************************************************************************************/

// standard includes
#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */

// netfliter specific includes
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
static int blocked_ip[4] = {208, 80, 154, 240}; // Using the 1st 3 octets to block /24 subnet
static unsigned int blocked_subnet; // int representation of calculated /24 subnet
static char *blocked_interface = "lo"; // interface we're blocking traffic on
struct sk_buff *sock_buff; // struct to copy packet over to
struct udphdr *udp_header; // struct to copy udp header over to
struct iphdr *ip_header;   // struct to copy ip header over to
struct tcphdr *tcp_header;  // struct to copy tcp header over to
unsigned int sport, dport;
char source_addr[16], dest_addr[16];

/* ===============================================================================================
 * module functions
 * ===============================================================================================*/

/* Function for getting int representation of subnet we're blocking
 *@param blocked_ip: int array consisting of ip used to claculate int subnet
 *@param size: size of blocked_ip int array
 * */
unsigned int calc_subnet(int ip[], int size) {
    // convert ip address to int representing it's /24 subnet
    unsigned int subnet = ip[0];
    int i;

    for(i=1;i<(size - 1);i++) { // don't include last octet
        subnet = (subnet << 8) ^ ip[i];
        printk(KERN_INFO "%u\n", subnet);
    }
    subnet = subnet << 8; // shift left for last zeroed-out octet

    return subnet;
}

unsigned int hook_func(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    ) 
{
    
    // Drop packets recieved on lo interface
    if(strcmp((char*)state->in, blocked_interface) == 0) {
        printk(KERN_INFO "Dropping packet recieved on interface: %s\n", (char *)state->in); 

        // return NF_DROP;
        return NF_ACCEPT;
    }

    // copy packet and grab network header
    sock_buff = skb;
    
    //ip_header = (struct iphdr *)skb_network_header(sock_buff);
    ip_header = ip_hdr(sock_buff);

    // check for valid sk_buff and validate IP packet
    if(!sock_buff || !ip_header) { return NF_ACCEPT; }    

    // TCP packet handling
    if(ip_header->protocol == IPPROTO_TCP) { 
        // first log some routing info
        tcp_header = tcp_hdr(sock_buff);
        snprintf(source_addr, 16, "%pI4", &ip_header->saddr);
        snprintf(dest_addr, 16, "%pI4", &ip_header->daddr);
        sport = htons((unsigned short int) tcp_header->source);
        dport = htons((unsigned short int) tcp_header->dest);
        printk(KERN_INFO "TCP route: %s:%d -> %s:%d\n", source_addr, sport, dest_addr, dport);
        printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
        
        // now drop any packets recived from 208.80.154.0/24 (wikipedia)        
        unsigned int saddr = htonl((ip_header->saddr)); // convert host byte order to network byte order
       saddr = saddr >> 8 << 8; // zero out last octet

        if(saddr == blocked_subnet) {
            printk(KERN_INFO "Dropping packet recieved from Wikipedia\n");
            
            //printk(KERN_INFO ">>>source subnet>>> %u\n", saddr);
            //printk(KERN_INFO ">>>blocked subnet>>> %u\n", blocked_subnet);

            return NF_DROP;
        }
        
        return NF_ACCEPT; 
    }

    // drop icmp packets
    if(ip_header->protocol == IPPROTO_ICMP) {
        printk(KERN_INFO "Dropping packet with ICMP protocol\n");
        
        return NF_DROP;
    }


    return NF_ACCEPT;
}

static struct nf_hook_ops nfho = { // struct holding set of hook function options
    .hook       = hook_func, //function to call when conditions below met
    .hooknum    = NF_INET_PRE_ROUTING, //called right after packet recieved, first hook in Netfilter
    .pf         = PF_INET, // IPV4 packets
    .priority   = NF_IP_PRI_FIRST // set highest priority over all other hook fuctions
};

/* ================================================================================================
 * entry function
 * ================================================================================================*/
static int __init onload(void) {
    // get int representation of subnet we're blocking
    blocked_subnet = calc_subnet(blocked_ip, sizeof(blocked_ip)/sizeof(blocked_ip[0]));

    // register hook
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
