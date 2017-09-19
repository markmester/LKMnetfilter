/*************************************************************************************************
 * Another Simple netfilter example -- drops all traffic on "lo" interface, drop all traffic coming
 * from 208.80.154.224 (wikipedia, drops all ping requests/responses, and finally modifies all dns
 * resolutions to point to 172.217.10.110 (google)
 ************************************************************************************************/

// standard includes
#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */

// netfliter specific includes
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h> 
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

/* ===============================================================================================
 * globals
 * * ===============================================================================================*/
static unsigned char *blocked_ip = "\xD0\x50\x9A\xE0"; // IP we're blocking traffic 
static char *blocked_interface = "lo"; // interface we're blocking traffic on
struct sk_buff *sock_buff; // struct to copy packet over to
struct udphdr *udp_header; // struct to copy udp header over to

/* ===============================================================================================
 * module functions
 * ===============================================================================================*/
unsigned int hook_func(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    ) 
{
    // block traffic recieved on "blocked_interface"
    if(strcmp(state->in, blocked_interface) == 0) {
    printk(KERN_INFO "Dropping packet recieved on interface: %s\n", state->in); 

    return NF_DROP;
    }

    sock_buff = *skb;
    
    // check for valid sk_buff and validate IP packet
    if(!sock_buff || !(sock_buff->nh.iph)) { return NF_ACCEPT; }    

    // compare source address with block IP
    if(sock_buff->nh.iph->saddr == *(unsigned int*)ip_address) {
        printk(KERN_INFO "Dropping packet with source address: %s\n", *(unsigned int*)blocked_ip);    
            
        return NF_DROP; 
    }
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
    nf_register_hook(&nfho);          //register hook

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
