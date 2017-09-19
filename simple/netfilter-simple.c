/*************************************************************************************************
 * A Simple netfilter example -- drops all IP packets and logs to /var/log/messages
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
 * module functions
 * ===============================================================================================*/

unsigned int hook_func(
    void *priv,
    struct sk_buff *skb,
    const struct nf_hook_state *state
    ) 
{
    printk(KERN_INFO "packet dropped\n"); //log to var/log/messages
    return NF_DROP;                       //drops the packet
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
