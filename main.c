#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_utun.h>

#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <ifaddrs.h>
#include <errno.h>

#include <arpa/inet.h>

//#if defined(__APPLE__) && defined(HAVE_NET_UTUN_H)
#include <sys/kern_control.h>
#include <sys/sys_domain.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
//#endif

// from if_tun.h because it does not exist on mac. TUNSETIFF ifr flags
#define IFF_TUN 0x0001
#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000
#define IFF_ONE_QUEUE 0x2000
#define IFF_VNET_HDR 0x4000
#define IFF_TUN_EXCL 0x8000

static char *device_ptr;

#define BUFFER_LEN 2048

//#define ARP_ETHERNET_FRAME_TYPE 0x0806            // 1544, ARP, Address resolution protocol ethernet frame type
#define ETHERTYPE_ARP_ENDIANNESS 0x0608 // endianess changed

#define ETHERTYPE_IP_ENDIANNESS 0x0008 // IPv4 endianess changed

#define ARP_802DOT2_FRAME_TYPE 0x0004 // 1024 is in fact 0x0004 = 802.2 frames

struct eth_hdr
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
} __attribute__((packed));

struct arp_hdr
{
    uint16_t hwtype;
    uint16_t protype;
    unsigned char hwsize;
    unsigned char prosize;
    uint16_t opcode;
    unsigned char data[];
} __attribute__((packed));

/*
int tuntap_sys_start(struct device *dev, int mode, int tun)
{
    struct ifreq ifr;
    struct ifaddrs *ifa;
    char name[MAXPATHLEN];
    int fd;
    char *type;

    fd = -1;

    // Force creation of the driver if needed or let it resilient
    if (mode & TUNTAP_MODE_PERSIST)
    {
        tuntap_log(TUNTAP_LOG_NOTICE,
                   "Your system does not support persistent device");
        return -1;
    }

    // Set the mode: tun or tap
    if (mode == TUNTAP_MODE_ETHERNET)
    {
        type = "tap";
        ifr.ifr_flags |= IFF_LINK0;
    }
    else if (mode == TUNTAP_MODE_TUNNEL)
    {
        type = "tun";
        ifr.ifr_flags &= ~IFF_LINK0;
    }
    else
    {
        tuntap_log(TUNTAP_LOG_ERR, "Invalid parameter 'mode'");
        return -1;
    }

    // Try to use the given driver or loop throught the avaible ones
    if (tun < TUNTAP_ID_MAX)
    {
        (void)snprintf(name, sizeof name, "/dev/%s%i", type, tun);
        fd = open(name, O_RDWR);
    }
    else if (tun == TUNTAP_ID_ANY)
    {
        for (tun = 0; tun < TUNTAP_ID_MAX; ++tun)
        {
            (void)memset(name, '\0', sizeof name);
            (void)snprintf(name, sizeof name, "/dev/%s%i",
                           type, tun);
            if ((fd = open(name, O_RDWR)) > 0)
                break;
        }
    }
    else
    {
        tuntap_log(TUNTAP_LOG_ERR, "Invalid parameter 'tun'");
        return -1;
    }
    switch (fd)
    {
    case -1:
        tuntap_log(TUNTAP_LOG_ERR, "Permission denied");
        return -1;
    case 256:
        tuntap_log(TUNTAP_LOG_ERR, "Can't find a tun entry");
        return -1;
    default:
        // NOTREACHED
        break;
    }

    // Set the interface name
    (void)memset(&ifr, '\0', sizeof ifr);
    (void)snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s%i", type, tun);
    // And save it
    (void)strlcpy(dev->if_name, ifr.ifr_name, sizeof dev->if_name);

    // Get the interface default values
    if (ioctl(dev->ctrl_sock, SIOCGIFFLAGS, &ifr) == -1)
    {
        tuntap_log(TUNTAP_LOG_ERR, "Can't get interface values");
        return -1;
    }

    // Set our modifications
    if (ioctl(dev->ctrl_sock, SIOCSIFFLAGS, &ifr) == -1)
    {
        tuntap_log(TUNTAP_LOG_ERR, "Can't set interface values");
        return -1;
    }

    // Save flags for tuntap_{up, down}
    dev->flags = ifr.ifr_flags;

    // Save pre-existing MAC address
    if (mode == TUNTAP_MODE_ETHERNET && getifaddrs(&ifa) == 0)
    {
        struct ifaddrs *pifa;

        for (pifa = ifa; pifa != NULL; pifa = pifa->ifa_next)
        {
            if (strcmp(pifa->ifa_name, dev->if_name) == 0)
            {
                struct ether_addr eth_addr;

                // The MAC address is from 10 to 15.
                //
                // And yes, I know, the buffer is supposed
                // to have a size of 14 bytes.
                (void)memcpy(dev->hwaddr,
                             pifa->ifa_addr->sa_data + 10,
                             ETHER_ADDR_LEN);

                (void)memset(&eth_addr.ether_addr_octet, 0,
                             ETHER_ADDR_LEN);
                (void)memcpy(&eth_addr.ether_addr_octet,
                             pifa->ifa_addr->sa_data + 10,
                             ETHER_ADDR_LEN);
                break;
            }
        }
        if (pifa == NULL)
            tuntap_log(TUNTAP_LOG_WARN,
                       "Can't get link-layer address");
        freeifaddrs(ifa);
    }
    return fd;
}

void tuntap_sys_destroy(struct device *dev)
{
    (void)dev;
}

int tuntap_sys_set_hwaddr(struct device *dev, struct ether_addr *eth_addr)
{
    struct ifreq ifr;

    (void)memset(&ifr, '\0', sizeof ifr);
    (void)strlcpy(ifr.ifr_name, dev->if_name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
    ifr.ifr_addr.sa_family = AF_LINK;
    (void)memcpy(ifr.ifr_addr.sa_data, eth_addr, ETHER_ADDR_LEN);
    if (ioctl(dev->ctrl_sock, SIOCSIFLLADDR, &ifr) < 0)
    {
        tuntap_log(TUNTAP_LOG_ERR, "Can't set link-layer address");
        return -1;
    }
    return 0;
}



int tuntap_sys_set_descr(struct device *dev, const char *descr, size_t len)
{
    tuntap_log(TUNTAP_LOG_NOTICE,
               "Your system does not support tuntap_set_descr()");
    return -1;
}

char *
tuntap_sys_get_descr(struct device *dev)
{
    (void)dev;
    tuntap_log(TUNTAP_LOG_NOTICE,
               "Your system does not support tuntap_get_descr()");
    return NULL;
}
*/

#if defined Windows
typedef IN_ADDR t_tun_in_addr;
typedef IN6_ADDR t_tun_in6_addr;
#else /* Unix */
typedef struct in_addr t_tun_in_addr;
typedef struct in6_addr t_tun_in6_addr;
#endif

typedef int t_tun;

struct device
{
    t_tun tun_fd;
    int ctrl_sock;
    int flags; /* ifr.ifr_flags on Unix */
    unsigned char hwaddr[ETHER_ADDR_LEN];
    char if_name[IF_NAMESIZE + 1];
};

//int tuntap_sys_set_ipv4(struct device *dev, t_tun_in_addr *s4, uint32_t bits)
int tuntap_sys_set_ipv4(struct device *dev, t_tun_in_addr *s4, uint32_t bits)
{
    struct ifaliasreq ifa;
    struct ifreq ifr;
    struct sockaddr_in addr;
    struct sockaddr_in mask;

    memset(&ifa, '\0', sizeof ifa);
    strlcpy(ifa.ifra_name, dev->if_name, sizeof(ifa.ifra_name));

    printf("A) %s\n", ifa.ifra_name);

    memset(&ifr, '\0', sizeof ifr);
    strlcpy(ifr.ifr_name, dev->if_name, sizeof(ifr.ifr_name));

    printf("B) %s\n", ifr.ifr_name);

    // Delete previously assigned address
    //ioctl(dev->ctrl_sock, SIOCDIFADDR, &ifr);

    // Fill-in the destination address and netmask,
    // but don't care of the broadcast address
    (void)memset(&addr, '\0', sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = s4->s_addr;
    addr.sin_len = sizeof(addr);
    (void)memcpy(&ifa.ifra_addr, &addr, sizeof addr);

    (void)memset(&mask, '\0', sizeof mask);
    mask.sin_family = AF_INET;
    mask.sin_addr.s_addr = bits;
    mask.sin_len = sizeof(mask);
    (void)memcpy(&ifa.ifra_mask, &mask, sizeof ifa.ifra_mask);

    // Simpler than calling SIOCSIFADDR and/or SIOCSIFBRDADDR
    if (ioctl(dev->ctrl_sock, SIOCSIFADDR, &ifa) == -1)
    {
        //tuntap_log(TUNTAP_LOG_ERR, "Can't set IP/netmask");
        printf("Can't set IP/netmask\n");
        printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        printf("If the error is 'operation not permitted' make sure you have to run this app with administrator rights (sudo)!\n");

        return -1;
    }

    return 0;
}

/*
//static int set_ip(struct ifreq *ifr, int sock, ip4_addr_t ip4)
//static int set_ip(struct ifreq *ifr, int sock)
static int set_ip(struct ifaliasreq *ifr, int sock)

{
    struct sockaddr_in addr;

    // set the IP of this end point of tunnel
    memset(&addr, 0, sizeof(addr));

    // network byte order
    //addr.sin_addr.s_addr = ip4;
    //inet_aton("10.10.10.1", &addr.sin_addr);

    //in_addr_t in_addr = inet_addr("192.168.101.17");
    in_addr_t in_addr = inet_addr("127.0.0.1");
    addr.sin_addr.s_addr = in_addr;

    addr.sin_family = AF_INET;
    //memcpy(&ifr->ifr_addr, &addr, sizeof(struct sockaddr));
    memcpy(&ifr->ifra_addr, &addr, sizeof(struct sockaddr));

    //if (ioctl(sock, SIOCSIFADDR, ifr) < 0)
    if (ioctl(sock, SIOCAIFADDR, ifr) < 0)
    {
        //printf("SIOCSIFADDR: %s\n", strerror(errno));
        printf("SIOCAIFADDR: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}*/

/*
http://tuntaposx.sourceforge.net/faq.xhtml

I'm a developer and I try to read() and write() to the character devices. However, 
all it gives me is an "Input/Output error". 
Why is that?

You can only read and write packets from and to the kernel while the corresponding network interface is up. 
The setup sequence is as follows (using tap0 as an example):

    open() the character device /dev/tap0.
    Configure the network interface tap0 and bring it up. 
    Typically, you'll also want to assign an IP address. 
    Here is an example using ifconfig (but you can also configure the device programatically using the usual IOCTLs):

    ifconfig tap0 10.1.2.3 up
    							
    Once the interface has been brought up, you can use the read() and write() functions on the character device's 
    file descriptor to receive or send a packet at a time.
    When you're done, close() the character device. This will remove the network interface from the system. 
     */

void print_hex_memory(void *mem, const int len)
{
    int i;
    unsigned char *p = (unsigned char *)mem;
    for (i = 0; i < len; i++)
    {

        // after 16 bytes, insert a newline
        if ((i % 16 == 0) && i > 0)
        {
            printf("\n");
        }

        printf("0x%02x ", p[i]);
    }
    printf("\n");
}

/*
 * Taken from Kernel Documentation/networking/tuntap.txt
 */
static int tun_alloc(char *dev)
{
    //struct ifreq ifr;
    struct ifaliasreq ifr;
    int fd, err;

    //if ((fd = open("/dev/net/tap", O_RDWR)) < 0)
    if ((fd = open("/dev/tap0", O_RDWR)) < 0)
    {
        perror("Cannot open TUN/TAP dev\n"
               "Make sure one exists with "
               "'$ mknod /dev/tap0 c 10 200'");

        return 1;
    }

    printf("device is opened %d!\n", fd);

    //set_ip(&ifr, fd, );

    // before this timesout, type
    // sudo ifconfig tap0 10.10.10.1 10.10.10.255
    // sudo ifconfig tap0 up
    //sleep(10);

    //CLEAR(ifr);
    memset(&ifr, 0, sizeof(ifr));

    printf("device is cleared!\n");

    // Flags: IFF_TUN   - TUN device (no Ethernet headers)
    //        IFF_TAP   - TAP device
    //
    //        IFF_NO_PI - Do not provide packet information
    //
    //ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (*dev)
    {
        strncpy(ifr.ifra_name, dev, IFNAMSIZ);
    }
    printf("device name '%s'\n", ifr.ifra_name);

    printf("Creating socket ...\n");
    int sock = -1;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        return -3;
    }
    printf("Creating socket done %d!\n", sock);

    //ioctl(fd, SIOCGIFFLAGS, &ifr);
    //ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    //ioctl(fd, SIOCSIFFLAGS, &ifr);

    printf("Setting ip ...\n");

    //in_addr_t in_addr = inet_addr("127.0.0.1");
    in_addr_t in_addr = inet_addr("10.10.10.1");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_addr.s_addr = in_addr;

    struct device libDevice;
    memset(&libDevice, 0, sizeof(struct device));
    strncpy(libDevice.if_name, "tap0\0", IFNAMSIZ);
    libDevice.ctrl_sock = sock;
    libDevice.flags &= IFF_LINK0;

    printf("tuntap_sys_set_ipv4 ...!\n");
    //if (tuntap_sys_set_ipv4(&libDevice, &(addr.sin_addr), IFF_UP | IFF_RUNNING) != 0)
    //if (tuntap_sys_set_ipv4(&libDevice, &(addr.sin_addr), IFF_UP) != 0)

    uint32_t bits;
    inet_pton(AF_INET, "10.10.10.255", &bits);

    if (tuntap_sys_set_ipv4(&libDevice, &(addr.sin_addr), bits) != 0)
    {
        printf("tuntap_sys_set_ipv4 failed!\n");
        return -1;
    }
    printf("tuntap_sys_set_ipv4 done.!\n");

    //sleep(10);

    /*
    if (set_ip(&ifr, sock) < 0)
    //if (set_ip(&ifr, fd) < 0)
    {
        printf("Setting ip failed!\n");
        printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        return -4;
    }
     */

    printf("Setting ip done.\n");

    /*
    // Get the interface default values
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {
        printf("Can't get interface values\n");
        printf("ERRNO: (%d) %s\n", errno, strerror(errno));

        return -1;
    }
    */

    /*
    // Set our modifications
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1)
    {
        printf("Can't set interface values\n");
        printf("ERRNO: (%d) %s\n", errno, strerror(errno));

        return -1;
    }
 */

    //
    // read and output mac address
    //

    struct ifaddrs *ifa = 0;
    if (getifaddrs(&ifa) != 0)
    {
        printf("Could not retrieve if addresses!\n");
        goto cleanup;
    }
    if (ifa == NULL)
    {
        printf("Can't get link-layer address\n");
    }

    struct ether_addr eth_addr;

    struct ifaddrs *pifa = 0;
    for (pifa = ifa; pifa != NULL; pifa = pifa->ifa_next)
    {
        // only output the addresses of the tun/tap interface
        if (strcmp(pifa->ifa_name, ifr.ifra_name) != 0)
        {
            continue;
        }

        printf("addresses found for ifc!\n");

        // The MAC address is from 10 to 15.
        //
        // And yes, I know, the buffer is supposed
        // to have a size of 14 bytes.
        //(void)memcpy(dev->hwaddr,
        //             pifa->ifa_addr->sa_data + 10,
        //            ETHER_ADDR_LEN);

        // initialize with zeroes
        (void)memset(&eth_addr.ether_addr_octet, 0, ETHER_ADDR_LEN);

        // copy data in
        (void)memcpy(&eth_addr.ether_addr_octet, pifa->ifa_addr->sa_data + 10, ETHER_ADDR_LEN);
        break;
    }

    printf("MAC: %s\n", ether_ntoa(&eth_addr));

    freeifaddrs(ifa);
    ifa = 0;

    /*
     * ioctl() ==  input/output control == system call
     * 
     * http://man7.org/linux/man-pages/man2/ioctl.2.html
     * 
     * Sends request codes to drivers. The reaction to the code is up to the driver implementation.
     * 
     * Parameters:
     * int fd -  file descriptor
     * unsigend long request - request code
     * ... - variadic parameter list
     
    // Call the TUNSETIFF ioctl to select the device mode and options.
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0)
    {
        perror("ERR: Could not ioctl tun");
        close(fd);
        return err;
    }*/

    //strcpy(dev, ifr.ifr_name);

    /* setup ip 
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return -3;

    if (set_ip(&ifr_tap, sock, local_ip) < 0)
        return -4;

    if (set_mask(&ifr_tap, sock, local_mask) < 0)
        return -5;

    if (ioctl(sock, SIOCGIFFLAGS, &ifr_tap) < 0)
        return -6;*/

    //char buffer[1024];
    char buffer[BUFFER_LEN];

    printf("Trying to read ...\n");

    //FD_ZERO(&set); /* clear the set */
    //FD_SET(filedesc, &set); /* add our file descriptor to the set */

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 10000;

    fd_set set;
    FD_ZERO(&set);    /* clear the set */
    FD_SET(fd, &set); /* add our file descriptor to the set */

    for (int i = 0; i < 10; i++)
    {
        memset(buffer, 0, BUFFER_LEN);

        printf("\n");
        printf("Selecting...\n");

        // select() and pselect() allow a program to monitor multiple file
        // descriptors, waiting until one or more of the file descriptors become
        // "ready" for some class of I/O operation (e.g., input possible).
        int rv = select(fd + 1, &set, NULL, NULL, &timeout);
        printf("rv: %d\n", rv);
        //printf("ERRNO: (%d) %s\n", errno, strerror(errno));

        if (rv == -1)
        {
            // an error accured
            perror("select\n");
            printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        }
        else if (rv == 0)
        {
            // a timeout occured
            printf("timeout\n");
            printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        }
        else
        {

            printf("Something was read!\n");

            int read_result = read(fd, buffer, BUFFER_LEN);
            if (read_result != 0)
            {
                printf("ERRNO: (%d) %s\n", errno, strerror(errno));
            }
            else
            {
                printf("Something was read!\n");
            }

            //printf("Read: %s\n", buffer);
            print_hex_memory(buffer, BUFFER_LEN);

            struct eth_hdr *ethHeader = (struct eth_hdr *)buffer;

            // 6 byte destination MAC
            printf("Destination MAC: ");
            print_hex_memory(ethHeader->dmac, 6);

            // 6 byte source MAC:
            printf("Source MAC:      ");
            print_hex_memory(ethHeader->smac, 6);

            // 2 byte ethernet frame type
            // 1544 = 0x0806 = ARP
            if (ethHeader->ethertype == ETHERTYPE_ARP_ENDIANNESS)
            {
                printf("Ethertype: %d ARP\n", ethHeader->ethertype);

                struct arp_hdr
                {
                    uint16_t hwtype;
                    uint16_t protype;
                    unsigned char hwsize;
                    unsigned char prosize;
                    uint16_t opcode;
                    unsigned char data[];
                } __attribute__((packed));

                // payload is ARP
                struct arp_hdr *arpHeader = (struct arp_hdr *)ethHeader->payload;

                // https://de.wikipedia.org/wiki/Address_Resolution_Protocol

                // https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml
                // 256 - HW_EXP2
                printf("ARP hardware address type: %d \n", arpHeader->hwtype);
                printf("ARP protocol address type: %d ", arpHeader->protype);
                if (arpHeader->protype == ETHERTYPE_IP_ENDIANNESS)
                {
                    printf("ipv4");
                }
                else
                {
                    printf("unknown");
                }
                printf("\n");
                printf("ARP hardware address size: %d \n", arpHeader->hwsize);
                printf("ARP protocol address size: %d \n", arpHeader->prosize);
                printf("ARP opcode: %d \n", arpHeader->opcode);

                unsigned char *tempPtr = arpHeader->data;

                printf("Source MAC: ");
                print_hex_memory(tempPtr, 6);
                tempPtr += 6;

                printf("Source IP: ");
                print_hex_memory(tempPtr, 4);
                tempPtr += 4;

                printf("Dest MAC: ");
                print_hex_memory(tempPtr, 6);
                tempPtr += 6;

                printf("Dest IP: ");
                print_hex_memory(tempPtr, 4);
            }
            //else if (ethHeader->ethertype == ARP_802DOT2_FRAME_TYPE)
            //{
            //    printf("Ethertype: %d 802.2\n", ethHeader->ethertype);
            //}
            else if (ethHeader->ethertype == ETHERTYPE_IP_ENDIANNESS)
            {
                printf("Ethertype: %d IPv4\n", ethHeader->ethertype);
            }
            else
            {
                printf("UNKNOWN Ethertype: %d ???\n", ethHeader->ethertype);
            }
        }

        printf("Selecting done.\n");

        //sleep(3);
    }

    /*
    for (int i = 0; i < 10; i++)
    {
        memset(buffer, 0, BUFFER_LEN);

        int read_result = read(fd, buffer, BUFFER_LEN);
        if (read_result != 0)
        {
            printf("ERRNO: (%d) %s\n", errno, strerror(errno));
        }
        else
        {
            printf("Something was read!\n");
        }

        sleep(1);
    }
    printf("Reading done.\n");
     */

    //sleep(5);

cleanup:
    printf("Closeing device ...\n");
    close(fd);
    fd = 0;
    printf("Closeing device done.\n");

    return fd;
}

int main(int argc, char **argv)
{
    printf("You have to run this app with administrator rights (sudo)!\n");
    printf("You have to run this app with administrator rights (sudo)!\n");
    printf("You have to run this app with administrator rights (sudo)!\n");

    device_ptr = calloc(16, 1);
    strncpy(device_ptr, "tap0", strlen("tap0"));

    if (tun_alloc(device_ptr) != 0)
    {
        printf("There was an error allocating the tun/tap device!\n");
    }

    free(device_ptr);
    device_ptr = 0;

    return 0;
}