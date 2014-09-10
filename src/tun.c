#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <memory.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include "util.h"

int tun_alloc(char *dev)
{
    assert(dev != NULL);

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        perror("failed to open tun device");
        return fd;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (*dev) {
        strncpy_s(ifr.ifr_name, dev, IFNAMSIZ);
    }

    int err = ioctl(fd, TUNSETIFF, &ifr);
    if (err < 0) {
        perror("failed to set interface");
        close(fd);
        return err;
    }

    strncpy_s(dev, ifr.ifr_name, IFNAMSIZ);
    return fd;
}
