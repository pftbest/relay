#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "relay.h"

static void print_usage()
{
    puts("usage: relay [-c] [-s] [-d tun_iface] [-k key] [-p port] [-h host]");
}

int main(int argc, char *argv[])
{
    struct relay_config config;
    config.is_server = 0;
    config.key = "relay";
    config.tun_device = "tun0";
    config.host_name = "127.0.0.1";
    config.port = 8000;

    for (;;) {
        int ch = getopt(argc, argv, "csd:k:p:h:");
        if (ch < 0) {
            break;
        }
        switch (ch) {
        case 'c':
            config.is_server = 0;
            break;
        case 's':
            config.is_server = 1;
            break;
        case 'd':
            config.tun_device = optarg;
            break;
        case 'k':
            config.key = optarg;
            break;
        case 'p':
            config.port = atoi(optarg);
            break;
        case 'h':
            config.host_name = optarg;
            break;
        default:
            print_usage();
            return EXIT_FAILURE;
        }
    }

    if (config.port <= 0 || config.port >= 65536) {
        puts("error: port out of range");
        print_usage();
        return EXIT_FAILURE;
    }

    if (optind != argc) {
        puts("error: invalid argument");
        print_usage();
        return EXIT_FAILURE;
    }

    return relay_start(&config);
}
