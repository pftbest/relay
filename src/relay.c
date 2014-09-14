#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tun.h"
#include "util.h"
#include "relay.h"
#include "client.h"

int tunfd = 0;
int serverfd = 0;

static void close_connection(int *socketfd)
{
    if (*socketfd > 0) {
        printf("connection closed: [%d]\n", *socketfd);
        shutdown(*socketfd, SHUT_RDWR);
        close(*socketfd);
    }
    *socketfd = 0;
}

static void relay_signal_handler(int signal)
{
    close_connection(&serverfd);
    close(tunfd);
    exit(signal);
}

static void delay()
{
    usleep(1000000);
}

int relay_start(const struct relay_config *config)
{
    signal(SIGCHLD, SIG_IGN);
    signal(SIGINT, relay_signal_handler);
    signal(SIGTERM, relay_signal_handler);

    char devname[IFNAMSIZ];
    strncpy_s(devname, config->tun_device, IFNAMSIZ);
    tunfd = tun_alloc(devname);
    if (tunfd < 0) {
        return EXIT_FAILURE;
    }
    printf("opened tun device: %s\n", devname);

    struct hostent *host = gethostbyname2(config->host_name, AF_INET);
    if (host == NULL) {
        puts("error: host name not found");
        close(tunfd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config->port);
    memcpy(&(addr.sin_addr), host->h_addr_list[0], sizeof(addr.sin_addr));

    if (config->is_server) {
        serverfd = socket(AF_INET, SOCK_STREAM, 0);
        if (serverfd < 0) {
            perror("failed to open socket");
            close(tunfd);
            return EXIT_FAILURE;
        }
        if (bind(serverfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("bind failed");
            close_connection(&serverfd);
            close(tunfd);
            return EXIT_FAILURE;
        }
        if (listen(serverfd, 3) < 0) {
            perror("listen failed");
            close_connection(&serverfd);
            close(tunfd);
            return EXIT_FAILURE;
        }
        printf("started server on port: %d [%d]\n", config->port, serverfd);
    }

    for (;;) {
        int clientfd = 0;
        if (config->is_server) {
            struct sockaddr_in clientaddr;
            socklen_t clientaddr_size = sizeof(clientaddr);
            clientfd = accept(serverfd, (struct sockaddr *)&clientaddr, &clientaddr_size);
            if (clientfd < 0) {
                perror("failed to accept client");
                delay();
                continue;
            }
            printf("accepted client: %s [%d]\n", inet_ntoa(clientaddr.sin_addr), clientfd);
        } else {
            clientfd = socket(AF_INET, SOCK_STREAM, 0);
            if (clientfd < 0) {
                perror("failed to open socket");
                delay();
                continue;
            }
            if (connect(clientfd, (const struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("connection failed");
                close(clientfd);
                delay();
                continue;
            }
            printf("connected to host: %s [%d]\n", inet_ntoa(addr.sin_addr), clientfd);
        }
        if (config->is_server) {
            int pid = fork();
            if (pid != 0) {
                continue;
            }
            signal(SIGINT, SIG_DFL);
            signal(SIGTERM, SIG_DFL);
        }
        client_start(clientfd, tunfd, config->key);
        close_connection(&clientfd);
        if (config->is_server) {
            return EXIT_SUCCESS;
        }
    }

    close_connection(&serverfd);
    close(tunfd);
    return EXIT_SUCCESS;
}
