#ifndef RELAY_H
#define RELAY_H

struct relay_config {
    int is_server;
    const char *key;
    const char *tun_device;
    const char *host_name;
    int port;
};

int relay_start(const struct relay_config *config);

#endif /* RELAY_H */
