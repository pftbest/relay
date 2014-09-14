#include <time.h>
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/select.h>
#include "client.h"

static const int MD5_KEY_SIZE = 16;
static const int DES_KEY_SIZE = 64;
static const int DES_BLOCK_SIZE = 8;
static const int MAX_PACKET_SIZE = 4096;
static const int LOGIN_TIMEOUT = 3;
static const int RECEIVE_TIMEOUT = 5;
static const int SELECT_TIMEOUT = 60;

static int wait_read(int fd, int sec)
{
    struct timeval tv;
    tv.tv_sec = sec;
    tv.tv_usec = 0;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    return select(fd + 1, &rfds, NULL, NULL, &tv);
}

static int send_data(int clientfd, uint8_t *buffer, int size)
{
    int sent = 0;
    while (sent < size) {
        int n = write(clientfd, buffer + sent, size - sent);
        if (n < 0) {
            perror("write failed");
            break;
        }
        if (n == 0) {
            break;
        }
        sent += n;
    }
    return sent;
}

static int recv_data(int clientfd, uint8_t *buffer, int size)
{
    int count = 0;
    while (count < size) {
        int n = wait_read(clientfd, RECEIVE_TIMEOUT);
        if (n < 0) {
            perror("select failed");
            break;
        } else if (n == 0) {
            puts("error: receive timeout");
            break;
        }
        n = read(clientfd, buffer + count, size - count);
        if (n < 0) {
            perror("read failed");
            break;
        }
        if (n == 0) {
            break;
        }
        count += n;
    }
    return count;
}

static void byte2bit(const uint8_t *bytes, char *bits, int bit_count)
{
    for (int i = 0; i < bit_count; i++) {
        bits[i] = (bytes[i / 8] >> (i % 8)) & 1;
    }
}

static void bit2byte(const char *bits, uint8_t *bytes, int bit_count)
{
    memset(bytes, 0, (bit_count + 7) / 8);
    for (int i = 0; i < bit_count; i++) {
        bytes[i / 8] |= ((bits[i] & 1) << (i % 8));
    }
}

static int encrypt_buffer(uint8_t *buffer, int data_size, int max_size, const char des_key[DES_KEY_SIZE])
{
    setkey(des_key);
    char block[DES_KEY_SIZE];
    for (int i = 0; i < data_size / DES_BLOCK_SIZE; i++) {
        byte2bit(buffer + (i * DES_BLOCK_SIZE), block, DES_KEY_SIZE);
        encrypt(block, 0);
        bit2byte(block, buffer + (i * DES_BLOCK_SIZE), DES_KEY_SIZE);
    }

    int left = data_size % DES_BLOCK_SIZE;
    if (data_size - left + DES_BLOCK_SIZE > max_size) {
        return data_size - left;
    }

    for (int i = left; i < DES_BLOCK_SIZE; i++) {
        buffer[data_size - left + i] = 8 - left;
    }
    byte2bit(buffer + (data_size - left), block, DES_KEY_SIZE);
    encrypt(block, 0);
    bit2byte(block, buffer + (data_size - left), DES_KEY_SIZE);
    return data_size - left + DES_BLOCK_SIZE;
}

static int decrypt_buffer(uint8_t *buffer, int size, const char des_key[DES_KEY_SIZE])
{
    if (size % DES_BLOCK_SIZE != 0) {
        return -1;
    }

    char block[DES_KEY_SIZE];
    for (int i = 0; i < size / DES_BLOCK_SIZE; i++) {
        byte2bit(buffer + (i * DES_BLOCK_SIZE), block, DES_KEY_SIZE);
        encrypt(block, 1);
        bit2byte(block, buffer + (i * DES_BLOCK_SIZE), DES_KEY_SIZE);
    }

    int trim = buffer[size - 1];
    if (trim >= 1 && trim <= DES_BLOCK_SIZE) {
        return size - trim;
    }
    return size;
}

static int recv_packet(int tunfd, int clientfd, const char des_key[DES_KEY_SIZE])
{
    uint8_t header[DES_BLOCK_SIZE];
    int n = read(clientfd, &header, DES_BLOCK_SIZE);
    if (n < 0) {
        perror("read failed");
        return -1;
    }
    if (n != DES_BLOCK_SIZE) {
        return -1;
    }

    n = decrypt_buffer(header, n, des_key);
    if (n != sizeof(uint32_t)) {
        puts("error: decryption failed");
        return -1;
    }

    uint32_t size = 0;
    memcpy(&size, header, sizeof(uint32_t));
    size = ntohl(size);
    if (size > MAX_PACKET_SIZE) {
        puts("error: invalid packet size");
        return -1;
    }

    uint8_t data[MAX_PACKET_SIZE];
    n = recv_data(clientfd, data, size);
    if (n != size) {
        puts("error: packet receive failed");
        return -1;
    }

    size = decrypt_buffer(data, size, des_key);
    if (size <= 0) {
        puts("error: decryption failed");
        return -1;
    }

    n = write(tunfd, data, size);
    if (n != size) {
        puts("error: tun write failed");
        return -1;
    }

    return n;
}

static int send_packet(int tunfd, int clientfd, const char des_key[DES_KEY_SIZE])
{
    uint8_t packet[MAX_PACKET_SIZE + DES_BLOCK_SIZE];
    uint8_t *data = packet + DES_BLOCK_SIZE;
    int n = read(tunfd, data, MAX_PACKET_SIZE);
    if (n < 0) {
        perror("read failed");
        return -1;
    }
    if (n == 0) {
        return 0;
    }

    int size = encrypt_buffer(data, n, MAX_PACKET_SIZE, des_key);
    if (size <= n) {
        puts("error: encryption failed");
        return -1;
    }

    uint32_t header = htonl(size);
    memcpy(packet, &header, sizeof(uint32_t));
    n = encrypt_buffer(packet, sizeof(uint32_t), DES_BLOCK_SIZE, des_key);
    if (n != DES_BLOCK_SIZE) {
        puts("error: encryption failed");
        return -1;
    }

    size += DES_BLOCK_SIZE;
    n = send_data(clientfd, packet, size);
    if (n != size) {
        puts("error: packet send failed");
        return -1;
    }
    return n;
}

static int login(int clientfd, const char *key, char des_key[DES_KEY_SIZE])
{
    uint8_t rnd1[MD5_KEY_SIZE];
    for (int i = 0; i < MD5_KEY_SIZE; i++) {
        rnd1[i] = rand() ^ clientfd;
    }

    int n = write(clientfd, rnd1, MD5_KEY_SIZE);
    if (n != MD5_KEY_SIZE) {
        perror("login: write failed");
        return -1;
    }

    n = wait_read(clientfd, LOGIN_TIMEOUT);
    if (n < 0) {
        perror("login: select failed");
        return -1;
    } else if (n == 0) {
        puts("error: login: connection timeout 1");
        return -1;
    }

    uint8_t rnd2[MD5_KEY_SIZE];
    n = read(clientfd, rnd2, MD5_KEY_SIZE);
    if (n < 0) {
        perror("login: read failed");
        return -1;
    }
    if (n != MD5_KEY_SIZE) {
        puts("error: login: not enough data");
        return -1;
    }

    const char *md5 = crypt(key, "$1$2$");
    int md5_offset = strlen(md5) - MD5_KEY_SIZE;
    if (md5_offset < 0) {
        puts("error: login: md5 hash is too short");
        return -1;
    }

    int sum = 0;
    for (int i = 0; i < DES_KEY_SIZE; i++) {
        if ((i + 1) % 8 == 0) {
            des_key[i] = sum ^ 1;
            sum = 0;
            continue;
        }
        const int fract = DES_KEY_SIZE / MD5_KEY_SIZE;
        int val = rnd1[i / fract] ^ rnd2[i / fract] ^ md5[i / fract + md5_offset];
        des_key[i] = (val >> (i % fract)) & 1;
        sum ^= des_key[i];
    }

    n = encrypt_buffer(rnd2, MD5_KEY_SIZE, MD5_KEY_SIZE, des_key);
    if (n != MD5_KEY_SIZE) {
        puts("error: login: encryption failed");
        return -1;
    }

    n = send_data(clientfd, rnd2, MD5_KEY_SIZE);
    if (n != MD5_KEY_SIZE) {
        return -1;
    }

    n = wait_read(clientfd, LOGIN_TIMEOUT);
    if (n < 0) {
        perror("login: select failed");
        return -1;
    } else if (n == 0) {
        puts("error: login: connection timeout 2");
        return -1;
    }

    n = read(clientfd, rnd2, MD5_KEY_SIZE);
    if (n < 0) {
        perror("login: read failed");
        return -1;
    }
    if (n != MD5_KEY_SIZE) {
        puts("error: login: not enough data");
        return -1;
    }

    n = decrypt_buffer(rnd2, MD5_KEY_SIZE, des_key);
    if (n < 0) {
        puts("error: login: decryption failed");
        return -1;
    }

    n = memcmp(rnd1, rnd2, MD5_KEY_SIZE);
    if (n != 0) {
        puts("error: login: keys do not match");
        return -1;
    }
    return 1;
}

static void set_timeouts(int socketfd)
{
    struct timeval tv;
    tv.tv_sec = RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
    }
    tv.tv_sec = RECEIVE_TIMEOUT;
    tv.tv_usec = 0;
    if (setsockopt(socketfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt failed");
    }
}

void client_start(int clientfd, int tunfd, const char *key)
{
    set_timeouts(clientfd);

    char des_key[DES_KEY_SIZE];
    if (login(clientfd, key, des_key) < 0) {
        return;
    }

    puts("login successful");
    for (;;) {
        struct timeval tv;
        tv.tv_sec = SELECT_TIMEOUT;
        tv.tv_usec = 0;
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tunfd, &rfds);
        FD_SET(clientfd, &rfds);
        int maxfd = tunfd > clientfd ? tunfd : clientfd;
        int n = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (n < 0) {
            perror("select failed");
            break;
        }
        if (n == 0) {
            puts("select: timeout");
            break;
        }
        if (FD_ISSET(clientfd, &rfds)) {
            n = recv_packet(tunfd, clientfd, des_key);
            if (n <= 0) {
                break;
            }
        }
        if (FD_ISSET(tunfd, &rfds)) {
            n = send_packet(tunfd, clientfd, des_key);
            if (n <= 0) {
                break;
            }
        }
    }
}
