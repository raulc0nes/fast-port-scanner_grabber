#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <errno.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/time.h>
#include <signal.h>
#include <time.h>

#define MAX_THREADS 20
#define DEFAULT_PORTS 104
#define TIMEOUT_FACTOR 2
#define SYN_SCAN_TIMEOUT 2
#define LOG_FILE "scan_results.log"

int ports[] = {
    20, 21, 22, 23, 25, 26, 37, 43, 53, 67, 68, 69, 80, 88, 110, 113, 119, 123, 135, 137,
    138, 139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 500, 514, 515, 520, 523, 546, 547,
    554, 587, 631, 636, 873, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1812, 1813, 1863,
    2049, 2082, 2083, 2100, 2222, 2375, 2376, 2483, 2484, 3128, 3268, 3306, 3389, 3690, 4000,
    4031, 4190, 4444, 4567, 4672, 4899, 5000, 5060, 5061, 5432, 5631, 5900, 5938, 6000, 6379,
    6646, 6665, 6666, 6667, 6668, 6669, 6881, 6969, 7000, 7070, 8000, 8080, 8081, 8443, 8888,
    9418, 9999, 10000, 11371, 13720, 13721, 19283, 25565, 27017, 27374, 31337
};

typedef struct {
    const char *ip;
    int port;
    int timeout;
    int total_ports;
    int *progress;
    FILE *log_file;
} ThreadArgs;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t stop = 0;

void handle_sigint(int sig) {
    stop = 1;
}

void update_progress(int current, int total) {
    int percent = (current * 100) / total;
    printf("\rProgreso: [%d/%d] (%d%%)", current, total, percent);
    fflush(stdout);
}

int tcp_connect_scan(const char *ip, int port, int timeout, FILE *log_file) {
    int sockfd;
    struct sockaddr_in dest;
    struct timeval tv;
    char banner[1024] = {0};

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return 0;
    }

    tv.tv_sec = timeout;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv));

    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = inet_addr(ip);

    int result = connect(sockfd, (struct sockaddr *)&dest, sizeof(dest));
    if (result == 0) {
        // Intentar leer el banner si está disponible
        int bytes_received = recv(sockfd, banner, sizeof(banner) - 1, 0);
        if (bytes_received > 0) {
            banner[bytes_received] = '\0';
        } else {
            snprintf(banner, sizeof(banner), "No banner");
        }
        pthread_mutex_lock(&mutex);
        fprintf(log_file, "Puerto %d abierto. Banner: %s\n", port, banner);
        printf("\nPuerto %d abierto. Banner: %s", port, banner);
        pthread_mutex_unlock(&mutex);
    }

    close(sockfd);
    return (result == 0);
}

char *get_local_ip() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    static char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("Error al obtener la IP local");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            if (strcmp(ifa->ifa_name, "lo") != 0) {  // Evita la dirección de loopback
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return host;
}

void *scan_thread(void *args) {
    ThreadArgs *threadArgs = (ThreadArgs *)args;
    int port = threadArgs->port;

    tcp_connect_scan(threadArgs->ip, port, threadArgs->timeout, threadArgs->log_file);

    pthread_mutex_lock(&mutex);
    (*threadArgs->progress)++;
    update_progress(*threadArgs->progress, threadArgs->total_ports);
    pthread_mutex_unlock(&mutex);

    free(threadArgs);
    pthread_exit(NULL);
}

int calculate_timeout(const char *ip) {
    struct timeval start, end;
    int sock;
    struct sockaddr_in server;
    int ping_count = 4;
    double total_time = 0;
    double total_rtt = 0;
    double rtt_variance = 0;

    for (int i = 0; i < ping_count; i++) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            return TIMEOUT_FACTOR;
        }

        server.sin_addr.s_addr = inet_addr(ip);
        server.sin_family = AF_INET;
        server.sin_port = htons(80);

        gettimeofday(&start, NULL);
        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
            close(sock);
            return TIMEOUT_FACTOR;
        }
        gettimeofday(&end, NULL);

        double elapsed_time = (end.tv_sec - start.tv_sec) * 1000.0;
        elapsed_time += (end.tv_usec - start.tv_usec) / 1000.0;
        total_time += elapsed_time;
        total_rtt += elapsed_time;

        if (i > 0) {
            double previous_avg = total_rtt / i;
            rtt_variance += (elapsed_time - previous_avg) * (elapsed_time - previous_avg);
        }

        close(sock);
    }

    double avg_time = total_time / ping_count;
    double variance = rtt_variance / ping_count;
    double adjusted_timeout = avg_time + 2 * variance;

    printf("Tiempo medio de respuesta: %.2f ms (ajustado a %.2f ms)\n", avg_time, adjusted_timeout);
    return (int)(adjusted_timeout / 1000.0) * TIMEOUT_FACTOR;
}

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_sigint);

    if (argc < 2) {
        fprintf(stderr, "Uso: %s <IP objetivo> [comunes/todos]\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int use_all_ports = (argc == 3 && strcmp(argv[2], "todos") == 0);
    int port_count = use_all_ports ? 65535 : DEFAULT_PORTS;

    struct hostent *he;
    struct in_addr **addr_list;
    if ((he = gethostbyname(target_ip)) == NULL) {
        herror("Error al resolver el dominio");
        return 1;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    if (addr_list[0] != NULL) {
        target_ip = inet_ntoa(*addr_list[0]);
        printf("IP resuelta: %s\n", target_ip);
    } else {
        fprintf(stderr, "No se pudo resolver la IP\n");
        return 1;
    }

    int timeout = calculate_timeout(target_ip);

    pthread_t threads[MAX_THREADS];
    int thread_index = 0;
    int progress = 0;

    FILE *log_file = fopen(LOG_FILE, "w");
    if (log_file == NULL) {
        perror("Error al abrir el archivo de log");
        return 1;
    }

    for (int i = 0; i < port_count; i++) {
        if (stop) {
            printf("\nEscaneo interrumpido.\n");
            break;
        }

        int port = use_all_ports ? i + 1 : ports[i];

        if (thread_index >= MAX_THREADS) {
            for (int j = 0; j < thread_index; j++) {
                pthread_join(threads[j], NULL);
            }
            thread_index = 0;
        }

        ThreadArgs *args = (ThreadArgs *)malloc(sizeof(ThreadArgs));
        args->ip = target_ip;
        args->port = port;
        args->timeout = timeout;
        args->total_ports = port_count;
        args->progress = &progress;
        args->log_file = log_file;

        pthread_create(&threads[thread_index], NULL, scan_thread, (void *)args);
        thread_index++;
    }

    for (int i = 0; i < thread_index; i++) {
        pthread_join(threads[i], NULL);
    }

    fclose(log_file);

    printf("\nEscaneo completado. Resultados guardados en %s\n", LOG_FILE);

    return 0;
}

