#ifndef MQVPN_VPN_CLIENT_H
#define MQVPN_VPN_CLIENT_H

#include <stdint.h>

#define MQVPN_MAX_PATH_IFACES 4

typedef struct mqvpn_client_cfg_s {
    const char *server_addr;                        /* server address (e.g. "1.2.3.4") */
    int server_port;                                /* server port (e.g. 443) */
    const char *tun_name;                           /* TUN device name */
    int insecure;                                   /* skip TLS cert verification */
    int log_level;                                  /* mqvpn_log_level_t */
    const char *path_ifaces[MQVPN_MAX_PATH_IFACES]; /* network interfaces for multipath */
    int n_paths;                /* number of path interfaces (0 = single-path) */
    int scheduler;              /* 0=minrtt, 1=wlb (default) */
    int cc;                     /* mqvpn_cc_t */
    int mtu;                    /* 0=auto; otherwise pinned TUN MTU */
    int outer_packet_size;      /* QUIC packet size, 0/default=1400 */
    int pmtud_enable;           /* 1=enable negotiated xquic PMTUD */
    int pmtud_probe_size;       /* PMTUD probe cap, 0/default=1420 */
    const char *auth_key;       /* PSK for server authentication (NULL = no auth) */
    const char *dns_servers[4]; /* DNS servers to configure (NULL = no DNS override) */
    int n_dns;                  /* number of DNS servers */
    const char *client_routes[16]; /* IPv4 prefixes allowed as local TUN sources */
    int n_client_routes;
    int reconnect;              /* 1=auto-reconnect on disconnect (default 1) */
    int reconnect_interval;     /* base reconnect interval in seconds (default 5) */
    int kill_switch;            /* 1=block traffic outside tunnel (default 0) */
    int manage_routes;          /* 1=install split default routes (default), 0=caller managed */
} mqvpn_client_cfg_t;

#endif /* MQVPN_VPN_CLIENT_H */
