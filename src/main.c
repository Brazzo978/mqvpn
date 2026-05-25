#include "libmqvpn.h"
#include "log.h"
#include "config.h"
#include "json_mini.h"
#include "auth.h"
#include "vpn_client.h"
#include "vpn_server.h"
#include "flow_sched.h"

#include <xquic/xquic.h> /* for XQC_ENABLE_* compile-time defines */

#ifdef _WIN32
#  include "platform_windows.h"
#  include <winsock2.h>
#else
#  include "platform_linux.h"
#  include "status.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

static void
usage(const char *prog)
{
    fprintf(
        stderr,
        "Usage:\n"
        "  sudo %s --config <path>                  (mode from config)\n"
        "  sudo %s --mode client --server <host:port> [options]\n"
        "  sudo %s --mode server --listen <bind:port> [options]\n"
        "\n"
        "Options:\n"
        "  --config PATH             Configuration file (INI or JSON format)\n"
        "  --mode client|server      Operating mode (required if no config)\n"
        "  --server HOST:PORT        Server address (client mode, [IPv6]:PORT for IPv6)\n"
        "  --listen BIND:PORT        Listen address (server mode, default 0.0.0.0:443)\n"
        "  --subnet CIDR             Client IP pool (server mode, default 10.0.0.0/24)\n"
        "  --subnet6 CIDR            IPv6 client IP pool (server mode, e.g. "
        "2001:db8:1::/112)\n"
        "  --tun-name NAME           TUN device name (default mqvpn0)\n"
        "  --cert PATH               TLS certificate (server mode)\n"
        "  --key PATH                TLS private key (server mode)\n"
        "  --insecure                Accept untrusted certs (client mode, testing only)\n"
        "  --auth-key KEY            PSK for authentication\n"
        "  --user NAME:KEY           Add a server user credential (repeatable)\n"
        "  --genkey                  Generate a random PSK and exit\n"
        "  --path IFACE              Network interface for multipath (repeatable, client "
        "mode)\n"
        "  --dns ADDR                DNS server to use (repeatable, client mode, max 4)\n"
        "  --no-reconnect            Disable automatic reconnection (client mode)\n"
        "  --kill-switch             Block traffic outside the VPN tunnel (client mode)\n"
        "  --no-routes               Do not install split-default routes (client mode)\n"
        "  --control-port PORT       TCP port for JSON control API (server mode)\n"
        "  --control-addr ADDR       Bind address for control API (default 127.0.0.1)\n"
        "                            (also configurable via [Control] Listen in INI / "
        "control_listen in JSON)\n"
        "  --status                  Query server status via control API and exit\n"
        "                            (uses --control-port, or [Control] Listen from "
        "--config)\n"
        "  --scheduler minrtt|wlb|backup|backup_fec|rap\n"
        "                            Multipath scheduler (default wlb)\n"
        "  --cc bbr2|bbr|cubic|new_reno|copa|unlimited\n"
        "                            Congestion control (default bbr2)\n"
        "  --mtu N                   TUN MTU override, 0=auto (default 0)\n"
        "  --outer-packet-size N     QUIC/UDP payload size 1298-1472 (default 1400)\n"
        "  --pmtud                   Enable negotiated xquic PMTUD (off by default)\n"
        "  --pmtud-probe-size N      PMTUD probe cap 1298-1472 (default 1420)\n"
        "  --max-clients N           Max concurrent clients (server mode, default 64)\n"
        "  --log-level debug|info|warn|error  (default info)\n"
        "  --version                 Show version and exit\n"
        "  --help                    Show this help\n"
        "\n"
        "CLI options override config file values.\n",
        prog, prog, prog);
}

static int
parse_host_port(const char *str, char *host, size_t host_len, int *port)
{
    if (str[0] == '[') {
        /* Bracket notation for IPv6: [host]:port */
        const char *close = strchr(str, ']');
        if (!close || close[1] != ':') {
            fprintf(stderr, "error: expected [HOST]:PORT, got '%s'\n", str);
            return -1;
        }
        size_t hlen = (size_t)(close - str - 1);
        if (hlen >= host_len) hlen = host_len - 1;
        memcpy(host, str + 1, hlen);
        host[hlen] = '\0';
        *port = atoi(close + 2);
    } else {
        /* Legacy: host:port (last colon) */
        const char *colon = strrchr(str, ':');
        if (!colon) {
            fprintf(stderr, "error: expected HOST:PORT, got '%s'\n", str);
            return -1;
        }
        size_t hlen = (size_t)(colon - str);
        if (hlen >= host_len) hlen = host_len - 1;
        memcpy(host, str, hlen);
        host[hlen] = '\0';
        *port = atoi(colon + 1);
    }
    if (*port <= 0 || *port > 65535) {
        fprintf(stderr, "error: invalid port in '%s'\n", str);
        return -1;
    }
    return 0;
}

static int
parse_range_int(const char *str, int min, int max, const char *name, int allow_zero,
                int *out)
{
    if (!str || *str == '\0') {
        fprintf(stderr, "error: %s must be %s%d and %d\n", name,
                allow_zero ? "0 or between " : "between ", min, max);
        return -1;
    }
    char *end = NULL;
    long v = strtol(str, &end, 10);
    if (!end || *end != '\0' ||
        ((!allow_zero || v != 0) && (v < min || v > max))) {
        fprintf(stderr, "error: %s must be %s%d and %d\n", name,
                allow_zero ? "0 or between " : "between ", min, max);
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int
parse_scheduler_name(const char *name, mqvpn_scheduler_t *out)
{
    if (strcmp(name, "wlb") == 0) {
        *out = MQVPN_SCHED_WLB;
    } else if (strcmp(name, "backup") == 0) {
        *out = MQVPN_SCHED_BACKUP;
    } else if (strcmp(name, "backup_fec") == 0) {
#if defined(XQC_ENABLE_FEC) && defined(XQC_ENABLE_XOR)
        *out = MQVPN_SCHED_BACKUP_FEC;
#else
        fprintf(stderr, "error: --scheduler 'backup_fec' requires rebuild with "
                        "-DXQC_ENABLE_FEC=ON -DXQC_ENABLE_XOR=ON in xquic\n");
        return -1;
#endif
    } else if (strcmp(name, "rap") == 0) {
        *out = MQVPN_SCHED_RAP;
    } else if (strcmp(name, "minrtt") == 0) {
        *out = MQVPN_SCHED_MINRTT;
    } else {
        fprintf(stderr,
                "error: --scheduler must be 'minrtt', 'wlb', 'backup', "
                "'backup_fec', or 'rap'\n");
        return -1;
    }
    return 0;
}

static int
parse_cc_name(const char *name, mqvpn_cc_t *out)
{
    if (strcmp(name, "bbr2") == 0) {
        *out = MQVPN_CC_BBR2;
    } else if (strcmp(name, "bbr") == 0) {
        *out = MQVPN_CC_BBR;
    } else if (strcmp(name, "cubic") == 0) {
        *out = MQVPN_CC_CUBIC;
    } else if (strcmp(name, "new_reno") == 0 || strcmp(name, "reno") == 0) {
        *out = MQVPN_CC_NEW_RENO;
    } else if (strcmp(name, "copa") == 0) {
        *out = MQVPN_CC_COPA;
    } else if (strcmp(name, "unlimited") == 0) {
        *out = MQVPN_CC_UNLIMITED;
    } else {
        fprintf(stderr,
                "error: --cc must be 'bbr2', 'bbr', 'cubic', 'new_reno', "
                "'copa', or 'unlimited'\n");
        return -1;
    }
    return 0;
}

/* mqvpn_copy_str is provided by json_mini.h as mqvpn_copy_str */

int
main(int argc, char *argv[])
{
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "error: WSAStartup failed\n");
        return 1;
    }
#endif

    static struct option long_opts[] = {
        {"config", required_argument, NULL, 'C'},
        {"mode", required_argument, NULL, 'm'},
        {"server", required_argument, NULL, 's'},
        {"listen", required_argument, NULL, 'l'},
        {"subnet", required_argument, NULL, 'n'},
        {"subnet6", required_argument, NULL, '6'},
        {"tun-name", required_argument, NULL, 't'},
        {"cert", required_argument, NULL, 'c'},
        {"key", required_argument, NULL, 'k'},
        {"insecure", no_argument, NULL, 'i'},
        {"auth-key", required_argument, NULL, 'a'},
        {"user", required_argument, NULL, 'u'},
        {"genkey", no_argument, NULL, 'G'},
        {"path", required_argument, NULL, 'p'},
        {"dns", required_argument, NULL, 'd'},
        {"scheduler", required_argument, NULL, 'S'},
        {"cc", required_argument, NULL, 'Q'},
        {"mtu", required_argument, NULL, 0x100},
        {"outer-packet-size", required_argument, NULL, 0x101},
        {"pmtud", no_argument, NULL, 0x102},
        {"pmtud-probe-size", required_argument, NULL, 0x103},
        {"max-clients", required_argument, NULL, 'M'},
        {"log-level", required_argument, NULL, 'L'},
        {"no-reconnect", no_argument, NULL, 'R'},
        {"kill-switch", no_argument, NULL, 'K'},
        {"no-routes", no_argument, NULL, 'N'},
        {"control-port", required_argument, NULL, 'X'},
        {"control-addr", required_argument, NULL, 'x'},
        {"status", no_argument, NULL, 'T'},
        {"version", no_argument, NULL, 'V'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    const char *config_path = NULL;
    const char *mode = NULL;
    const char *server_str = NULL;
    const char *listen_str = NULL; /* NULL means "not set by CLI" */
    const char *subnet = NULL;
    const char *subnet6 = NULL;
    const char *tun_name = NULL;
    const char *cert_file = NULL;
    const char *key_file = NULL;
    int insecure = -1; /* -1 means "not set by CLI" */
    const char *auth_key = NULL;
    char cli_user_names[MQVPN_CONFIG_MAX_USERS][64];
    char cli_user_keys[MQVPN_CONFIG_MAX_USERS][256];
    int n_cli_users = 0;
    int genkey = 0;
    const char *log_level_str = NULL;
    const char *scheduler_str = NULL;
    const char *cc_str = NULL;
    int mtu = -1;
    int outer_packet_size = -1;
    int pmtud_enable = -1;
    int pmtud_probe_size = -1;
    int max_clients = -1; /* -1 means "not set by CLI" */
    const char *path_ifaces[MQVPN_MAX_PATH_IFACES];
    int n_paths = 0;
    const char *dns_servers[4];
    int n_dns = 0;
    int no_reconnect = 0;
    int kill_switch = -1; /* -1 = not set by CLI */
    int manage_routes = -1; /* -1 = config/default, 0 = disabled by CLI */
    int control_port = 0;
    int control_port_set = 0; /* 1 iff --control-port was passed explicitly */
    const char *control_addr = NULL;
    int status_mode = 0;

    int opt;
    while ((opt = getopt_long(argc, argv, "C:m:s:l:n:6:t:c:k:ia:u:Gp:d:S:Q:M:L:X:x:Vh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'C': config_path = optarg; break;
        case 'm': mode = optarg; break;
        case 's': server_str = optarg; break;
        case 'l': listen_str = optarg; break;
        case 'n': subnet = optarg; break;
        case '6': subnet6 = optarg; break;
        case 't': tun_name = optarg; break;
        case 'c': cert_file = optarg; break;
        case 'k': key_file = optarg; break;
        case 'i': insecure = 1; break;
        case 'a': auth_key = optarg; break;
        case 'u': {
            if (n_cli_users >= MQVPN_CONFIG_MAX_USERS) {
                fprintf(stderr, "error: max %d users supported\n",
                        MQVPN_CONFIG_MAX_USERS);
                return 1;
            }
            char pair[360];
            snprintf(pair, sizeof(pair), "%s", optarg);
            char *sep = strchr(pair, ':');
            if (!sep) {
                fprintf(stderr, "error: --user must be NAME:KEY\n");
                return 1;
            }
            *sep = '\0';
            mqvpn_copy_str(cli_user_names[n_cli_users],
                           sizeof(cli_user_names[n_cli_users]), pair);
            mqvpn_copy_str(cli_user_keys[n_cli_users], sizeof(cli_user_keys[n_cli_users]),
                           sep + 1);
            if (cli_user_names[n_cli_users][0] == '\0' ||
                cli_user_keys[n_cli_users][0] == '\0') {
                fprintf(stderr, "error: --user must be NAME:KEY\n");
                return 1;
            }
            n_cli_users++;
            break;
        }
        case 'G': genkey = 1; break;
        case 'p':
            if (n_paths < MQVPN_MAX_PATH_IFACES) {
                path_ifaces[n_paths++] = optarg;
            } else {
                fprintf(stderr, "error: max %d paths supported\n", MQVPN_MAX_PATH_IFACES);
                return 1;
            }
            break;
        case 'd':
            if (n_dns < 4) {
                dns_servers[n_dns++] = optarg;
            } else {
                fprintf(stderr, "error: max 4 DNS servers supported\n");
                return 1;
            }
            break;
        case 'S': scheduler_str = optarg; break;
        case 'Q': cc_str = optarg; break;
        case 0x100:
            if (parse_range_int(optarg, MQVPN_TUN_MTU_MIN, MQVPN_TUN_MTU_MAX,
                                "--mtu", 1, &mtu) < 0)
                return 1;
            break;
        case 0x101:
            if (parse_range_int(optarg, MQVPN_OUTER_PACKET_SIZE_MIN,
                                MQVPN_OUTER_PACKET_SIZE_MAX,
                                "--outer-packet-size", 1, &outer_packet_size) < 0)
                return 1;
            break;
        case 0x102: pmtud_enable = 1; break;
        case 0x103:
            if (parse_range_int(optarg, MQVPN_OUTER_PACKET_SIZE_MIN,
                                MQVPN_OUTER_PACKET_SIZE_MAX,
                                "--pmtud-probe-size", 1, &pmtud_probe_size) < 0)
                return 1;
            break;
        case 'M': max_clients = atoi(optarg); break;
        case 'R': no_reconnect = 1; break;
        case 'K': kill_switch = 1; break;
        case 'N': manage_routes = 0; break;
        case 'X':
            control_port = atoi(optarg);
            control_port_set = 1;
            break;
        case 'x': control_addr = optarg; break;
        case 'T': status_mode = 1; break;
        case 'L': log_level_str = optarg; break;
        case 'V': printf("mqvpn %s\n", mqvpn_version_string()); return 0;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    /* --genkey: generate PSK and exit */
    if (genkey) {
        return mqvpn_auth_genkey() < 0 ? 1 : 0;
    }

    /* Load config file (if given), then apply CLI overrides.
     * Hoisted above --status so [Control] Listen in the INI/JSON config
     * can satisfy --status without requiring --control-port on the CLI. */
    mqvpn_file_config_t file_cfg;
    mqvpn_config_defaults(&file_cfg);

    if (config_path) {
        if (mqvpn_config_load(&file_cfg, config_path) < 0) {
            return 1;
        }
    }

    /* Resolve effective control endpoint (INI base + per-field CLI overrides).
     * Used by both --status (below) and the server-mode listener (further down). */
    char eff_control_addr_buf[256] = {0};
    const char *eff_control_addr = NULL;
    int eff_control_port = 0;
    if (mqvpn_resolve_control_endpoint(file_cfg.control_listen, control_addr,
                                       control_port, control_port_set,
                                       eff_control_addr_buf, sizeof(eff_control_addr_buf),
                                       &eff_control_addr, &eff_control_port) < 0) {
        fprintf(stderr, "error: invalid [Control] Listen = '%s'\n",
                file_cfg.control_listen);
        return 1;
    }
    /* --control-addr without a port is a silent-disable trap: warn so admins
     * notice the missing --control-port / [Control] Listen. */
    if (eff_control_addr != NULL && eff_control_port == 0) {
        LOG_WRN("--control-addr ignored: no port configured (use --control-port "
                "or [Control] Listen)");
    }

#ifndef _WIN32
    /* --status: query control API and exit */
    if (status_mode) {
        if (eff_control_port <= 0) {
            fprintf(stderr, "error: --status requires --control-port or "
                            "[Control] Listen in config\n");
            return 1;
        }
        return run_status(eff_control_addr, eff_control_port);
    }
#endif

    /* CLI overrides config file values */
    const char *eff_tun_name = tun_name ? tun_name : file_cfg.tun_name;
    const char *eff_log_level = log_level_str ? log_level_str : file_cfg.log_level;
    const char *eff_scheduler = scheduler_str ? scheduler_str : file_cfg.scheduler;
    const char *eff_cc = cc_str ? cc_str : file_cfg.cc;
    int eff_mtu = mtu >= 0 ? mtu : file_cfg.mtu;
    int eff_outer_packet_size =
        outer_packet_size >= 0 ? outer_packet_size : file_cfg.outer_packet_size;
    int eff_pmtud_enable = pmtud_enable >= 0 ? pmtud_enable : file_cfg.pmtud_enable;
    int eff_pmtud_probe_size =
        pmtud_probe_size >= 0 ? pmtud_probe_size : file_cfg.pmtud_probe_size;
    const char *eff_listen = listen_str ? listen_str : file_cfg.listen;
    const char *eff_subnet = subnet ? subnet : file_cfg.subnet;
    const char *eff_subnet6 =
        subnet6 ? subnet6 : (file_cfg.subnet6[0] ? file_cfg.subnet6 : NULL);
    const char *eff_cert = cert_file ? cert_file : file_cfg.cert_file;
    const char *eff_key = key_file ? key_file : file_cfg.key_file;
    int eff_insecure = insecure >= 0 ? insecure : file_cfg.insecure;
    int eff_max_clients = max_clients >= 0 ? max_clients : file_cfg.max_clients;

    /* Auth key: CLI > config (use auth_key for client, server_auth_key for server) */
    const char *eff_auth_key =
        auth_key ? auth_key
                 : (file_cfg.server_auth_key[0]
                        ? file_cfg.server_auth_key
                        : (file_cfg.auth_key[0] ? file_cfg.auth_key : NULL));

    const char *eff_user_names[MQVPN_CONFIG_MAX_USERS];
    const char *eff_user_keys[MQVPN_CONFIG_MAX_USERS];
    int eff_n_users = 0;
    if (n_cli_users > 0) {
        eff_n_users = n_cli_users;
        for (int i = 0; i < eff_n_users; i++) {
            eff_user_names[i] = cli_user_names[i];
            eff_user_keys[i] = cli_user_keys[i];
        }
    } else if (file_cfg.n_users > 0) {
        eff_n_users = file_cfg.n_users;
        for (int i = 0; i < eff_n_users; i++) {
            eff_user_names[i] = file_cfg.user_names[i];
            eff_user_keys[i] = file_cfg.user_keys[i];
        }
    }

    /* Determine mode: CLI > config file > error */
    const char *eff_mode = mode;
    if (!eff_mode) {
        if (config_path) {
            eff_mode = file_cfg.is_server ? "server" : "client";
            /* Client mode needs server address */
            if (!file_cfg.is_server && file_cfg.server_addr[0] == '\0') {
                fprintf(
                    stderr,
                    "error: config has no [Server] Address and no --mode specified\n");
                usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "error: --mode is required\n");
            usage(argv[0]);
            return 1;
        }
    }

    /* Server address: CLI > config */
    const char *eff_server = server_str ? server_str : file_cfg.server_addr;

    /* Set log level */
    mqvpn_log_level_t log_level = MQVPN_LOG_INFO;
    if (strcmp(eff_log_level, "debug") == 0)
        log_level = MQVPN_LOG_DEBUG;
    else if (strcmp(eff_log_level, "info") == 0)
        log_level = MQVPN_LOG_INFO;
    else if (strcmp(eff_log_level, "warn") == 0)
        log_level = MQVPN_LOG_WARN;
    else if (strcmp(eff_log_level, "error") == 0)
        log_level = MQVPN_LOG_ERROR;
    mqvpn_log_set_level(log_level);

    mqvpn_scheduler_t scheduler = MQVPN_SCHED_MINRTT;
    if (parse_scheduler_name(eff_scheduler, &scheduler) < 0) return 1;

    mqvpn_cc_t cc = MQVPN_CC_BBR2;
    if (parse_cc_name(eff_cc, &cc) < 0) return 1;

    /* Paths: CLI paths override config paths entirely */
    if (n_paths == 0 && file_cfg.n_paths > 0) {
        n_paths = file_cfg.n_paths;
        for (int i = 0; i < n_paths; i++) {
            path_ifaces[i] = file_cfg.paths[i];
        }
    }

    /* DNS: CLI servers override config DNS entirely */
    if (n_dns == 0 && file_cfg.n_dns > 0) {
        n_dns = file_cfg.n_dns;
        for (int i = 0; i < n_dns; i++) {
            dns_servers[i] = file_cfg.dns_servers[i];
        }
    }

    if (strcmp(eff_mode, "client") == 0) {
        if (!eff_server || eff_server[0] == '\0') {
            fprintf(stderr, "error: --server is required for client mode\n");
            return 1;
        }

        char host[256];
        int port;
        if (parse_host_port(eff_server, host, sizeof(host), &port) < 0) {
            return 1;
        }

        if (eff_insecure) {
            LOG_WRN("--insecure: accepting untrusted certificates");
        }

        int eff_reconnect = no_reconnect ? 0 : file_cfg.reconnect;

        mqvpn_client_cfg_t cfg = {
            .server_addr = host,
            .server_port = port,
            .tun_name = eff_tun_name,
            .insecure = eff_insecure,
            .log_level = log_level,
            .n_paths = n_paths,
            .scheduler = scheduler,
            .cc = cc,
            .mtu = eff_mtu,
            .outer_packet_size = eff_outer_packet_size,
            .pmtud_enable = eff_pmtud_enable,
            .pmtud_probe_size = eff_pmtud_probe_size,
            .auth_key = eff_auth_key,
            .n_dns = n_dns,
            .n_client_routes = file_cfg.n_client_routes,
            .reconnect = eff_reconnect,
            .reconnect_interval = file_cfg.reconnect_interval,
            .kill_switch = kill_switch >= 0 ? kill_switch : file_cfg.kill_switch,
            .manage_routes = manage_routes >= 0 ? manage_routes : file_cfg.manage_routes,
        };
        for (int i = 0; i < n_paths; i++) {
            cfg.path_ifaces[i] = path_ifaces[i];
        }
        for (int i = 0; i < n_dns; i++) {
            cfg.dns_servers[i] = dns_servers[i];
        }
        for (int i = 0; i < file_cfg.n_client_routes; i++) {
            cfg.client_routes[i] = file_cfg.client_routes[i];
        }
#ifdef _WIN32
        return win_platform_run_client(&cfg);
#else
        return linux_platform_run_client(&cfg);
#endif

    } else if (strcmp(eff_mode, "server") == 0) {
        if ((!eff_auth_key || eff_auth_key[0] == '\0') && eff_n_users == 0) {
            fprintf(stderr,
                    "error: auth is required for server mode (--auth-key or --user)\n"
                    "       generate one with: mqvpn --genkey\n");
            return 1;
        }

        char bind_addr[256] = "0.0.0.0";
        int bind_port = 443;
        if (parse_host_port(eff_listen, bind_addr, sizeof(bind_addr), &bind_port) < 0) {
            return 1;
        }

        mqvpn_server_cfg_t cfg = {
            .listen_addr = bind_addr,
            .listen_port = bind_port,
            .subnet = eff_subnet,
            .subnet6 = eff_subnet6,
            .n_client_routes = file_cfg.n_client_routes,
            .tun_name = eff_tun_name,
            .cert_file = eff_cert,
            .key_file = eff_key,
            .log_level = log_level,
            .scheduler = scheduler,
            .cc = cc,
            .mtu = eff_mtu,
            .outer_packet_size = eff_outer_packet_size,
            .pmtud_enable = eff_pmtud_enable,
            .pmtud_probe_size = eff_pmtud_probe_size,
            .auth_key = eff_auth_key,
            .n_users = eff_n_users,
            .max_clients = eff_max_clients,
            .control_addr = eff_control_addr,
            .control_port = eff_control_port,
        };
        for (int i = 0; i < file_cfg.n_client_routes; i++) {
            cfg.client_routes[i] = file_cfg.client_routes[i];
        }
        for (int i = 0; i < eff_n_users; i++) {
            cfg.user_names[i] = eff_user_names[i];
            cfg.user_keys[i] = eff_user_keys[i];
        }
#ifdef _WIN32
        return win_platform_run_server(&cfg);
#else
        return linux_platform_run_server(&cfg);
#endif

    } else {
        fprintf(stderr, "error: --mode must be 'client' or 'server'\n");
        return 1;
    }
}
