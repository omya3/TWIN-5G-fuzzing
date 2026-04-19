#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_LISTEN_IP "127.0.0.6"
#define DEFAULT_LISTEN_PORT 38412
#define DEFAULT_AMF_IP "127.0.0.5"
#define DEFAULT_AMF_PORT 38412
#define DEFAULT_STREAMS 10
#define BUFFER_SIZE (1024 * 1024)

static volatile sig_atomic_t g_stop = 0;

struct ProxyConfig
{
    const char *listen_ip;
    int listen_port;
    const char *amf_ip;
    int amf_port;
    int streams;
    bool mutate_initial_nas_msgtype;
    bool mutate_registration_type_and_ngksi;
    bool mutate_initial_nas_security_header;
    bool mutate_mobile_identity_length;
    bool mutate_mobile_identity_tail_bcd;
    bool mutate_mobile_identity_type_bits;
    uint8_t initial_nas_target_msgtype;
    uint8_t registration_type_and_ngksi_target;
    uint8_t initial_nas_target_security_header;
    uint8_t mobile_identity_tail_bcd_target;
    uint16_t mobile_identity_length_target;
    int preview_bytes;
};

struct ProxyRuntime
{
    bool initial_nas_mutation_applied;
};

static void handle_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [--listen-ip IP] [--listen-port PORT] [--amf-ip IP] [--amf-port PORT]\n"
            "          [--streams N] [--preview-bytes N] [--mutate-initial-nas-msgtype BYTE]\n"
            "          [--mutate-registration-type-and-ngksi BYTE]\n"
            "          [--mutate-initial-nas-security-header BYTE]\n"
            "          [--mutate-mobile-identity-length WORD]\n"
            "          [--mutate-mobile-identity-tail-bcd BYTE]\n"
            "          [--mutate-mobile-identity-type-bits]\n"
            "          [--mutate-mobile-identity-length-zero]\n"
            "\n"
            "Transport-only SCTP NGAP proxy. It forwards SCTP messages unchanged while preserving\n"
            "stream id and PPID. It can also patch the first uplink plain Registration Request\n"
            "message-type byte found inside an NGAP payload, for example 0x41 -> 0x5c, or\n"
            "replace the Registration Request registration-type / ngKSI octet 0x79 -> another\n"
            "value such as 0x00, 0x71, 0x7f, or 0xf9, or\n"
            "replace the Registration Request plain security header 0x00 -> another value such\n"
            "as 0x01, 0x02, 0x03, 0x04, or 0x0f, or\n"
            "corrupt the Registration Request mobile-identity length 0x000d -> another value\n"
            "such as 0x0000, 0x0001, 0x000c, or 0x00ff, or\n"
            "patch the Registration Request mobile-identity tail octet 0x2e -> another value\n"
            "such as 0x2a to inject an invalid BCD digit, or\n"
            "toggle the first mobile-identity payload octet 0x01 -> 0x06 to make the\n"
            "identity type bits inconsistent.\n"
            "\n"
            "Defaults:\n"
            "  --listen-ip   %s\n"
            "  --listen-port %d\n"
            "  --amf-ip      %s\n"
            "  --amf-port    %d\n"
            "  --streams     %d\n"
            "  --preview-bytes %d\n",
            program,
            DEFAULT_LISTEN_IP,
            DEFAULT_LISTEN_PORT,
            DEFAULT_AMF_IP,
            DEFAULT_AMF_PORT,
            DEFAULT_STREAMS,
            12);
}

static int parse_int_arg(const char *name, const char *value)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 1 || parsed > 65535)
    {
        fprintf(stderr, "Invalid %s value: %s\n", name, value);
        exit(2);
    }
    return (int)parsed;
}

static uint8_t parse_byte_arg(const char *name, const char *value)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 0);
    if (end == value || *end != '\0' || parsed < 0 || parsed > 255)
    {
        fprintf(stderr, "Invalid %s value: %s\n", name, value);
        exit(2);
    }
    return (uint8_t)parsed;
}

static uint16_t parse_word_arg(const char *name, const char *value)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 0);
    if (end == value || *end != '\0' || parsed < 0 || parsed > 65535)
    {
        fprintf(stderr, "Invalid %s value: %s\n", name, value);
        exit(2);
    }
    return (uint16_t)parsed;
}

static struct ProxyConfig parse_args(int argc, char **argv)
{
    struct ProxyConfig cfg = {
        .listen_ip = DEFAULT_LISTEN_IP,
        .listen_port = DEFAULT_LISTEN_PORT,
        .amf_ip = DEFAULT_AMF_IP,
        .amf_port = DEFAULT_AMF_PORT,
        .streams = DEFAULT_STREAMS,
        .mutate_initial_nas_msgtype = false,
        .mutate_registration_type_and_ngksi = false,
        .mutate_initial_nas_security_header = false,
        .mutate_mobile_identity_length = false,
        .mutate_mobile_identity_tail_bcd = false,
        .mutate_mobile_identity_type_bits = false,
        .initial_nas_target_msgtype = 0x5c,
        .registration_type_and_ngksi_target = 0x00,
        .initial_nas_target_security_header = 0x01,
        .mobile_identity_tail_bcd_target = 0x2a,
        .mobile_identity_length_target = 0x000d,
        .preview_bytes = 12,
    };

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
        {
            usage(argv[0]);
            exit(0);
        }
        else if (strcmp(argv[i], "--listen-ip") == 0 && i + 1 < argc)
        {
            cfg.listen_ip = argv[++i];
        }
        else if (strcmp(argv[i], "--listen-port") == 0 && i + 1 < argc)
        {
            cfg.listen_port = parse_int_arg("--listen-port", argv[++i]);
        }
        else if (strcmp(argv[i], "--amf-ip") == 0 && i + 1 < argc)
        {
            cfg.amf_ip = argv[++i];
        }
        else if (strcmp(argv[i], "--amf-port") == 0 && i + 1 < argc)
        {
            cfg.amf_port = parse_int_arg("--amf-port", argv[++i]);
        }
        else if (strcmp(argv[i], "--streams") == 0 && i + 1 < argc)
        {
            cfg.streams = parse_int_arg("--streams", argv[++i]);
        }
        else if (strcmp(argv[i], "--preview-bytes") == 0 && i + 1 < argc)
        {
            cfg.preview_bytes = parse_int_arg("--preview-bytes", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-initial-nas-msgtype") == 0 && i + 1 < argc)
        {
            cfg.mutate_initial_nas_msgtype = true;
            cfg.initial_nas_target_msgtype =
                parse_byte_arg("--mutate-initial-nas-msgtype", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-registration-type-and-ngksi") == 0 && i + 1 < argc)
        {
            cfg.mutate_registration_type_and_ngksi = true;
            cfg.registration_type_and_ngksi_target =
                parse_byte_arg("--mutate-registration-type-and-ngksi", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-initial-nas-security-header") == 0 && i + 1 < argc)
        {
            cfg.mutate_initial_nas_security_header = true;
            cfg.initial_nas_target_security_header =
                parse_byte_arg("--mutate-initial-nas-security-header", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-mobile-identity-length-zero") == 0)
        {
            cfg.mutate_mobile_identity_length = true;
            cfg.mobile_identity_length_target = 0x0000;
        }
        else if (strcmp(argv[i], "--mutate-mobile-identity-length") == 0 && i + 1 < argc)
        {
            cfg.mutate_mobile_identity_length = true;
            cfg.mobile_identity_length_target =
                parse_word_arg("--mutate-mobile-identity-length", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-mobile-identity-tail-bcd") == 0 && i + 1 < argc)
        {
            cfg.mutate_mobile_identity_tail_bcd = true;
            cfg.mobile_identity_tail_bcd_target =
                parse_byte_arg("--mutate-mobile-identity-tail-bcd", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-mobile-identity-type-bits") == 0)
        {
            cfg.mutate_mobile_identity_type_bits = true;
        }
        else
        {
            usage(argv[0]);
            exit(2);
        }
    }

    int mutation_modes = 0;
    if (cfg.mutate_initial_nas_msgtype)
        mutation_modes++;
    if (cfg.mutate_registration_type_and_ngksi)
        mutation_modes++;
    if (cfg.mutate_initial_nas_security_header)
        mutation_modes++;
    if (cfg.mutate_mobile_identity_length)
        mutation_modes++;
    if (cfg.mutate_mobile_identity_tail_bcd)
        mutation_modes++;
    if (cfg.mutate_mobile_identity_type_bits)
        mutation_modes++;

    if (mutation_modes > 1)
    {
        fprintf(stderr,
                "Choose only one mutation mode at a time: message-type, registration-type-and-ngksi, security-header, mobile-identity-length, mobile-identity-tail-bcd, or mobile-identity-type-bits.\n");
        exit(2);
    }

    return cfg;
}

static void set_initmsg(int fd, int streams)
{
    struct sctp_initmsg initmsg;
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = (uint16_t)streams;
    initmsg.sinit_max_instreams = (uint16_t)streams;
    initmsg.sinit_max_attempts = 4;

    if (setsockopt(fd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0)
    {
        perror("setsockopt(SCTP_INITMSG)");
        exit(1);
    }
}

static struct sockaddr_in make_addr(const char *ip, int port)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1)
    {
        fprintf(stderr, "Invalid IPv4 address: %s\n", ip);
        exit(2);
    }

    return addr;
}

static int create_listener(const struct ProxyConfig *cfg)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0)
    {
        perror("socket(listener)");
        exit(1);
    }

    int yes = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0)
    {
        perror("setsockopt(SO_REUSEADDR)");
        exit(1);
    }

    set_initmsg(fd, cfg->streams);

    struct sockaddr_in listen_addr = make_addr(cfg->listen_ip, cfg->listen_port);
    if (bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
    {
        perror("bind(listener)");
        exit(1);
    }

    if (listen(fd, 1) < 0)
    {
        perror("listen");
        exit(1);
    }

    return fd;
}

static int connect_to_amf(const struct ProxyConfig *cfg)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0)
    {
        perror("socket(amf)");
        exit(1);
    }

    set_initmsg(fd, cfg->streams);

    struct sockaddr_in amf_addr = make_addr(cfg->amf_ip, cfg->amf_port);
    if (connect(fd, (struct sockaddr *)&amf_addr, sizeof(amf_addr)) < 0)
    {
        perror("connect(amf)");
        close(fd);
        return -1;
    }

    return fd;
}

static const char *direction_label(int from_fd, int gnb_fd)
{
    return from_fd == gnb_fd ? "gNB -> AMF" : "AMF -> gNB";
}

static void log_preview_bytes(const unsigned char *buffer, ssize_t n, int preview_bytes)
{
    int limit = preview_bytes;
    if (limit < 0)
        limit = 0;
    if ((ssize_t)limit > n)
        limit = (int)n;

    fprintf(stderr, "[proxy] preview   ");
    for (int i = 0; i < limit; i++)
    {
        fprintf(stderr, "%02x", buffer[i]);
        if (i + 1 < limit)
            fputc(' ', stderr);
    }
    if (limit < n)
        fprintf(stderr, " ...");
    fputc('\n', stderr);
}

static bool maybe_patch_initial_nas(
    const struct ProxyConfig *cfg,
    struct ProxyRuntime *runtime,
    int from_fd,
    int gnb_fd,
    unsigned char *buffer,
    ssize_t n)
{
    if (!cfg->mutate_initial_nas_msgtype &&
        !cfg->mutate_registration_type_and_ngksi &&
        !cfg->mutate_initial_nas_security_header &&
        !cfg->mutate_mobile_identity_length &&
        !cfg->mutate_mobile_identity_tail_bcd &&
        !cfg->mutate_mobile_identity_type_bits)
        return false;
    if (runtime->initial_nas_mutation_applied)
        return false;
    if (from_fd != gnb_fd)
        return false;
    if (n < 3)
        return false;

    if (cfg->mutate_initial_nas_msgtype)
    {
        for (ssize_t i = 0; i <= n - 3; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41)
            {
                fprintf(stderr,
                        "[proxy] mutating initial NAS message type at offset=%zd 0x41 -> 0x%02x\n",
                        i + 2,
                        cfg->initial_nas_target_msgtype);
                buffer[i + 2] = cfg->initial_nas_target_msgtype;
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_initial_nas_security_header)
    {
        for (ssize_t i = 0; i <= n - 3; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41)
            {
                fprintf(stderr,
                        "[proxy] mutating initial NAS security header at offset=%zd 0x00 -> 0x%02x\n",
                        i + 1,
                        cfg->initial_nas_target_security_header);
                buffer[i + 1] = cfg->initial_nas_target_security_header;
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_registration_type_and_ngksi)
    {
        for (ssize_t i = 0; i <= n - 4; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41)
            {
                fprintf(stderr,
                        "[proxy] mutating registration type / ngKSI at offset=%zd 0x%02x -> 0x%02x\n",
                        i + 3,
                        buffer[i + 3],
                        cfg->registration_type_and_ngksi_target);
                buffer[i + 3] = cfg->registration_type_and_ngksi_target;
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_mobile_identity_length)
    {
        if (n < 6)
            return false;

        for (ssize_t i = 0; i <= n - 6; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41 &&
                buffer[i + 3] == 0x79 && buffer[i + 4] == 0x00 && buffer[i + 5] == 0x0d)
            {
                fprintf(stderr,
                        "[proxy] corrupting mobile identity length at offsets=%zd/%zd 0x000d -> 0x%04x\n",
                        i + 4,
                        i + 5,
                        cfg->mobile_identity_length_target);
                buffer[i + 4] = (unsigned char)((cfg->mobile_identity_length_target >> 8) & 0xff);
                buffer[i + 5] = (unsigned char)(cfg->mobile_identity_length_target & 0xff);
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_mobile_identity_tail_bcd)
    {
        if (n < 20)
            return false;

        for (ssize_t i = 0; i <= n - 20; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41 &&
                buffer[i + 3] == 0x79 && buffer[i + 4] == 0x00 && buffer[i + 5] == 0x0d &&
                buffer[i + 19] == 0x2e)
            {
                fprintf(stderr,
                        "[proxy] corrupting mobile identity tail octet at offset=%zd 0x2e -> 0x%02x\n",
                        i + 19,
                        cfg->mobile_identity_tail_bcd_target);
                buffer[i + 19] = cfg->mobile_identity_tail_bcd_target;
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_mobile_identity_type_bits)
    {
        if (n < 7)
            return false;

        for (ssize_t i = 0; i <= n - 7; i++)
        {
            if (buffer[i] == 0x7e && buffer[i + 1] == 0x00 && buffer[i + 2] == 0x41 &&
                buffer[i + 3] == 0x79 && buffer[i + 4] == 0x00 && buffer[i + 5] == 0x0d)
            {
                fprintf(stderr,
                        "[proxy] toggling mobile identity type bits at offset=%zd 0x%02x -> 0x06\n",
                        i + 6,
                        buffer[i + 6]);
                buffer[i + 6] = 0x06;
                runtime->initial_nas_mutation_applied = true;
                return true;
            }
        }
    }

    return false;
}

static bool forward_one_message(
    const struct ProxyConfig *cfg,
    struct ProxyRuntime *runtime,
    int from_fd,
    int to_fd,
    int gnb_fd,
    unsigned char *buffer)
{
    struct sctp_sndrcvinfo info;
    memset(&info, 0, sizeof(info));
    int flags = 0;

    ssize_t n = sctp_recvmsg(from_fd, buffer, BUFFER_SIZE, NULL, 0, &info, &flags);
    if (n == 0)
    {
        fprintf(stderr, "[proxy] %s association closed\n", direction_label(from_fd, gnb_fd));
        return false;
    }
    if (n < 0)
    {
        if (errno == EINTR)
            return true;
        perror("sctp_recvmsg");
        return false;
    }

    if (flags & MSG_NOTIFICATION)
    {
        fprintf(stderr, "[proxy] SCTP notification on %s (%zd bytes), not forwarded\n",
                direction_label(from_fd, gnb_fd),
                n);
        return true;
    }

    uint32_t ppid = ntohl(info.sinfo_ppid);
    uint16_t stream = info.sinfo_stream;
    fprintf(stderr,
            "[proxy] %-10s bytes=%zd stream=%u ppid=%u\n",
            direction_label(from_fd, gnb_fd),
            n,
            stream,
            ppid);
    log_preview_bytes(buffer, n, cfg->preview_bytes);
    maybe_patch_initial_nas(cfg, runtime, from_fd, gnb_fd, buffer, n);

    int sent = sctp_sendmsg(to_fd,
                            buffer,
                            (size_t)n,
                            NULL,
                            0,
                            info.sinfo_ppid,
                            info.sinfo_flags,
                            stream,
                            info.sinfo_timetolive,
                            info.sinfo_context);
    if (sent < 0)
    {
        perror("sctp_sendmsg");
        return false;
    }
    if (sent != n)
    {
        fprintf(stderr, "[proxy] short SCTP send: sent=%d expected=%zd\n", sent, n);
        return false;
    }

    return true;
}

static int relay_loop_with_config(
    const struct ProxyConfig *cfg,
    struct ProxyRuntime *runtime,
    int gnb_fd,
    int amf_fd)
{
    unsigned char *buffer = malloc(BUFFER_SIZE);
    if (!buffer)
    {
        perror("malloc");
        return 1;
    }

    while (!g_stop)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(gnb_fd, &readfds);
        FD_SET(amf_fd, &readfds);
        int maxfd = gnb_fd > amf_fd ? gnb_fd : amf_fd;

        int rc = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (rc < 0)
        {
            if (errno == EINTR)
                continue;
            perror("select");
            free(buffer);
            return 1;
        }

        if (FD_ISSET(gnb_fd, &readfds))
        {
            if (!forward_one_message(cfg, runtime, gnb_fd, amf_fd, gnb_fd, buffer))
                break;
        }

        if (FD_ISSET(amf_fd, &readfds))
        {
            if (!forward_one_message(cfg, runtime, amf_fd, gnb_fd, gnb_fd, buffer))
                break;
        }
    }

    free(buffer);
    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    struct ProxyConfig cfg = parse_args(argc, argv);

    fprintf(stderr,
            "[proxy] listen %s:%d -> AMF %s:%d streams=%d preview-bytes=%d\n",
            cfg.listen_ip,
            cfg.listen_port,
            cfg.amf_ip,
            cfg.amf_port,
            cfg.streams,
            cfg.preview_bytes);
    if (cfg.mutate_initial_nas_msgtype)
    {
        fprintf(stderr,
                "[proxy] initial NAS message-type mutation enabled: 0x41 -> 0x%02x\n",
                cfg.initial_nas_target_msgtype);
    }
    if (cfg.mutate_initial_nas_security_header)
    {
        fprintf(stderr,
                "[proxy] initial NAS security-header mutation enabled: 0x00 -> 0x%02x\n",
                cfg.initial_nas_target_security_header);
    }
    if (cfg.mutate_mobile_identity_length)
    {
        fprintf(stderr,
                "[proxy] mobile-identity-length mutation enabled: 0x000d -> 0x%04x\n",
                cfg.mobile_identity_length_target);
    }
    if (cfg.mutate_mobile_identity_tail_bcd)
    {
        fprintf(stderr,
                "[proxy] mobile-identity-tail-bcd mutation enabled: 0x2e -> 0x%02x\n",
                cfg.mobile_identity_tail_bcd_target);
    }
    if (cfg.mutate_mobile_identity_type_bits)
    {
        fprintf(stderr,
                "[proxy] mobile-identity-type-bits mutation enabled: 0x01 -> 0x06\n");
    }

    int listener = create_listener(&cfg);
    fprintf(stderr, "[proxy] waiting for gNB SCTP association...\n");

    struct sockaddr_in peer_addr;
    socklen_t peer_len = sizeof(peer_addr);
    int gnb_fd = accept(listener, (struct sockaddr *)&peer_addr, &peer_len);
    if (gnb_fd < 0)
    {
        perror("accept");
        close(listener);
        return 1;
    }

    char peer_ip[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, sizeof(peer_ip));
    fprintf(stderr, "[proxy] accepted gNB from %s:%d\n", peer_ip, ntohs(peer_addr.sin_port));

    fprintf(stderr, "[proxy] connecting to real AMF...\n");
    int amf_fd = connect_to_amf(&cfg);
    if (amf_fd < 0)
    {
        close(gnb_fd);
        close(listener);
        return 1;
    }
    fprintf(stderr, "[proxy] connected to AMF\n");

    struct ProxyRuntime runtime = {
        .initial_nas_mutation_applied = false,
    };

    int rc = relay_loop_with_config(&cfg, &runtime, gnb_fd, amf_fd);

    fprintf(stderr, "[proxy] shutting down\n");
    close(amf_fd);
    close(gnb_fd);
    close(listener);
    return rc;
}
