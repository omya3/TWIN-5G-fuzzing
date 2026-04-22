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
    bool mutate_nested_optional_ie_omit;
    bool mutate_nested_optional_ie_bad_length;
    bool mutate_nested_optional_ie_duplicate;
    bool mutate_nested_optional_ie_unsupported_sst_sd;
    bool mutate_nested_optional_ie_duplicate_payload_entries;
    bool mutate_nested_optional_ie_set_reserved_bits;
    bool mutate_nested_optional_ie_truncate_payload;
    uint8_t initial_nas_target_msgtype;
    uint8_t registration_type_and_ngksi_target;
    uint8_t initial_nas_target_security_header;
    uint8_t mobile_identity_tail_bcd_target;
    uint8_t nested_optional_ie_tag;
    uint8_t nested_optional_ie_bad_length_target;
    const char *nested_optional_ie_name;
    uint16_t mobile_identity_length_target;
    int preview_bytes;
};

struct ProxyRuntime
{
    bool selected_nas_mutation_applied;
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
            "          [--mutate-nested-optional-ie SPEC]\n"
            "          [--mutate-nested-requested-nssai-omit]\n"
            "          [--mutate-nested-requested-nssai-bad-length BYTE]\n"
            "          [--mutate-nested-fivegmm-capability-omit]\n"
            "          [--mutate-nested-fivegmm-capability-bad-length BYTE]\n"
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
            "identity type bits inconsistent, or\n"
            "remove or corrupt optional IEs such as Requested NSSAI or 5GMM capability\n"
            "inside a later nested Registration Request carried in an uplink protected NAS payload.\n"
            "For the generic nested optional-IE flag, SPEC can look like:\n"
            "  field:requested_nssai,action:omit\n"
            "  field:requested_nssai,action:bad-length,length:0xff\n"
            "  field:requested_nssai,action:duplicate\n"
            "  field:requested_nssai,action:unsupported-sst-sd\n"
            "  field:requested_nssai,action:duplicate-payload-entries\n"
            "  field:fivegmm_capability,action:omit\n"
            "  field:fivegmm_capability,action:bad-length,length:0xff\n"
            "  field:fivegmm_capability,action:set-reserved-bits\n"
            "  field:fivegmm_capability,action:truncate-payload\n"
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

static bool read_spec_token(
    const char *spec,
    const char *key,
    char *output,
    size_t output_size)
{
    size_t key_length = strlen(key);
    const char *cursor = spec;

    while (cursor && *cursor)
    {
        const char *next = strchr(cursor, ',');
        size_t token_length = next ? (size_t)(next - cursor) : strlen(cursor);

        if (token_length > key_length + 1 &&
            strncmp(cursor, key, key_length) == 0 &&
            cursor[key_length] == ':')
        {
            size_t value_length = token_length - key_length - 1;
            if (value_length >= output_size)
            {
                fprintf(stderr, "Nested optional IE spec value too long for key '%s'\n", key);
                exit(2);
            }
            memcpy(output, cursor + key_length + 1, value_length);
            output[value_length] = '\0';
            return true;
        }

        cursor = next ? next + 1 : NULL;
    }

    return false;
}

static void configure_nested_optional_ie_field(struct ProxyConfig *cfg, const char *field_name)
{
    if (strcmp(field_name, "requested_nssai") == 0)
    {
        cfg->nested_optional_ie_tag = 0x2f;
        cfg->nested_optional_ie_name = "Requested NSSAI";
        return;
    }

    if (strcmp(field_name, "fivegmm_capability") == 0)
    {
        cfg->nested_optional_ie_tag = 0x10;
        cfg->nested_optional_ie_name = "5GMM capability";
        return;
    }

    fprintf(stderr, "Unsupported nested optional IE field '%s'\n", field_name);
    exit(2);
}

static void parse_nested_optional_ie_spec(struct ProxyConfig *cfg, const char *spec)
{
    char field_name[64];
    char action[64];
    char length_value[64];
    bool has_field = read_spec_token(spec, "field", field_name, sizeof(field_name));
    bool has_action = read_spec_token(spec, "action", action, sizeof(action));
    bool has_length = read_spec_token(spec, "length", length_value, sizeof(length_value));

    if (!has_field || !has_action)
    {
        fprintf(stderr,
                "Invalid nested optional IE spec '%s'; expected field:<name>,action:<name>[,length:<byte>]\n",
                spec);
        exit(2);
    }

    configure_nested_optional_ie_field(cfg, field_name);

    if (strcmp(action, "omit") == 0)
    {
        cfg->mutate_nested_optional_ie_omit = true;
        return;
    }

    if (strcmp(action, "bad-length") == 0)
    {
        cfg->mutate_nested_optional_ie_bad_length = true;
        cfg->nested_optional_ie_bad_length_target = has_length
            ? parse_byte_arg("--mutate-nested-optional-ie length", length_value)
            : 0xff;
        return;
    }

    if (strcmp(action, "duplicate") == 0)
    {
        cfg->mutate_nested_optional_ie_duplicate = true;
        return;
    }

    if (strcmp(action, "unsupported-sst-sd") == 0)
    {
        if (cfg->nested_optional_ie_tag != 0x2f)
        {
            fprintf(stderr,
                    "Action 'unsupported-sst-sd' is only supported for requested_nssai, not '%s'\n",
                    field_name);
            exit(2);
        }
        cfg->mutate_nested_optional_ie_unsupported_sst_sd = true;
        return;
    }

    if (strcmp(action, "duplicate-payload-entries") == 0)
    {
        if (cfg->nested_optional_ie_tag != 0x2f)
        {
            fprintf(stderr,
                    "Action 'duplicate-payload-entries' is only supported for requested_nssai, not '%s'\n",
                    field_name);
            exit(2);
        }
        cfg->mutate_nested_optional_ie_duplicate_payload_entries = true;
        return;
    }

    if (strcmp(action, "set-reserved-bits") == 0)
    {
        if (cfg->nested_optional_ie_tag != 0x10)
        {
            fprintf(stderr,
                    "Action 'set-reserved-bits' is only supported for fivegmm_capability, not '%s'\n",
                    field_name);
            exit(2);
        }
        cfg->mutate_nested_optional_ie_set_reserved_bits = true;
        return;
    }

    if (strcmp(action, "truncate-payload") == 0)
    {
        if (cfg->nested_optional_ie_tag != 0x10)
        {
            fprintf(stderr,
                    "Action 'truncate-payload' is only supported for fivegmm_capability, not '%s'\n",
                    field_name);
            exit(2);
        }
        cfg->mutate_nested_optional_ie_truncate_payload = true;
        return;
    }

    fprintf(stderr,
            "Unsupported nested optional IE action '%s' in spec '%s'\n",
            action,
            spec);
    exit(2);
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
        .mutate_nested_optional_ie_omit = false,
        .mutate_nested_optional_ie_bad_length = false,
        .mutate_nested_optional_ie_duplicate = false,
        .mutate_nested_optional_ie_unsupported_sst_sd = false,
        .mutate_nested_optional_ie_duplicate_payload_entries = false,
        .mutate_nested_optional_ie_set_reserved_bits = false,
        .mutate_nested_optional_ie_truncate_payload = false,
        .initial_nas_target_msgtype = 0x5c,
        .registration_type_and_ngksi_target = 0x00,
        .initial_nas_target_security_header = 0x01,
        .mobile_identity_tail_bcd_target = 0x2a,
        .nested_optional_ie_tag = 0x00,
        .nested_optional_ie_bad_length_target = 0xff,
        .nested_optional_ie_name = "nested optional IE",
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
        else if (strcmp(argv[i], "--mutate-nested-optional-ie") == 0 && i + 1 < argc)
        {
            parse_nested_optional_ie_spec(&cfg, argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-nested-requested-nssai-omit") == 0)
        {
            cfg.mutate_nested_optional_ie_omit = true;
            configure_nested_optional_ie_field(&cfg, "requested_nssai");
        }
        else if (strcmp(argv[i], "--mutate-nested-requested-nssai-bad-length") == 0 && i + 1 < argc)
        {
            cfg.mutate_nested_optional_ie_bad_length = true;
            configure_nested_optional_ie_field(&cfg, "requested_nssai");
            cfg.nested_optional_ie_bad_length_target =
                parse_byte_arg("--mutate-nested-requested-nssai-bad-length", argv[++i]);
        }
        else if (strcmp(argv[i], "--mutate-nested-fivegmm-capability-omit") == 0)
        {
            cfg.mutate_nested_optional_ie_omit = true;
            configure_nested_optional_ie_field(&cfg, "fivegmm_capability");
        }
        else if (strcmp(argv[i], "--mutate-nested-fivegmm-capability-bad-length") == 0 && i + 1 < argc)
        {
            cfg.mutate_nested_optional_ie_bad_length = true;
            configure_nested_optional_ie_field(&cfg, "fivegmm_capability");
            cfg.nested_optional_ie_bad_length_target =
                parse_byte_arg("--mutate-nested-fivegmm-capability-bad-length", argv[++i]);
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
    if (cfg.mutate_nested_optional_ie_omit)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_bad_length)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_duplicate)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_unsupported_sst_sd)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_duplicate_payload_entries)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_set_reserved_bits)
        mutation_modes++;
    if (cfg.mutate_nested_optional_ie_truncate_payload)
        mutation_modes++;

    if (mutation_modes > 1)
    {
        fprintf(stderr,
                "Choose only one mutation mode at a time: message-type, registration-type-and-ngksi, security-header, mobile-identity-length, mobile-identity-tail-bcd, mobile-identity-type-bits, mutate-nested-optional-ie, nested-requested-nssai-omit, nested-requested-nssai-bad-length, nested-fivegmm-capability-omit, or nested-fivegmm-capability-bad-length.\n");
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

static void remove_octet_span(unsigned char *buffer, ssize_t *n_inout, ssize_t offset, ssize_t length)
{
    memmove(buffer + offset,
            buffer + offset + length,
            (size_t)(*n_inout - (offset + length)));
    *n_inout -= length;
}

static bool duplicate_octet_span(
    unsigned char *buffer,
    ssize_t *n_inout,
    ssize_t offset,
    ssize_t length,
    ssize_t insert_offset)
{
    if (offset < 0 || length < 0 || insert_offset < 0)
    {
        fprintf(stderr, "[proxy] duplicate span uses a negative offset or length\n");
        return false;
    }
    if (offset + length > *n_inout || insert_offset > *n_inout)
    {
        fprintf(stderr, "[proxy] duplicate span exceeds the current packet bounds\n");
        return false;
    }
    if (*n_inout + length > BUFFER_SIZE)
    {
        fprintf(stderr, "[proxy] duplicate span would exceed the proxy buffer capacity\n");
        return false;
    }

    unsigned char *copy = malloc((size_t)length);
    if (!copy)
    {
        perror("malloc");
        return false;
    }

    memcpy(copy, buffer + offset, (size_t)length);
    memmove(buffer + insert_offset + length,
            buffer + insert_offset,
            (size_t)(*n_inout - insert_offset));
    memcpy(buffer + insert_offset, copy, (size_t)length);
    *n_inout += length;
    free(copy);
    return true;
}

static bool maybe_patch_selected_nas(
    const struct ProxyConfig *cfg,
    struct ProxyRuntime *runtime,
    int from_fd,
    int gnb_fd,
    unsigned char *buffer,
    ssize_t *n_inout)
{
    ssize_t n = *n_inout;
    if (!cfg->mutate_initial_nas_msgtype &&
        !cfg->mutate_registration_type_and_ngksi &&
        !cfg->mutate_initial_nas_security_header &&
        !cfg->mutate_mobile_identity_length &&
        !cfg->mutate_mobile_identity_tail_bcd &&
        !cfg->mutate_mobile_identity_type_bits &&
        !cfg->mutate_nested_optional_ie_omit &&
        !cfg->mutate_nested_optional_ie_bad_length &&
        !cfg->mutate_nested_optional_ie_duplicate &&
        !cfg->mutate_nested_optional_ie_unsupported_sst_sd &&
        !cfg->mutate_nested_optional_ie_duplicate_payload_entries &&
        !cfg->mutate_nested_optional_ie_set_reserved_bits &&
        !cfg->mutate_nested_optional_ie_truncate_payload)
        return false;
    if (runtime->selected_nas_mutation_applied)
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
                runtime->selected_nas_mutation_applied = true;
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
                runtime->selected_nas_mutation_applied = true;
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
                runtime->selected_nas_mutation_applied = true;
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
                runtime->selected_nas_mutation_applied = true;
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
                runtime->selected_nas_mutation_applied = true;
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
                runtime->selected_nas_mutation_applied = true;
                return true;
            }
        }
    }

    if (cfg->mutate_nested_optional_ie_omit ||
        cfg->mutate_nested_optional_ie_bad_length ||
        cfg->mutate_nested_optional_ie_duplicate ||
        cfg->mutate_nested_optional_ie_unsupported_sst_sd ||
        cfg->mutate_nested_optional_ie_duplicate_payload_entries ||
        cfg->mutate_nested_optional_ie_set_reserved_bits ||
        cfg->mutate_nested_optional_ie_truncate_payload)
    {
        if (n < 8)
            return false;

        for (ssize_t start = 1; start <= n - 6; start++)
        {
            if (buffer[start] != 0x7e || buffer[start + 1] != 0x00 || buffer[start + 2] != 0x41 ||
                buffer[start + 3] != 0x79)
                continue;

            ssize_t mobile_identity_length = ((ssize_t)buffer[start + 4] << 8) | buffer[start + 5];
            ssize_t tlv_offset = start + 6 + mobile_identity_length;
            if (mobile_identity_length < 0 || tlv_offset > n)
                continue;

            for (ssize_t pos = tlv_offset; pos <= n - 2;)
            {
                uint8_t tag = buffer[pos];
                ssize_t value_length = buffer[pos + 1];
                ssize_t total_length = 2 + value_length;

                if (pos + total_length > n)
                    break;

                if (tag == cfg->nested_optional_ie_tag)
                {
                    if (cfg->mutate_nested_optional_ie_omit)
                    {
                        fprintf(stderr,
                                "[proxy] removing nested %s IE at outer offset=%zd nested_rr_offset=%zd total_length=%zd\n",
                                cfg->nested_optional_ie_name,
                                pos,
                                start,
                                total_length);
                        remove_octet_span(buffer, n_inout, pos, total_length);
                    }
                    else if (cfg->mutate_nested_optional_ie_bad_length)
                    {
                        fprintf(stderr,
                                "[proxy] patching nested %s IE length at outer offset=%zd nested_rr_offset=%zd 0x%02x -> 0x%02x\n",
                                cfg->nested_optional_ie_name,
                                pos + 1,
                                start,
                                buffer[pos + 1],
                                cfg->nested_optional_ie_bad_length_target);
                        buffer[pos + 1] = cfg->nested_optional_ie_bad_length_target;
                    }
                    else if (cfg->mutate_nested_optional_ie_duplicate)
                    {
                        fprintf(stderr,
                                "[proxy] duplicating nested %s IE at outer offset=%zd nested_rr_offset=%zd total_length=%zd\n",
                                cfg->nested_optional_ie_name,
                                pos,
                                start,
                                total_length);
                        if (!duplicate_octet_span(buffer, n_inout, pos, total_length, pos + total_length))
                            return false;
                    }
                    else if (cfg->mutate_nested_optional_ie_unsupported_sst_sd)
                    {
                        if (value_length < 2)
                        {
                            fprintf(stderr,
                                    "[proxy] cannot patch nested %s payload into unsupported SST/SD: payload length=%zd\n",
                                    cfg->nested_optional_ie_name,
                                    value_length);
                            return false;
                        }
                        fprintf(stderr,
                                "[proxy] patching nested %s payload at outer offsets=%zd/%zd 0x%02x:0x%02x -> 0xff:0xff\n",
                                cfg->nested_optional_ie_name,
                                pos + 2,
                                pos + 3,
                                buffer[pos + 2],
                                buffer[pos + 3]);
                        buffer[pos + 2] = 0xff;
                        buffer[pos + 3] = 0xff;
                    }
                    else if (cfg->mutate_nested_optional_ie_duplicate_payload_entries)
                    {
                        if (value_length < 1)
                        {
                            fprintf(stderr,
                                    "[proxy] cannot duplicate nested %s payload entries because the payload is empty\n",
                                    cfg->nested_optional_ie_name);
                            return false;
                        }
                        if (value_length > 0xff - value_length)
                        {
                            fprintf(stderr,
                                    "[proxy] cannot duplicate nested %s payload entries because the new length would exceed 0xff\n",
                                    cfg->nested_optional_ie_name);
                            return false;
                        }
                        fprintf(stderr,
                                "[proxy] duplicating nested %s payload entries at outer offset=%zd nested_rr_offset=%zd length=0x%02x -> 0x%02x\n",
                                cfg->nested_optional_ie_name,
                                pos + 2,
                                start,
                                buffer[pos + 1],
                                (unsigned int)(value_length * 2));
                        if (!duplicate_octet_span(
                                buffer,
                                n_inout,
                                pos + 2,
                                value_length,
                                pos + 2 + value_length))
                            return false;
                        buffer[pos + 1] = (unsigned char)(value_length * 2);
                    }
                    else if (cfg->mutate_nested_optional_ie_set_reserved_bits)
                    {
                        if (value_length < 1)
                        {
                            fprintf(stderr,
                                    "[proxy] cannot set reserved bits for nested %s because the payload is empty\n",
                                    cfg->nested_optional_ie_name);
                            return false;
                        }
                        fprintf(stderr,
                                "[proxy] setting reserved bits in nested %s payload at outer offset=%zd 0x%02x -> 0xff\n",
                                cfg->nested_optional_ie_name,
                                pos + 2,
                                buffer[pos + 2]);
                        buffer[pos + 2] = 0xff;
                    }
                    else if (cfg->mutate_nested_optional_ie_truncate_payload)
                    {
                        if (value_length < 1)
                        {
                            fprintf(stderr,
                                    "[proxy] cannot truncate nested %s payload because it is already empty\n",
                                    cfg->nested_optional_ie_name);
                            return false;
                        }
                        fprintf(stderr,
                                "[proxy] truncating nested %s payload at outer offset=%zd removing 0x%02x and length 0x%02x -> 0x%02x\n",
                                cfg->nested_optional_ie_name,
                                pos + 1 + value_length,
                                buffer[pos + 1 + value_length],
                                buffer[pos + 1],
                                (unsigned int)(value_length - 1));
                        remove_octet_span(buffer, n_inout, pos + 1 + value_length, 1);
                        buffer[pos + 1] = (unsigned char)(value_length - 1);
                    }
                    else
                    {
                        fprintf(stderr,
                                "[proxy] nested optional IE mutation mode was selected but no action matched\n");
                        return false;
                    }
                    runtime->selected_nas_mutation_applied = true;
                    return true;
                }

                pos += total_length;
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
    maybe_patch_selected_nas(cfg, runtime, from_fd, gnb_fd, buffer, &n);

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
    if (cfg.mutate_nested_optional_ie_omit)
    {
        fprintf(stderr,
                "[proxy] nested %s omit mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
    }
    if (cfg.mutate_nested_optional_ie_bad_length)
    {
        fprintf(stderr,
                "[proxy] nested %s bad-length mutation enabled for later nested Registration Request packets: 0x%02x\n",
                cfg.nested_optional_ie_name,
                cfg.nested_optional_ie_bad_length_target);
    }
    if (cfg.mutate_nested_optional_ie_duplicate)
    {
        fprintf(stderr,
                "[proxy] nested %s duplicate-IE mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
    }
    if (cfg.mutate_nested_optional_ie_unsupported_sst_sd)
    {
        fprintf(stderr,
                "[proxy] nested %s unsupported-SST/SD mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
    }
    if (cfg.mutate_nested_optional_ie_duplicate_payload_entries)
    {
        fprintf(stderr,
                "[proxy] nested %s duplicate-payload-entries mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
    }
    if (cfg.mutate_nested_optional_ie_set_reserved_bits)
    {
        fprintf(stderr,
                "[proxy] nested %s set-reserved-bits mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
    }
    if (cfg.mutate_nested_optional_ie_truncate_payload)
    {
        fprintf(stderr,
                "[proxy] nested %s truncate-payload mutation enabled for later nested Registration Request packets\n",
                cfg.nested_optional_ie_name);
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
        .selected_nas_mutation_applied = false,
    };

    int rc = relay_loop_with_config(&cfg, &runtime, gnb_fd, amf_fd);

    fprintf(stderr, "[proxy] shutting down\n");
    close(amf_fd);
    close(gnb_fd);
    close(listener);
    return rc;
}
