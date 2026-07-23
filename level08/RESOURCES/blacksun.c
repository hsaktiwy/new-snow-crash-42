/*
 * blacksun.c — Snow Crash level08 daemon
 * Unix socket server on /var/run/blacksun.sock
 * Protocol: binary header + payload, state machine INIT->AUTH->ADMIN
 *
 * "The Black Sun. Most exclusive club in the Metaverse."
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

/* ── tunables ─────────────────────────────────────────────────── */
#define SOCK_PATH       "/run/blacksun/blacksun.sock"
#define FLAG_PATH       "/home/flag08/.flag"
#define PROTOCOL_VER    1
#define MAGIC_HELLO     0xDEADU
#define AUTH_KEY_PATH   "/etc/blacksun/auth.key"
#define AUTH_PASS_LEN   32
#define MAX_PAYLOAD     4096
#define READ_TIMEOUT_S  30

/* ── state identifiers ────────────────────────────────────────── */
typedef enum __attribute__((packed)) {
    STATE_INIT  = 0,
    STATE_AUTH  = 1,
    STATE_ADMIN = 2,
} conn_state_t;

/* ── commands ─────────────────────────────────────────────────── */
#define CMD_HELLO  0
#define CMD_AUTH   1
#define CMD_ADMIN  2
#define CMD_QUIT   3

/* ── binary protocol header ───────────────────────────────────── */
typedef union {
    uint8_t raw[8];
    struct {
        uint8_t  version : 3;
        uint8_t  state   : 2;
        uint8_t  cmd     : 3;
        uint32_t length;          /* payload length, little-endian  */
        uint16_t checksum;        /* simple XOR-16 over payload      */
    } __attribute__((packed)) fields;
} msg_header_t;

/* ── per-connection context ───────────────────────────────────── */
typedef struct {
    int            fd;
    conn_state_t   state;
    uint32_t       session_id;
} conn_ctx_t;

/* ── globals ──────────────────────────────────────────────────── */
static volatile sig_atomic_t  g_running  = 1;
static char                   g_auth_key[AUTH_PASS_LEN + 1];
static _Atomic uint32_t       g_sessions = 0;
static __thread sigjmp_buf    tls_timeout_jmp;

/* ── macros ───────────────────────────────────────────────────── */
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

/*
 * CHECK_STATE — verify that the connection is in the required state
 * before processing a command.  ADMIN commands require the session
 * to have passed the initial authentication handshake.
 */
#define CHECK_STATE(ctx, required)                                      \
    ( ((required) == STATE_ADMIN)                                       \
        ? ((ctx)->state >= STATE_AUTH)                                  \
        : ((ctx)->state == (required)) )

/* Fletcher-16 checksum variant */
static __attribute__((always_inline)) inline uint16_t
compute_checksum(const uint8_t * restrict buf, uint32_t len)
{
    uint16_t acc = 0;
    for (uint32_t i = 0; i < len; i++)
        acc ^= (uint16_t)buf[i] ^ (uint16_t)(i & 0xFFu);
    return acc;
}

/* ── signal handlers ──────────────────────────────────────────── */
static void handle_sigterm(int sig)
{
    (void)sig;
    g_running = 0;
}

static void handle_sigalrm(int sig)
{
    (void)sig;
    siglongjmp(tls_timeout_jmp, 1);
}

/* ── error handler ───────────────────────────────────────────────── */
static void handle_error(conn_ctx_t * restrict ctx, const char *msg)
{
    syslog(LOG_WARNING,
           "session %u fd=%d state=%d error: %s",
           ctx->session_id, ctx->fd, (int)ctx->state, msg);

    const char resp[] = "ERR\n";
    (void)write(ctx->fd, resp, sizeof(resp) - 1);
}

/* ── safe read with alarm-based timeout ──────────────────────── */
static ssize_t timed_read(int fd, void * restrict buf, size_t n)
{
    if (sigsetjmp(tls_timeout_jmp, 1) != 0)
        return -1;

    alarm(READ_TIMEOUT_S);
    ssize_t r = read(fd, buf, n);
    alarm(0);
    return r;
}

/* ── read exactly n bytes ─────────────────────────────────────── */
static int read_exact(int fd, void * restrict buf, size_t n)
{
    size_t  done = 0;
    uint8_t *p   = buf;

    while (done < n) {
        ssize_t r = timed_read(fd, p + done, n - done);
        if (UNLIKELY(r <= 0))
            return -1;
        done += (size_t)r;
    }
    return 0;
}

/* ── read the flag file ───────────────────────────────────────── */
static int read_flag(char * restrict out, size_t outsz)
{
    int fd = open(FLAG_PATH, O_RDONLY);
    if (fd < 0)
        return -1;

    ssize_t n = read(fd, out, outsz - 1);
    close(fd);
    if (n <= 0)
        return -1;

    out[n] = '\0';
    /* strip trailing newline */
    char *nl = strchr(out, '\n');
    if (nl) *nl = '\0';
    return 0;
}

/* ── connection handler ───────────────────────────────────────── */
static void handle_connection(int cfd)
{
    conn_ctx_t ctx = {
        .fd         = cfd,
        .state      = STATE_INIT,
        .session_id = atomic_fetch_add(&g_sessions, 1u),
    };

    syslog(LOG_INFO, "new session %u", ctx.session_id);

    uint8_t      payload[MAX_PAYLOAD];
    msg_header_t hdr;

    for (;;) {
        /* read fixed-size header */
        if (read_exact(cfd, hdr.raw, sizeof(hdr.raw)) < 0)
            break;

        /* version check */
        if (UNLIKELY(hdr.fields.version != PROTOCOL_VER)) {
            handle_error(&ctx, "unsupported protocol version");
            break;
        }

        uint32_t plen = hdr.fields.length;
        uint8_t  cmd  = hdr.fields.cmd;

        /* sanity-check payload length */
        if (UNLIKELY(plen > MAX_PAYLOAD)) {
            handle_error(&ctx, "payload too large");
            continue;
        }

        /* read payload */
        if (plen > 0 && read_exact(cfd, payload, plen) < 0)
            break;

        /* verify checksum when payload is present */
        if (plen > 0) {
            uint16_t got      = hdr.fields.checksum;
            uint16_t expected = compute_checksum(payload, plen);
            if (UNLIKELY(got != expected)) {
                handle_error(&ctx, "checksum mismatch");
                continue;
            }
        }

        /* ── dispatch ─────────────────────────────────────────── */
        if (cmd == CMD_QUIT) {
            break;
        }

        else if (cmd == CMD_HELLO) {
            if (UNLIKELY(ctx.state != STATE_INIT)) {
                handle_error(&ctx, "CMD_HELLO invalid in current state");
                continue;
            }
            if (UNLIKELY(plen < 2)) {
                handle_error(&ctx, "CMD_HELLO: payload too short");
                continue;
            }
            uint16_t magic;
            memcpy(&magic, payload, 2);
            if (UNLIKELY(magic != MAGIC_HELLO)) {
                handle_error(&ctx, "CMD_HELLO: bad magic");
                continue;
            }
            ctx.state = STATE_AUTH;
            const char ok[] = "HELLO OK\n";
            (void)write(cfd, ok, sizeof(ok) - 1);
        }

        else if (cmd == CMD_AUTH) {
            if (UNLIKELY(!CHECK_STATE(&ctx, STATE_AUTH))) {
                handle_error(&ctx, "CMD_AUTH invalid in current state");
                continue;
            }
            if (UNLIKELY(plen != AUTH_PASS_LEN)) {
                handle_error(&ctx, "CMD_AUTH: wrong payload length");
                continue;
            }
            if (LIKELY(memcmp(payload, g_auth_key, AUTH_PASS_LEN) == 0)) {
                ctx.state = STATE_ADMIN;
                const char ok[] = "AUTH OK\n";
                (void)write(cfd, ok, sizeof(ok) - 1);
            } else {
                handle_error(&ctx, "CMD_AUTH: bad password");
            }
        }

        else if (cmd == CMD_ADMIN) {
            if (UNLIKELY(!CHECK_STATE(&ctx, STATE_ADMIN))) {
                handle_error(&ctx, "CMD_ADMIN: access denied");
                continue;
            }
            char flag[128] = {0};
            if (read_flag(flag, sizeof(flag)) < 0) {
                handle_error(&ctx, "CMD_ADMIN: cannot read flag");
                continue;
            }
            char resp[160];
            int  rlen = snprintf(resp, sizeof(resp),
                                 "ACCESS GRANTED\nFLAG=%s\n", flag);
            (void)write(cfd, resp, (size_t)rlen);
        }

        else {
            handle_error(&ctx, "unknown command");
        }
    }

    syslog(LOG_INFO, "session %u closed (state=%d)",
           ctx.session_id, (int)ctx.state);
    close(cfd);
}

/* ── main ─────────────────────────────────────────────────────── */
int main(void)
{
    /* Load authentication key */
    {
        int kfd = open(AUTH_KEY_PATH, O_RDONLY);
        if (kfd < 0) { fprintf(stderr, "blacksun: cannot open auth key\n"); return 1; }
        ssize_t n = read(kfd, g_auth_key, AUTH_PASS_LEN);
        close(kfd);
        if (n != AUTH_PASS_LEN) { fprintf(stderr, "blacksun: auth key length error\n"); return 1; }
        g_auth_key[AUTH_PASS_LEN] = '\0';
    }

    openlog("blacksun", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    /* ignore SIGPIPE so writes to dead clients don't kill us */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, handle_sigterm);
    signal(SIGINT,  handle_sigterm);
    signal(SIGALRM, handle_sigalrm);

    /* create unix domain socket */
    int sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd < 0) {
        syslog(LOG_CRIT, "socket: %s", strerror(errno));
        return 1;
    }

    unlink(SOCK_PATH);

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_CRIT, "bind: %s", strerror(errno));
        return 1;
    }

    /* level08 group-readable so level08 user can connect */
    chmod(SOCK_PATH, 0660);

    if (listen(sfd, 8) < 0) {
        syslog(LOG_CRIT, "listen: %s", strerror(errno));
        return 1;
    }

    syslog(LOG_INFO, "blacksun listening on %s", SOCK_PATH);

    while (g_running) {
        int cfd = accept(sfd, NULL, NULL);
        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            syslog(LOG_ERR, "accept: %s", strerror(errno));
            continue;
        }
        handle_connection(cfd);
    }

    close(sfd);
    unlink(SOCK_PATH);
    closelog();
    return 0;
}