#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

#include <rho/rho.h>

/*
 * Useful guides for signing with OpenSSL:
 *  - https://www.openssl.org/docs/manmaster/man3/EVP_PKEY_sign.html
 *  - https://wiki.openssl.org/index.php/EVP_Signing_and_Verifying
 */

/**************************************
 * DEFINES
 **************************************/
#define TNT_REQUEST_SIZE    8
#define TNT_HEADER_SIZE    8

/**************************************
 * TYPES
 **************************************/
struct tnt_server {
    struct rho_sock *srv_sock;
    EVP_PKEY *srv_pkey;
    EVP_MD_CTX *srv_md_ctx;
};

/**************************************
 * FORWARD DECLARATIONS
 **************************************/
static void tnt_openssl_init(void);
static void tnt_openssl_fini(void);

static void tnt_openssl_clear_ssl_queue(void);
static void tnt_openssl_warn(const char *fmt, ...);
static void tnt_openssl_die(const char *fmt, ...);

static struct tnt_server * tnt_server_alloc(void);
static void tnt_server_load_key(struct tnt_server *server, const char *keyfile);
static void tnt_server_init_sig(struct tnt_server *server);
static void tnt_server_init(struct tnt_server *server, const char *keyfile);

static int tnt_server_sign(struct tnt_server *server, uint8_t *data,
        size_t datalen, uint8_t *sig, size_t *sigsize);
static void tnt_server_runloop(struct tnt_server *server);

static struct tnt_server * tnt_server_create(const char *keyfile);
static void tnt_server_destroy(struct tnt_server *server);
static void tnt_server_serve(struct tnt_server *server, const char *address, 
        const char *portstr);

static void tnt_log_init(const char *logfile, bool verbose);

/**************************************
 * GLOBALS
 **************************************/
struct rho_log *tnt_log = NULL;

/**************************************
 * OPENSSL HELPERS
 **************************************/
/*
 * INIT/FINI
 */

/* 
 * see https://wiki.openssl.org/index.php/Library_Initialization
 */
static void
tnt_openssl_init(void)
{
    SSL_library_init(); /* same as OpenSSL_add_all_algorithms */
    SSL_load_error_strings();
}

/* 
 * see https://wiki.openssl.org/index.php/Library_Initialization#cleanup
 */
static void
tnt_openssl_fini(void)
{
    FIPS_mode_set(0);
    ENGINE_cleanup();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
}

/*
 * ERROR CHECKING/REPORTING
 */

/* print the contents of the SSL error queue */
static void
tnt_openssl_clear_ssl_queue(void)
{
    unsigned long sslcode = ERR_get_error();

    do {
        static const char sslfmt[] = "SSL Error: %s:%s:%s\n";
        fprintf(stderr, sslfmt,
                ERR_lib_error_string(sslcode),
                ERR_func_error_string(sslcode),
                ERR_reason_error_string(sslcode));
    } while ((sslcode = ERR_get_error()) != 0);
}

static void
tnt_openssl_warn(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    tnt_openssl_clear_ssl_queue();
}

static void
tnt_openssl_die(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fputs("\n", stderr);
    va_end(ap);

    tnt_openssl_clear_ssl_queue();
    exit(EXIT_FAILURE);
}

/**************************************
 * SERVER
 **************************************/
/*
 * Initialization
 */
static struct tnt_server *
tnt_server_alloc(void)
{
    struct tnt_server *server = NULL;
    server = rhoL_zalloc(sizeof(*server));
    return (server);
}

static void
tnt_server_load_key(struct tnt_server *server, const char *keyfile)
{
    FILE *fp = NULL;
    EVP_PKEY *pkey = NULL;

    RHO_TRACE_ENTER("keyfile=\"%s\"", keyfile);

    fp = fopen(keyfile, "rb");
    if (fp == NULL)
        rho_errno_die(errno, "can't open private key file: \"%s\"", keyfile);;

    if (PEM_read_PrivateKey(fp, &pkey, NULL, NULL) == NULL)
        tnt_openssl_die("PEM_read_PrivateKey(\"%s\")", keyfile);

    (void)fclose(fp);

    server->srv_pkey = pkey;

    RHO_TRACE_EXIT();
    return;
}

static void
tnt_server_init_sig(struct tnt_server *server)
{
    EVP_MD_CTX *md_ctx = NULL;
    const EVP_MD *md = EVP_sha256();
    //EVP_PKEY *pkey = server->srv_pkey;
    //EVP_PKEY_CTX *pkey_ctx = NULL;

    RHO_TRACE_ENTER();

    md_ctx = EVP_MD_CTX_create();
    if (md_ctx == NULL)
        tnt_openssl_die("EVP_MD_CTX_create");

    if (EVP_DigestInit_ex(md_ctx, md, NULL) != 1)
        tnt_openssl_die("EVP_DigestInit_ex");

    /*
     * The pkey_ctx step is not necessarily; RSA's default padding for
     * signatures is PKCS1v15.  Nevertheless, I want the code to be explicit
     * about what padding it is using, as this is not clear from the
     * OpenSSL manpages.
     */
#if 0 
    pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (pkey_ct == NULL)
        tnt_openssl_die("EVP_PKEY_CTX_new");

    if (EVP_PKEY_sign_init(pkey_ctx) != 1)
        tnt_openssl_die("EVP_PKEY_sign_init");

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        tnt_openssl_die("EVP_KEY_CTX_set_rsa_padding(RSA_PKCS1_PADDING)");

    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, pkey) != 1)
        tnt_openssl_die("EVP_SignInit");

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
        tnt_openssl_die("EVP_KEY_CTX_set_rsa_padding(RSA_PKCS1_PADDING)");
#endif

    server->srv_md_ctx = md_ctx;

    RHO_TRACE_EXIT();
    return;

}

static void
tnt_server_init(struct tnt_server *server, const char *keyfile)
{
    RHO_TRACE_ENTER();

    tnt_server_load_key(server, keyfile);
    tnt_server_init_sig(server);

    RHO_TRACE_EXIT();
    return;
}

/*
 * RUNLOOP / CORE FUNCTIONALITY
 */

static int
tnt_server_sign(struct tnt_server *server, uint8_t *data, size_t datalen,
        uint8_t *sig, size_t *sigsize)
{
    int error = 0;
    EVP_MD_CTX *md_ctx = server->srv_md_ctx;
    EVP_PKEY *pkey = server->srv_pkey;
    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pkey_ctx = NULL;

    if (EVP_DigestSignInit(md_ctx, &pkey_ctx, md, NULL, pkey) != 1)
        tnt_openssl_die("EVP_SignInit");

    /* 
     * RSA_PCKS1_PADDING is the default, so this step isn't necessary.
     * However, the manpages don't mention this, so I want to be explicit
     */
    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PADDING) <= 0)
        tnt_openssl_die("EVP_KEY_CTX_set_rsa_padding(RSA_PKCS1_PADDING)");

    if (EVP_DigestSignUpdate(md_ctx, data, datalen) != 1) {
        tnt_openssl_warn("EVP_SignUpdate");
        goto fail;
    }
    
    if (EVP_DigestSignFinal(md_ctx, sig, sigsize) != 1) {
        tnt_openssl_warn("EVP_SignFinal");
        goto fail;
    }

    goto succeed;

fail:
    error = -1;
succeed:
    return (error);
} 


static void
tnt_server_runloop(struct tnt_server *server)
{
    int error = 0;
    struct rho_sock *sock = server->srv_sock;
    struct rho_buf *buf = rho_buf_create();
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);
    char addrstr[INET_ADDRSTRLEN] = { 0 };
    uint64_t nonce = 0;
    struct timeval tv = { 0 };
    int sig_maxsize = 0;
    uint8_t *sig = NULL;
    size_t sigsize = 0;

    sig_maxsize = EVP_PKEY_size(server->srv_pkey);
    sig = rhoL_zalloc(sig_maxsize);

    /* 
     * For memory leak testing, make the while a for
     * for (int i = 0; i < 4; i++) {
     */
    while (1) { 
        rho_buf_clear(buf);
        rho_sock_recvfrom_buf(sock, buf, TNT_REQUEST_SIZE,
                (struct sockaddr *)&addr, &alen);

        rhoL_inet_ntop(AF_INET, &(addr.sin_addr), addrstr, sizeof(addrstr));
        rho_log_debug(tnt_log, "request from %s:%d", addrstr, addr.sin_port);
        /* read request 
         * TODO: add a header for the request
         */
        rho_buf_rewind(buf);
        rho_buf_readu64be(buf, &nonce);
        rho_buf_clear(buf);
        rho_log_debug(tnt_log, "request nonce:%"PRIx64, nonce);

        /* compose response */
        rhoL_gettimeofday(&tv, NULL);
        rho_buf_seek(buf, TNT_HEADER_SIZE, SEEK_SET);
        rho_buf_writeu64be(buf, nonce);
        rho_buf_writeu64be(buf, tv.tv_sec);
        rho_buf_writeu32be(buf, tv.tv_usec);

#if 0
        rho_hexdump(rho_buf_raw(buf, TNT_HEADER_SIZE, SEEK_SET),
           rho_buf_length(buf) - TNT_HEADER_SIZE, "nonce-sec-usec");     
#endif

        /* sign response */
        sigsize = sig_maxsize;
        error = tnt_server_sign(server,
                rho_buf_raw(buf, TNT_HEADER_SIZE, SEEK_SET), 
                rho_buf_length(buf) - TNT_HEADER_SIZE,
                sig, &sigsize);

        if (error == 0) {
            /* success */
            rho_buf_write_u32size_blob(buf, sig, sigsize);
            rho_buf_rewind(buf);
            rho_buf_writeu32be(buf, 0);
            rho_buf_writeu32be(buf, rho_buf_length(buf) - TNT_HEADER_SIZE);
        } else {
            /* failure */
            rho_buf_clear(buf);
            rho_buf_writeu32be(buf, 1);
            rho_buf_writeu32be(buf, 0);
        }

        rho_buf_rewind(buf);
        rho_log_debug(tnt_log, "sending request (%zu bytes)",
                rho_buf_length(buf));
        rho_sock_sendto_buf(sock, buf, rho_buf_length(buf), 
            (struct sockaddr *)&addr, alen);
    }

    /* NOT REACHED */
    rhoL_free(sig);
    rho_buf_destroy(buf);
}

/*
 * "PUBLIC" API
 */

static struct tnt_server *
tnt_server_create(const char *keyfile)
{
    struct tnt_server *server = NULL;

    RHO_TRACE_ENTER("keyfile=\"%s\"", keyfile);

    server = tnt_server_alloc();
    tnt_server_init(server, keyfile);

    RHO_TRACE_EXIT(); 
    return (server); 
}

static void
tnt_server_destroy(struct tnt_server *server)
{
    if (server->srv_pkey != NULL)
        EVP_PKEY_free(server->srv_pkey);

    if (server->srv_md_ctx != NULL)
        EVP_MD_CTX_destroy(server->srv_md_ctx);

    if (server->srv_sock != NULL)
        rho_sock_destroy(server->srv_sock);

    rhoL_free(server);
}

static void
tnt_server_serve(struct tnt_server *server, const char *address, 
        const char *portstr)
{
    struct rho_sock *sock = NULL;
    short port = 0;

    RHO_TRACE_ENTER("address=\"%s\", port=\"%s\"", address, portstr);

    port = rho_str_toshort(portstr, 10);
    sock = rho_sock_udp4server_create(address, port);
    server->srv_sock = sock;

    tnt_server_runloop(server);

    RHO_TRACE_EXIT();
    return;
}

/**************************************
 * LOG
 **************************************/
static void
tnt_log_init(const char *logfile, bool verbose)
{
    int fd = STDERR_FILENO;

    if (logfile != NULL) {
        fd = open(logfile, O_WRONLY|O_APPEND|O_CREAT,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH,S_IWOTH);
        if (fd == -1)
            rho_errno_die(errno, "can't open or creat logfile \"%s\"", logfile);
    }

    tnt_log = rho_log_create(fd, RHO_LOG_INFO, rho_log_default_writer, NULL);

    if (verbose) 
        rho_log_set_level(tnt_log, RHO_LOG_DEBUG);

    if (logfile != NULL) {
        rho_log_redirect_stderr(tnt_log);
        (void)close(fd);
    }
}

#define TNTSERVER_USAGE \
    "usage: tntserver [options] PORT\n" \
    "\n" \
    "OPTIONS:\n" \
    "   -d\n" \
    "       Daemonize\n" \
    "\n" \
    "   -h\n" \
    "       Show this help message and exit\n" \
    "\n" \
    "   -i ADDRESS\n" \
    "       The address to bind to.  If not specified, binds to\n" \
    "       all interfaces (i.e., INADDR_ANY)\n" \
    "\n" \
    "   -k PRIVKEY\n" \
    "       Private key\n" \
    "\n" \
    "   -l LOG_FILE\n" \
    "       Log file to use.  If not specified, logs are printed to stderr.\n" \
    "       If specified, stderr is also redirected to the log file.\n" \
    "\n" \
    "   -v\n" \
    "       Verbose logging.\n" \
    "\n" \
    "ARGUMENTS:\n" \
    "   PORT\n" \
    "       The port number to listen on\n" \

static void
usage(int exitcode)
{
    fprintf(stderr, "%s\n", TNTSERVER_USAGE);
    exit(exitcode);
}

int
main(int argc, char *argv[])
{
    int c = 0;
    struct tnt_server *server = NULL;
    /* options */
    bool daemonize  = false;
    const char *ipstr = NULL;
    const char *keyfile = NULL;
    const char *logfile = NULL;
    bool verbose = false;
    /* args */
    const char *portstr = NULL;

    tnt_openssl_init();

    while ((c = getopt(argc, argv, "dhi:k:l:v")) != -1) {
        switch (c) {
        case 'd':
            daemonize = true;
            break;
        case 'h':
            usage(EXIT_SUCCESS);
            break;
        case 'i':
            ipstr = optarg;
        case 'k':
            keyfile = optarg;
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        default:
            usage(1);
        }
    }
    argc -= optind;
    argv += optind;

    if (argc != 1)
        usage(EXIT_FAILURE);
    portstr = argv[0];

    if (daemonize)
        rho_daemon_daemonize(NULL, 0);

    tnt_log_init(logfile, verbose);

    server = tnt_server_create(keyfile);
    /* infinite loop */
    tnt_server_serve(server, ipstr, portstr);

    /* shouldn't reach here */
    tnt_server_destroy(server);
    rho_log_destroy(tnt_log);
    tnt_openssl_fini();
    return (0);
}
