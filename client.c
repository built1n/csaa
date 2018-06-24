/* Based on:
 * <https://github.com/troydhanson/network/blob/master/unixdomain/01.basic/cli.c> */

/* Usage:
 *
 * $ ./client [-s <SOCKET>] -k KEY -u USERID COMMAND [PARAMS]
 *
 * Where COMMAND and PARAMS is one of the following:
 *   create (takes no parameters)
 *   modifyacl fileidx user_1 acc_1 ... user_n acc_n
 *   modifyfile fileidx buildcode_file compose_file image_file [FILE_KEY]
 *   retrieveinfo fileidx version
 *   retrievefile fileidx version buildcode_out compose_out image_out [FILE_KEY]
 */

#define CLIENT
#include "crypto.h"
#include "service_provider.h"
#include "trusted_module.h"
#include "test.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

static const char *socket_path = "socket";
static const char *parse_args_fail = NULL;
static const char *userkey = NULL;
static uint64_t user_id = 0;
static struct user_request cl_request;
static struct iomt *new_acl = NULL;
const char *buildcode_path = NULL, *compose_path = NULL, *image_path = NULL, *file_key = NULL;

int compare_tuple(const void *p1, const void *p2)
{
    const uint64_t *a = p1, *b = p2;
    if(*a < *b)
        return -1;
    else if(*a == *b)
        return 0;
    else
        return 1;
}

static int ilog2(int n)
{
    int l = 0;
    while(n > 1)
    {
        n >>= 1;
        ++l;
    }
    return l;
}

void print_usage(const char *name)
{
    printf("Usage: %s [-s <SOCKET>] -k KEY -u USERID COMMAND [PARAMS]\n"
           "\n"
           "Where COMMAND and PARAMS are one of the following:\n"
           " create (takes no parameters)\n"
           " modifyacl fileidx USER1 ACCESS1 ... USERn ACCESSn\n"
           " modifyfile fileidx buildcode_file compose_file image_file [FILE_KEY]\n"
           " retrieveinfo fileidx version\n"
           " retrievefile fileidx version buildcode_out compose_out image_out [FILE_KEY]\n", name);
}

bool parse_args(int argc, char *argv[])
{
    for(int i = 1; i < argc; ++i)
    {
        char *arg = argv[i];
        if(!strcmp(arg, "-s") || !strcmp(arg, "--socket"))
        {
            if(++i < argc)
                socket_path = argv[i];
            else
            {
                parse_args_fail = "Expected parameter after -s";
                return false;
            }
        }
        else if(!strcmp(arg, "-k") || !strcmp(arg, "--userkey"))
        {
            if(++i < argc)
                userkey = argv[i];
            else
            {
                parse_args_fail = "Expected user key";
                return false;
            }
        }
        else if(!strcmp(arg, "-u"))
        {
            if(++i < argc)
                user_id = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected user id";
                return false;
            }
        }
        else if(!strcmp(arg, "-h") || !strcmp(arg, "--help"))
        {
            print_usage(argv[0]);
            exit(1);
        }
        else if(!strcmp(arg, "create"))
        {
            if(cl_request.type != USERREQ_NONE)
            {
                parse_args_fail = "Multiple commands";
                return false;
            }
            cl_request.type = CREATE_FILE;
        }
        else if(!strcmp(arg, "modifyacl"))
        {
            if(cl_request.type != USERREQ_NONE)
            {
                parse_args_fail = "Multiple commands";
                return false;
            }
            cl_request.type = MODIFY_ACL;

            if(++i < argc)
                cl_request.modify_acl.file_idx = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected file idx";
                return false;
            }

            i++;

            size_t n = argc - i;
            n &= ~1; /* round down to next even integer */

            uint64_t *acl_tuples = calloc(n, sizeof(uint64_t));

            /* consume (user, access level) tuples */
            for(int j = 0; i < argc; i += 2, j += 2)
            {
                acl_tuples[j] = atol(argv[i]);
                acl_tuples[j + 1] = atol(argv[i + 1]);
            }

            /* sort ACL tuples by user id */
            qsort(acl_tuples, n / 2, 2 * sizeof(uint64_t), compare_tuple);

            size_t logleaves = ilog2(n);

            /* round up if acl size is not an integer power of 2 */
            if((1 << logleaves) != n)
                logleaves++;

            new_acl = iomt_new(logleaves);
            /* now produce IOMT */
            uint64_t first_idx = acl_tuples[0];

            for(int j = 0; j < n; j += 2)
            {
                iomt_update_leaf_full(new_acl, j / 2, acl_tuples[j], first_idx, u64_to_hash(acl_tuples[j + 1]));
                if(j > 0)
                    iomt_update_leaf_nextidx(new_acl, j / 2 - 1, acl_tuples[j]);
            }
        }
        else if(!strcmp(arg, "modifyfile"))
        {
            if(cl_request.type != USERREQ_NONE)
            {
                parse_args_fail = "Multiple commands";
                return false;
            }
            cl_request.type = MODIFY_FILE;

            if(++i < argc)
                cl_request.modify_file.file_idx = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected file idx";
                return false;
            }

            buildcode_path = argv[++i];
            compose_path = argv[++i];
            image_path = argv[++i];
            if(i + 1 < argc)
                file_key = argv[++i];
        }
        else if(!strcmp(arg, "retrieveinfo") || !strcmp(arg, "retrievefile"))
        {
            if(cl_request.type != USERREQ_NONE)
            {
                parse_args_fail = "Multiple commands";
                return false;
            }
            cl_request.type = RETRIEVE_INFO;

            if(++i < argc)
                cl_request.retrieve.file_idx = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected file idx";
                return false;
            }

            if(++i < argc)
                cl_request.retrieve.version = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected file version";
                return false;
            }

            if(!strcmp(arg, "retrievefile"))
            {
                buildcode_path = argv[++i];
                compose_path = argv[++i];
                image_path = argv[++i];
                if(i + 1 < argc)
                    file_key = argv[++i];
            }
        }
        else
        {
            parse_args_fail = "Unknown parameter";
            return false;
        }
    }
    if(cl_request.type != USERREQ_NONE && user_id != 0 && userkey != NULL)
        return true;
    else
    {
        parse_args_fail = "Missing required parameter (either command, user ID, or user key)";
        return false;
    }
}

static struct tm_request verify_and_sign(int fd, const struct user_request *req)
{
    struct tm_request tmr = req_null;
    if(recv(fd, &tmr, sizeof(tmr), MSG_WAITALL) != sizeof(tmr))
    {
        perror("short read");
        exit(1);
    }

    assert(tmr.type != REQ_NONE);

    switch(req->type)
    {
    case CREATE_FILE:
    {
        /* check request values to make sure they actually do what we
         * want */
        struct iomt_node acl_node = { req->user_id, req->user_id, u64_to_hash(3) };
        if(tmr.type != ACL_UPDATE ||
           tmr.idx == 0 ||
           tmr.counter != 0 ||
           !hash_equals(hash_node(&acl_node), tmr.val))
        {
            printf("Refusing to sign request because %d %d %d %d\n", tmr.type != ACL_UPDATE,
                   tmr.idx == 0,
                   tmr.counter != 0,
                   !hash_equals(hash_node(&acl_node), tmr.val));
            return req_null;
        }
        break;
    }
    case MODIFY_FILE:
    {
        /* TODO */
        break;
    }
    case MODIFY_ACL:
    {
        /* TODO */
        break;
    }
    default:
        break;
    }

    printf("Signing request\n");
    hash_t hmac = hmac_sha256(&tmr, sizeof(tmr), userkey, strlen(userkey));
    write(fd, &hmac, sizeof(hmac));

    return tmr;
}

static bool verify_sp_ack(int fd, const struct tm_request *tmr)
{
    hash_t hmac = hash_null;
    if(recv(fd, &hmac, sizeof(hmac), MSG_WAITALL) != sizeof(hmac))
    {
        perror("read 2");
        exit(2);
    }

    return ack_verify(tmr, userkey, strlen(userkey), hmac);
}

/* In case of modifcation or file creation, returns true on successful
 * completion of request, as acknowledged by module. In case of info
 * retrieval, returns true if version info is verified by module. The
 * verinfo_out, user_key, and keylen parameters must not be NULL in
 * this case (in all other cases they are ignored). */
bool exec_request(int fd, const struct user_request *req,
                  const struct iomt *new_acl,                /* MODIFY_ACL only */
                  const struct iomt *new_buildcode,          /* MODIFY_FILE only */
                  const struct iomt *new_composefile,        /* MODIFY_FILE only */
                  const void *new_file_contents, size_t len, /* MODIFY_FILE only */
                  struct tm_request *tmreq_out,              /* CREATE_FILE, MODIFY_FILE, and MODIFY_ACL only */
                  struct version_info *verinfo_out,          /* RETRIEVE_INFO only */
                  const void *user_key, size_t keylen,       /* RETRIEVE_INFO and RETRIEVE_FILE only */
                  struct iomt **buildcode,                   /* RETRIEVE_FILE only */
                  struct iomt **composefile,                 /* RETRIEVE_FILE only */
                  hash_t *secret_out,                        /* RETRIEVE_FILE only */
                  void **file_contents_out,                  /* RETRIEVE_FILE only */
                  size_t *file_len)                          /* RETRIEVE_FILE only */
{
    write(fd, req, sizeof(*req));
    /* write additional data */
    switch(req->type)
    {
    case MODIFY_ACL:
        /* send ACL */
        iomt_serialize(new_acl, write_to_fd, &fd);
        break;
    case MODIFY_FILE:
        /* send build code, compose file, and file contents */
        iomt_serialize(new_buildcode, write_to_fd, &fd);
        iomt_serialize(new_composefile, write_to_fd, &fd);

        /* prefix file with size */
        write(fd, &len, sizeof(len));
        write(fd, new_file_contents, len);
        break;
    case CREATE_FILE:
    case RETRIEVE_INFO:
    case RETRIEVE_FILE:
        /* no additional data needed, fall through */
    default:
        break;
    }

    switch(req->type)
    {
    case CREATE_FILE:
    case MODIFY_ACL:
    case MODIFY_FILE:
    {
        /* verify module ack */
        struct tm_request tmr = verify_and_sign(fd, req);
        if(tmreq_out)
            *tmreq_out = tmr;
        return verify_sp_ack(fd, &tmr);
    }
    case RETRIEVE_INFO:
    {
        hash_t hmac;
        struct version_info verinfo;
        recv(fd, &verinfo, sizeof(verinfo), MSG_WAITALL);
        recv(fd, &hmac, sizeof(hmac), MSG_WAITALL);

        if(hash_equals(hmac, hmac_sha256(&verinfo, sizeof(verinfo), user_key, keylen)))
        {
            *verinfo_out = verinfo;
            return true;
        }
        return false;
    }
    case RETRIEVE_FILE:
    {
        hash_t encrypted_secret;
        recv(fd, &encrypted_secret, sizeof(encrypted_secret), MSG_WAITALL);

        *secret_out = crypt_secret(encrypted_secret,
                                   req->retrieve.file_idx,
                                   req->retrieve.version,
                                   user_key, keylen);

        *buildcode = iomt_deserialize(read_from_fd, &fd);
        *composefile = iomt_deserialize(read_from_fd, &fd);

        recv(fd, file_len, sizeof(*file_len), MSG_WAITALL);

        *file_contents_out = malloc(*file_len);
        recv(fd, file_contents_out, *file_len, MSG_WAITALL);
        return true;
    }
    default:
        assert(false);
    }
}

int connect_to_service(const char *sockpath)
{
    struct sockaddr_un addr;
    int fd;

    if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (*sockpath == '\0') {
        *addr.sun_path = '\0';
        strncpy(addr.sun_path+1, sockpath+1, sizeof(addr.sun_path)-2);
    } else {
        strncpy(addr.sun_path, sockpath, sizeof(addr.sun_path)-1);
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
    }

    return fd;
}

void *load_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "r");
    *len = fseek(f, 0, SEEK_END);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(*len);
    fread(buf, 1, *len, f);
    return buf;
}

bool server_request(const char *sockpath,
                    const char *userkey, uint64_t user_id,
                    struct user_request req,
                    struct iomt *new_acl,
                    const char *buildcode_path,
                    const char *compose_path,
                    const char *image_path,
                    const char *file_key)
{
    int fd = connect_to_service(sockpath);

    req.user_id = user_id;

    struct iomt *buildcode = NULL, *composefile = NULL;
    if(req.type == MODIFY_FILE)
    {
        /* these can safely take NULLs */
        buildcode = iomt_from_lines(buildcode_path);
        composefile = iomt_from_lines(compose_path);
    }

    void *file_contents = NULL;
    size_t file_len = 0;
    hash_t secret = hash_null;
    if(image_path && req.type == MODIFY_FILE)
        file_contents = load_file(image_path, &file_len);

    /* TODO: encrypt file */

    struct version_info verinfo;
    struct tm_request tmreq;

    bool success = exec_request(fd, &req,
                                req.type == MODIFY_ACL ? new_acl : NULL,
                                req.type == MODIFY_FILE ? buildcode : NULL,
                                req.type == MODIFY_FILE ? composefile : NULL,
                                req.type == MODIFY_FILE ? file_contents : NULL,
                                req.type == MODIFY_FILE ? file_len : 0,
                                req.type <= MODIFY_ACL ? &tmreq : NULL,
                                req.type == RETRIEVE_INFO ? &verinfo : NULL,
                                req.type >= RETRIEVE_INFO ? userkey : NULL,
                                req.type >= RETRIEVE_INFO ? strlen(userkey) : 0,
                                req.type == RETRIEVE_FILE ? &buildcode : NULL,
                                req.type == RETRIEVE_FILE ? &composefile : NULL,
                                req.type == RETRIEVE_FILE ? &secret : NULL,
                                req.type == RETRIEVE_FILE ? &file_contents : NULL,
                                req.type == RETRIEVE_FILE ? &file_len : NULL);

    printf("Request %s\n",
           success ?
           "\033[32;1msucceeded\033[0m" :
           "\033[31;1mfailed\033[0m");

    if(!success)
        return false;

    switch(req.type)
    {
    case CREATE_FILE:
        printf("Created file with index %lu.\n", tmreq.idx);
        break;
    default:
        break;
    }

    return true;
}

int main(int argc, char *argv[]) {
    char buf[100];
    int fd,rc;

    if(!parse_args(argc, argv))
    {
        printf("%s\n", parse_args_fail);
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    server_request(socket_path, userkey, user_id,
                   cl_request, new_acl,
                   buildcode_path, compose_path, image_path,
                   file_key);

#if 0
    fd = connect_to_service(socket_path);

    struct user_request req;
    req.type = CREATE_FILE;
    req.user_id = 1;

    check("Client file creation", exec_request(fd, &req, NULL, NULL, NULL, NULL, 0,
                                               NULL, NULL, 0,
                                               NULL, NULL, NULL, NULL, NULL));
    close(fd);
    fd = connect_to_service(socket_path);

    req.type = MODIFY_FILE;
    req.user_id = 1;
    req.modify_file.file_idx = 1;
    req.modify_file.encrypted_secret = hash_null;
    req.modify_file.kf = hash_null;

    check("Client file modification", exec_request(fd, &req, NULL, NULL, NULL, "contents", 8,
                                                   NULL, NULL, 0,
                                                   NULL, NULL, NULL, NULL, NULL));
    close(fd);
#endif

    return 0;
}
