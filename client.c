/* Based on:
 * <https://github.com/troydhanson/network/blob/master/unixdomain/01.basic/cli.c> */

/* Usage:
 *
 * $ ./client [-s <SOCKET>] -u USERID -k USER_KEY COMMAND [PARAMS]
 *
 * Where COMMAND and PARAMS are one of the following:
 *   create (takes no parameters)
 *
 *   modifyacl -f FILEIDX USER_1 ACCESS_1 ... USER_n ACCESS_n
 *   - NOTE: there must be nothing following this command, as everything
 *           will be interpreted as part of the ACL list.
 *
 *   modifyfile -f FILEIDX -i IMAGE_FILE [-ib buildcode_file]
 *              [-ic compose_file] [--encrypt, -e]
 *
 *   retrieveinfo -f FILEIDX [-v VERSION]
 *
 *   retrievefile -f FILEIDX [-v VERSION] -o IMAGE_OUT
 */

#define CLIENT
#include "crypto.h"
#include "iomt.h"
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
    printf("Usage:\n"
           "\n"
           "$ ./client [-s <SOCKET>] -u USERID -k USER_KEY COMMAND [PARAMS]\n"
           "\n"
           "Where COMMAND and PARAMS are one of the following:\n"
           "  create (takes no parameters)\n"
           "\n"
           "  modifyacl -f FILEIDX USER_1 ACCESS_1 ... USER_n ACCESS_n\n"
           "  - NOTE: there must be nothing following this command, as everything\n"
           "          will be interpreted as part of the ACL list.\n"
           "\n"
           "  modifyfile -f FILEIDX -i IMAGE_FILE [-ib buildcode_file]\n"
           "             [-ic compose_file] [--encrypt, -e]\n"
           "\n"
           "  retrieveinfo -f FILEIDX [-v VERSION]\n"
           "\n"
           "  retrievefile -f FILEIDX [-v VERSION] -o IMAGE_OUT\n");
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
        else if(!strcmp(arg, "-f"))
        {
            if(++i < argc)
                cl_request.file_idx = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected file index";
                return false;
            }
        }
        else if(!strcmp(arg, "-v"))
        {
            if(++i < argc)
                cl_request.retrieve.version = atol(argv[i]);
            else
            {
                parse_args_fail = "Expected version number";
                return false;
            }
        }
        /* -i and -o are handled identically */
        else if(!strcmp(arg, "-i") || !strcmp(arg, "-o"))
        {
            if(++i < argc)
                image_path = argv[i];
            else
            {
                parse_args_fail = "Expected image path";
                return false;
            }
        }
        else if(!strcmp(arg, "-ib"))
        {
            if(++i < argc)
                buildcode_path = argv[i];
            else
            {
                parse_args_fail = "Expected build code";
                return false;
            }
        }
        else if(!strcmp(arg, "-ic"))
        {
            if(++i < argc)
                compose_path = argv[i];
            else
            {
                parse_args_fail = "Expected compose file";
                return false;
            }
        }
        else if(!strcmp(arg, "-e") || !strcmp(arg, "--encrypt"))
        {
            /* a random nonce will be generated along with this to
             * form the key */
            file_key = "a";
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

            size_t logleaves = ilog2(n / 2);

            /* round up if acl size is not an integer power of 2 */
            if((1 << logleaves) != n / 2)
                logleaves++;

            printf("ACL logleaves = %d, count = %d, mt_leafcount = %d\n", logleaves, n, 1 << logleaves);
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
        }
        else if(!strcmp(arg, "retrieveinfo") || !strcmp(arg, "retrievefile"))
        {
            if(cl_request.type != USERREQ_NONE)
            {
                parse_args_fail = "Multiple commands";
                return false;
            }
            cl_request.type = RETRIEVE_INFO;

            if(!strcmp(arg, "retrievefile"))
            {
                cl_request.type = RETRIEVE_FILE;
            }
        }
        else
        {
            parse_args_fail = "Unknown parameter";
            return false;
        }
    }
    if(cl_request.type != USERREQ_NONE && user_id != 0 && userkey != NULL)
    {
        if(cl_request.type > CREATE_FILE)
        {
            if(!cl_request.file_idx)
            {
                parse_args_fail = "No file index specified";
                return false;
            }
        }
        else
        {
            if(cl_request.file_idx)
            {
                parse_args_fail = "Index specified for create";
                return false;
            }
        }

        if(cl_request.type == MODIFY_FILE ||
           cl_request.type == RETRIEVE_FILE)
        {
            if(!image_path)
            {
                parse_args_fail = "No image file specified";
                return false;
            }
        }

        return true;
    }
    else
    {
        parse_args_fail = "Missing required parameter (either command, user ID, or user key)";
        return false;
    }
}

/* val is lambda for FILE_UPDATE, ignored for create, and the ACL root for ACL_MODIFY */
static struct tm_request verify_and_sign(int fd, const struct user_request *req, hash_t val)
{
    struct tm_request tmr = req_null;
    if(recv(fd, &tmr, sizeof(tmr), MSG_WAITALL) != sizeof(tmr))
        return req_null;

    assert(tmr.type != REQ_NONE);

    switch(req->type)
    {
    case CREATE_FILE:
    {
        /* check request values to make sure they actually do what we
         * want */
        struct iomt_node acl_node = { req->user_id, req->user_id, u64_to_hash(3) };
        if(tmr.type != ACL_UPDATE ||
           tmr.idx == 0           ||
           tmr.counter != 0       ||
           !hash_equals(hash_node(acl_node), tmr.val))
        {
            printf("Refusing to sign request because %d %d %d %d\n", tmr.type != ACL_UPDATE,
                   tmr.idx == 0,
                   tmr.counter != 0,
                   !hash_equals(hash_node(acl_node), tmr.val));
            return req_null;
        }
        break;
    }
    case MODIFY_FILE:
    {
        if(tmr.type != FILE_UPDATE     ||
           tmr.user_id != req->user_id ||
           tmr.idx != req->file_idx    ||
           !hash_equals(tmr.val, val))
            return req_null;
        break;
    }
    case MODIFY_ACL:
    {
        if(tmr.type != ACL_UPDATE      ||
           tmr.user_id != req->user_id ||
           tmr.idx != req->file_idx    ||
           !hash_equals(tmr.val, val))
            return req_null;
        break;
    }
    default:
        return req_null;
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
        return false;

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
        hash_t val = hash_null;
        if(req->type == MODIFY_FILE)
        {
            hash_t gamma = sha256(new_file_contents, len);
            val = calc_lambda(gamma,
                              new_buildcode,
                              new_composefile,
                              req->modify_file.kf);
        }
        else if(req->type == MODIFY_ACL)
            val = iomt_getroot(new_acl);

        struct tm_request tmr = verify_and_sign(fd, req, val);
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
            if(verinfo.idx != 0)
            {
                struct iomt *acl = iomt_deserialize(read_from_fd, &fd);
                printf("ACL: ");
                iomt_dump(acl);
                iomt_free(acl);
            }

            *verinfo_out = verinfo;
            return true;
        }

        return false;
    }
    case RETRIEVE_FILE:
    {
        hash_t encrypted_secret, kf;
        recv(fd, &encrypted_secret, sizeof(encrypted_secret), MSG_WAITALL);
        recv(fd, &kf, sizeof(kf), MSG_WAITALL);

        if(!is_zero(kf))
        {
            hash_t pad = hmac_sha256(&kf, sizeof(kf),
                                     user_key, keylen);
            *secret_out = hash_xor(encrypted_secret, pad);
        }
        else
            *secret_out = hash_null;

        *buildcode = iomt_deserialize(read_from_fd, &fd);
        *composefile = iomt_deserialize(read_from_fd, &fd);

        recv(fd, file_len, sizeof(*file_len), MSG_WAITALL);

        if(*file_len)
        {
            *file_contents_out = malloc(*file_len);
            recv(fd, *file_contents_out, *file_len, MSG_WAITALL);
        }
        else
        {
            *file_contents_out = NULL;
            return false;
        }
        return true;
    }
    default:
        assert(false);
    }
}

/* set version = 0 to get latest version */
struct version_info request_verinfo(int fd, uint64_t user_id,
                                    const char *user_key, size_t keylen,
                                    uint64_t file_idx, uint64_t version)

{
    struct user_request req;
    req.type = RETRIEVE_INFO;
    req.user_id = user_id;
    req.retrieve.file_idx = file_idx;
    req.retrieve.version = version;

    struct version_info verinfo;

    bool rc = exec_request(fd, &req,
                           NULL,
                           NULL,
                           NULL,
                           NULL, 0,
                           NULL,
                           &verinfo,
                           user_key, keylen,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           NULL);
    if(rc)
        return verinfo;
    return verinfo_null;
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
    fseek(f, 0, SEEK_END);
    *len = ftell(f);
    fseek(f, 0, SEEK_SET);
    void *buf = malloc(*len);
    fread(buf, 1, *len, f);
    return buf;
}

void write_file(const char *path, const void *contents, size_t len)
{
    if(contents)
    {
        FILE *f = fopen(path, "w");
        fwrite(contents, 1, len, f);
        fclose(f);
    }
}

bool server_request(const char *sockpath,
                    const char *user_key, uint64_t user_id,
                    struct user_request req,
                    struct iomt *new_acl,
                    const char *buildcode_path,
                    const char *compose_path,
                    const char *image_path,
                    const char *file_key)
{
    struct iomt *buildcode = NULL, *composefile = NULL;
    void *file_contents = NULL;
    size_t file_len = 0;
    hash_t secret = hash_null;

    /* Fill in rest of request structure */
    req.user_id = user_id;

    if(req.type == MODIFY_FILE)
    {
        /* these can safely take NULLs */
        buildcode = iomt_from_lines(buildcode_path);
        composefile = iomt_from_lines(compose_path);

        if(image_path)
        {
            file_contents = load_file(image_path, &file_len);

            /* Encrypt file and secret */
            if(file_key)
            {
                /* Get version */
                int fd = connect_to_service(sockpath);
                struct version_info verinfo = request_verinfo(fd, user_id,
                                                              user_key, strlen(user_key),
                                                              req.modify_file.file_idx,
                                                              0);
                close(fd);

                /* failure */
                if(verinfo.idx == 0)
                {
                    printf("Could not get version info.\n");
                    return false;
                }

                /* We use a block cipher in CTR mode and can thus
                 * avoid having to use an IV (as long as we never
                 * re-use keys) */
                hash_t nonce = generate_nonce();
                secret = derive_key(file_key, nonce);

                /* encrypt file (presumably a symmetric cipher) */
                crypt_bytes(file_contents, file_len, secret);

                printf("Derived file secret: %s\n", hash_format(secret, 4).str);
                req.modify_file.kf = calc_kf(secret, req.modify_file.file_idx);
                req.modify_file.encrypted_secret = crypt_secret(secret,
                                                                req.modify_file.file_idx,
                                                                verinfo.max_version + 1,
                                                                user_key, user_id);
            }
        }
    }

    struct version_info verinfo;
    struct tm_request tmreq;

    int fd = connect_to_service(sockpath);

    bool success = exec_request(fd, &req,
                                req.type == MODIFY_ACL ? new_acl : NULL,
                                req.type == MODIFY_FILE ? buildcode : NULL,
                                req.type == MODIFY_FILE ? composefile : NULL,
                                req.type == MODIFY_FILE ? file_contents : NULL,
                                req.type == MODIFY_FILE ? file_len : 0,
                                req.type <= MODIFY_ACL ? &tmreq : NULL,
                                req.type == RETRIEVE_INFO ? &verinfo : NULL,
                                req.type >= RETRIEVE_INFO ? user_key : NULL,
                                req.type >= RETRIEVE_INFO ? strlen(user_key) : 0,
                                req.type == RETRIEVE_FILE ? &buildcode : NULL,
                                req.type == RETRIEVE_FILE ? &composefile : NULL,
                                req.type == RETRIEVE_FILE ? &secret : NULL,
                                req.type == RETRIEVE_FILE ? &file_contents : NULL,
                                req.type == RETRIEVE_FILE ? &file_len : NULL);

    close(fd);

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
    case RETRIEVE_INFO:
        printf("File info: ");
        dump_versioninfo(&verinfo);
        break;
    case RETRIEVE_FILE:
    {
        hash_t gamma = sha256(file_contents, file_len);

        hash_t kf = calc_kf(secret, req.retrieve.file_idx);

        /* We should recalculate the roots of the two IOMTs ourselves
         * to be sure */
        hash_t lambda = calc_lambda(gamma, buildcode, composefile, kf);

        printf("Decrypted file secret as %s\n", hash_format(secret, 4).str);
        printf("File lambda = %s\n", hash_format(lambda, 4).str);

        if(!is_zero(kf))
            crypt_bytes(file_contents, file_len, secret);

        printf("Writing image file to %s.\n", image_path);
        write_file(image_path, file_contents, file_len);
        /* What about build code? We only have the IOMT, not the actual contents. */

        /* Verify contents */
        int fd = connect_to_service(sockpath);
        struct version_info verinfo = request_verinfo(fd, user_id,
                                                      user_key, strlen(user_key),
                                                      req.file_idx,
                                                      0);
        close(fd);

        bool success = hash_equals(lambda, verinfo.lambda);

        if(!success)
        {
            printf("Could not verify integrity of response (lambda should be %s).\n",
                   hash_format(verinfo.lambda, 4).str);
        }
        else
            printf("Successfully verifed integrity of file.\n");

        return success;
    }
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

    bool success = server_request(socket_path, userkey, user_id,
                                  cl_request, new_acl,
                                  buildcode_path, compose_path, image_path,
                                  file_key);

    return !success;

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
}
