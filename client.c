/* Taken from
 * https://github.com/troydhanson/network/blob/master/unixdomain/01.basic/cli.c */

#define CLIENT
#include "crypto.h"
#include "service_provider.h"
#include "trusted_module.h"
#include "test.h"

#include <sys/socket.h>
#include <sys/un.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

char *socket_path = "socket";

static struct tm_request verify_and_sign(int fd, const struct user_request *req)
{
    struct tm_request tmr = req_null;
    if(read(fd, &tmr, sizeof(tmr)) != sizeof(tmr))
    {
        perror("read");
        exit(1);
    }

    assert(tmr.type != REQ_NONE);

    switch(req->type)
    {
    case CREATE_FILE:
    {
        /* check request values to make sure they actually do what we
         * want */
        struct iomt_node acl_node = { req->create.user_id, req->create.user_id, u64_to_hash(3) };
        if(tmr.type != ACL_UPDATE ||
           tmr.idx == 0 ||
           tmr.counter != 0 ||
           !hash_equals(hash_node(&acl_node), tmr.val))
            return req_null;
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

    hash_t hmac = hmac_sha256(&tmr, sizeof(tmr), "a", 1);
    write(fd, &hmac, sizeof(hmac));

    return tmr;
}

static bool verify_sp_ack(int fd, const struct tm_request *tmr)
{
    hash_t hmac = hash_null;
    if(read(fd, &hmac, sizeof(hmac)) != sizeof(hmac))
    {
        perror("read 2");
        exit(2);
    }

    return ack_verify(tmr, "a", 1, hmac);
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
        return verify_sp_ack(fd, &tmr);
    }
    case RETRIEVE_INFO:
    {
        hash_t hmac;
        struct version_info verinfo;
        read(fd, &verinfo, sizeof(verinfo));
        read(fd, &hmac, sizeof(hmac));

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
        read(fd, &encrypted_secret, sizeof(encrypted_secret));

        *secret_out = crypt_secret(encrypted_secret,
                                   req->retrieve.file_idx,
                                   req->retrieve.version,
                                   user_key, keylen);

        *buildcode = iomt_deserialize(read_from_fd, &fd);
        *composefile = iomt_deserialize(read_from_fd, &fd);

        read(fd, file_len, sizeof(*file_len));

        *file_contents_out = malloc(*file_len);
        read(fd, file_contents_out, *file_len);
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
    if (*socket_path == '\0') {
        *addr.sun_path = '\0';
        strncpy(addr.sun_path+1, socket_path+1, sizeof(addr.sun_path)-2);
    } else {
        strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path)-1);
    }

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("connect error");
        exit(-1);
    }

    return fd;
}

int main(int argc, char *argv[]) {
    char buf[100];
    int fd,rc;

    if (argc > 1) socket_path=argv[1];

    fd = connect_to_service(socket_path);

    struct user_request req;
    req.type = CREATE_FILE;
    req.create.user_id = 1;

    check("Client file creation", exec_request(fd, &req, NULL, NULL, NULL, NULL, 0,
                                               NULL, NULL, 0,
                                               NULL, NULL, NULL, NULL, NULL));
    close(fd);
    fd = connect_to_service(socket_path);

    req.type = MODIFY_FILE;
    req.modify_file.user_id = 1;
    req.modify_file.file_idx = 1;
    req.modify_file.encrypted_secret = hash_null;
    req.modify_file.kf = hash_null;

    check("Client file modification", exec_request(fd, &req, NULL, NULL, NULL, "contents", 8,
                                                   NULL, NULL, 0,
                                                   NULL, NULL, NULL, NULL, NULL));
    close(fd);

    return 0;
}
