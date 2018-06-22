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

static bool need_sign(int reqtype)
{
    return reqtype == CREATE_FILE || reqtype == MODIFY_FILE || reqtype == MODIFY_ACL;
}

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

void write_fd(void *userdata, const void *data, size_t len)
{
    int *fdptr = userdata;
    write(*fdptr, data, len);
}

bool exec_request(int fd, const struct user_request *req,
                  const struct iomt *new_acl,
                  const struct iomt *new_buildcode,
                  const struct iomt *new_composefile,
                  const void *file_contents, size_t len)
{
    write(fd, req, sizeof(*req));
    /* write additional data */
    switch(req->type)
    {
    case MODIFY_ACL:
        /* send ACL */
        iomt_serialize(new_acl, write_fd, &fd);
        break;
    case MODIFY_FILE:
        /* send build code, compose file, and file contents */
        iomt_serialize(new_buildcode, write_fd, &fd);
        iomt_serialize(new_composefile, write_fd, &fd);

        /* prefix file with size */
        write(fd, &len, sizeof(len));
        write(fd, file_contents, len);
        break;
    case CREATE_FILE:
    case RETRIEVE_INFO:
    case RETRIEVE_FILE:
        /* no additional data needed, fall through */
    default:
        break;
    }

    struct tm_request tmr;

    /* sign request */
    if(need_sign(req->type))
    {
        /* read a tm_request from the file descriptor, and verify that
         * it carries out the requested action, and then sign */
        tmr = verify_and_sign(fd, req);
    }

    /* verify acknowledgement */
    return verify_sp_ack(fd, &tmr);
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

    check("Client file creation", exec_request(fd, &req, NULL, NULL, NULL, NULL, 0));
    close(fd);
    fd = connect_to_service(socket_path);

    req.type = MODIFY_FILE;
    req.modify_file.user_id = 1;
    req.modify_file.file_idx = 1;
    req.modify_file.encrypted_secret = hash_null;
    req.modify_file.kf = hash_null;

    check("Client file modification", exec_request(fd, &req, NULL, NULL, NULL, "contents", 8));
    close(fd);

    return 0;
}
