/* Based on:
 * <https://github.com/troydhanson/network/blob/master/unixdomain/01.basic/cli.c> */

/* A dummy client for use with the dummy service provider, which
 * provides no assurances. */

/* Usage:
 *
 * $ ./client [-s <SOCKET>] -u USERID COMMAND [PARAMS]
 *
 * Where COMMAND and PARAMS are one of the following:
 *   create (takes no parameters)
 *
 *   modifyfile -f FILEIDX -i IMAGE_FILE
 *
 *   retrievefile -f FILEIDX [-v VERSION] -o IMAGE_OUT
 */

#define CLIENT
#include "crypto.h"
#include "service_provider.h"
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
static uint64_t user_id = 0;
static struct user_request cl_request;
const char *image_path = NULL;
static bool labels = false, labels_only = false;

void print_usage(const char *name)
{
    printf("Usage:\n"
           "\n"
           "$ ./client [-s <SOCKET>] -u USERID -k USER_KEY COMMAND [PARAMS]\n"
           "\n"
           "Where COMMAND and PARAMS are one of the following:\n"
           "  create (takes no parameters)\n"
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
        else if(!strcmp(arg, "-h") || !strcmp(arg, "--help"))
        {
            print_usage(argv[0]);
            exit(1);
        }
        else if(!strcmp(arg, "-p") || !strcmp(arg, "--profile"))
        {
            cl_request.profile = true;
        }
        else if(!strcmp(arg, "-l") || !strcmp(arg, "--labels"))
        {
            labels = true;
        }
        else if(!strcmp(arg, "--labels-only"))
        {
            labels_only = true;
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
            /* ignore unknowns */
            //parse_args_fail = "Unknown parameter";
            //return false;
        }
    }
    if(cl_request.type != USERREQ_NONE && user_id != 0)
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

/* In case of modifcation or file creation, returns true on successful
 * completion of request, as acknowledged by module. In case of info
 * retrieval, returns true if version info is verified by module. The
 * verinfo_out, user_key, and keylen parameters must not be NULL in
 * this case (in all other cases they are ignored). */
bool exec_request(int fd, const struct user_request *req,
                  const void *new_file_contents, size_t len, /* MODIFY_FILE only */
                  struct version_info *verinfo_out,          /* RETRIEVE_INFO only */
                  void **file_contents_out,                  /* RETRIEVE_FILE only */
                  size_t *file_len,                          /* RETRIEVE_FILE only */
                  uint64_t *new_idx,                         /* CREATE_FILE only */
		  struct server_profile *profile_out)        /* profile=true only */
{
    write(fd, req, sizeof(*req));
    /* write additional data */
    switch(req->type)
    {
    case MODIFY_FILE:
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

    /* server now processes request */
    
    switch(req->type)
    {
    case CREATE_FILE:
    {
        if(new_idx)
            recv(fd, new_idx, sizeof(*new_idx), MSG_WAITALL);
	
        if(req->profile)
            prof_read(fd, profile_out);
	
        return true;
    }
    case MODIFY_ACL:
    case MODIFY_FILE:
    {
        /* don't verify */
        if(req->profile)
            prof_read(fd, profile_out);

        return true;
    }
    case RETRIEVE_INFO:
    {
        struct version_info verinfo;
        recv(fd, &verinfo, sizeof(verinfo), MSG_WAITALL);
        *verinfo_out = verinfo;
        if(req->profile)
            prof_read(fd, profile_out);

        return true;
    }
    case RETRIEVE_FILE:
    {
        *file_contents_out = deserialize_file(fd, file_len);

        if(req->profile)
            prof_read(fd, profile_out);

        return true;
    }
    default:
        assert(false);
    }
}

/* set version = 0 to get latest version */
struct version_info request_verinfo(int fd, uint64_t user_id,
                                    uint64_t file_idx, uint64_t version)

{
    struct user_request req;
    req.type = RETRIEVE_INFO;
    req.user_id = user_id;
    req.retrieve.file_idx = file_idx;
    req.retrieve.version = version;

    struct version_info verinfo;

    exec_request(fd, &req,
                 NULL, 0,
                 &verinfo,
                 NULL,
                 NULL,
                 NULL,
		 NULL);

    return verinfo;
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

bool server_request(const char *sockpath,
                    uint64_t user_id,
                    struct user_request req,
                    const char *image_path)
{
    void *file_contents = NULL;
    size_t file_len = 0;

    /* Fill in rest of request structure */
    req.user_id = user_id;

    if(req.type == MODIFY_FILE)
    {
        if(image_path)
        {
            file_contents = load_file(image_path, &file_len);
        }
    }

    struct version_info verinfo;
    struct server_profile profile;

    int fd = connect_to_service(sockpath);
    uint64_t new_idx;

    bool success = exec_request(fd, &req,
                                req.type == MODIFY_FILE ? file_contents : NULL,
                                req.type == MODIFY_FILE ? file_len : 0,
                                req.type == RETRIEVE_INFO ? &verinfo : NULL,
                                req.type == RETRIEVE_FILE ? &file_contents : NULL,
                                req.type == RETRIEVE_FILE ? &file_len : NULL,
                                req.type == CREATE_FILE ? &new_idx : NULL,
				req.profile ? &profile : NULL);

    printf("Request %s\n",
           success ?
           "\033[32;1msucceeded\033[0m" :
           "\033[31;1mfailed\033[0m");

    if(!success)
        return false;

    switch(req.type)
    {
    case CREATE_FILE:
        printf("Created file with index %lu.\n", new_idx);
        break;
    case RETRIEVE_INFO:
        printf("File info: ");
        dump_versioninfo(&verinfo);
        break;
    case RETRIEVE_FILE:
    {
        printf("Writing image file to %s.\n", image_path);
        write_file(image_path, file_contents, file_len);
        /* What about build code? We only have the IOMT, not the actual contents. */
        break;
    }
    default:
        break;
    }
    
    if(req.profile)
    {
        /* dump to stderr */
        prof_dump(&profile, labels, labels_only);
    }

    return true;
}

int main(int argc, char *argv[]) {
    if(!parse_args(argc, argv))
    {
        printf("%s\n", parse_args_fail);
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);

    server_request(socket_path, user_id,
                   cl_request,
                   image_path);

    return 0;
}
