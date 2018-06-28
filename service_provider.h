/* implementation of a basic service provider for use with the trusted
 * module */

#ifndef CSAA_SERVICE_PROVIDER_H
#define CSAA_SERVICE_PROVIDER_H

#include "crypto.h"
#include "trusted_module.h"

struct service_provider;

/* Client-service protocol: */

/* 1. Client sends user_request to service.
 *
 * 2. Client sends additional data to service, if needed.
 *
 * 3. Service sends filled tm_request to client for signature.
 *
 * 4. Client verifies that the tm_request is appropriate.
 *
 * 5. Client sends HMAC(tm_request, user key) to service.
 *
 * 6. Service performs action.
 *
 * 7. Service sends module's authenticated acknowledgement (and
 * response, in the case of RETRIEVE_INFO) to client.
 *
 * 8. Client verifies acknowledgement against earlier tm_request or
 * response.
 */

/* request from the client to the service */
struct user_request {
    enum { USERREQ_NONE = 0, CREATE_FILE, MODIFY_FILE, MODIFY_ACL, RETRIEVE_INFO, RETRIEVE_FILE } type;
    uint64_t user_id;
    union {
        uint64_t file_idx;
        struct {
            uint64_t file_idx;
            /* ACL IOMT will follow */

            /* service will respond with tm_request structure,
             * requiring a client signature; then the module's HMAC
             * will follow */
        } modify_acl;
        struct {
            uint64_t file_idx;
            hash_t encrypted_secret, kf;
            /* file contents, build code IOMT, and compose file IOMT
             * will follow */

            /* service will respond with tm_request structure,
             * requiring a client signature; then the module's HMAC
             * will follow */
        } modify_file;
        struct {
            /* same structure for retrieve file and retrieve info */
            uint64_t file_idx, version;
            /* service will respond with either version_info struct,
             * the serialized ACL, and an HMAC, or file contents and
             * key (which the client can verify themselves) */
        } retrieve;
    };
} __attribute__((packed));

#ifndef CLIENT
struct service_provider *sp_new(const void *key, size_t keylen, int logleaves, const char *data_dir);
void sp_free(struct service_provider *sp);

/* see .c file for documentation */
struct tm_cert sp_request(struct service_provider *sp,
                          const struct tm_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac_out,
                          hash_t *ack_hmac_out,
                          hash_t encrypted_secret, hash_t kf,
                          const struct iomt *buildcode, const struct iomt *composefile,
                          const void *encrypted_contents, size_t contents_len,
                          const struct iomt *new_acl);

/* Reserve a new file index with user_id added to the ACL. Returns
 * cert on failure. Authenticated with ack_hmac, which is the returned
 * request with a zero byte appended, signed by the module. */
struct tm_request sp_createfile(struct service_provider *sp,
                                uint64_t user_id,
                                hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                                void *userdata,
                                hash_t *ack_hmac);

struct tm_request sp_modifyacl(struct service_provider *sp,
                               uint64_t user_id,
                               hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                               void *userdata,
                               uint64_t file_idx,
                               struct iomt *new_acl,
                               hash_t *ack_hmac);

struct tm_request sp_modifyfile(struct service_provider *sp,
                                uint64_t user_id,
                                hash_t (*sign_request)(void *userdata, const struct tm_request *req),
                                void *userdata,
                                uint64_t file_idx,
                                hash_t encrypted_secret, hash_t kf,
                                const struct iomt *buildcode, const struct iomt *composefile,
                                const void *encrypted_file, size_t filelen,
                                hash_t *ack_hmac);

/* Retrieve authenticated information on a version of a file; if
 * version is zero, default to the latest version. */
struct version_info sp_fileinfo(struct service_provider *sp,
                                uint64_t user_id, uint64_t file_idx,
                                uint64_t version,
                                hash_t *hmac,
                                struct iomt **acl_out);

/* Again, version=0 selects the latest version. */
void *sp_retrieve_file(struct service_provider *sp,
                       uint64_t user_id,
                       uint64_t file_idx,
                       uint64_t version,
                       hash_t *encrypted_secret,
                       hash_t *kf,
                       struct iomt **buildcode,
                       struct iomt **composefile,
                       size_t *len);

int sp_main(int sockfd, int logleaves);

void sp_test(void);
#endif

#endif
