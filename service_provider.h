/* implementation of a basic service provider for use with the trusted
 * module */

#ifndef CSAA_SERVICE_PROVIDER_H
#define CSAA_SERVICE_PROVIDER_H

#include "crypto.h"
#include "trusted_module.h"

struct service_provider;

struct service_provider *sp_new(const void *key, size_t keylen, int logleaves);
void sp_free(struct service_provider *sp);

/* see .c file for documentation */
struct tm_cert sp_request(struct service_provider *sp,
                          const struct user_request *req, hash_t req_hmac,
                          hash_t *hmac_out,
                          struct tm_cert *vr_out, hash_t *vr_hmac_out,
                          hash_t *ack_hmac_out,
                          hash_t encrypted_secret, hash_t kf,
                          const void *encrypted_contents, size_t contents_len,
                          struct iomt *new_acl);

/* Reserve a new file index with user_id added to the ACL. Returns
 * cert on failure. Authenticated with ack_hmac, which is the returned
 * request with a zero byte appended, signed by the module. */
struct user_request sp_createfile(struct service_provider *sp,
                                  uint64_t user_id, const void *key, size_t keylen,
                                  hash_t *ack_hmac);

struct user_request sp_modifyacl(struct service_provider *sp,
                                 uint64_t user_id, const void *key, size_t keylen,
                                 uint64_t file_idx,
                                 struct iomt *new_acl,
                                 hash_t *ack_hmac);

struct user_request sp_modifyfile(struct service_provider *sp,
                                  uint64_t user_id, const void *key, size_t keylen,
                                  uint64_t file_idx,
                                  hash_t encrypted_secret, hash_t kf,
                                  const void *encrypted_file, size_t filelen,
                                  hash_t *ack_hmac);

/* Retrieve authenticated information on a version of a file; if
 * version is zero, default to the latest version. */
struct version_info sp_fileinfo(struct service_provider *sp,
                                uint64_t user_id, uint64_t file_id,
                                uint64_t version,
                                hash_t *hmac);

/* Again, version=0 selects the latest version. */
void *sp_retrieve_file(struct service_provider *sp,
                       uint64_t user_id,
                       uint64_t file_idx,
                       uint64_t version,
                       hash_t *encrypted_secret,
                       size_t *len);

void sp_test(void);

#endif
