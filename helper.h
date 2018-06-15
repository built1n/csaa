#include "trusted_module.h"
#include "crypto.h"

struct tm_cert cert_ru(const struct trusted_module *tm,
                       const struct iomt_node *node, hash_t new_val,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out);

struct tm_cert cert_rv(const struct trusted_module *tm,
                       const struct iomt_node *node,
                       const hash_t *comp, const int *orders, size_t n,
                       hash_t *hmac_out,
                       uint64_t b,
                       struct tm_cert *nonexist, hash_t *hmac_nonexist);

/* Fill out a user_request struct to create a file with the index
 * given in file_node->idx with the user added with level 3 access in
 * the ACL. */
struct user_request req_filecreate(const struct trusted_module *tm,
                                   uint64_t user_id,
                                   const struct iomt_node *file_node,
                                   const hash_t *file_comp, const int *file_orders, size_t file_n);

/* Fill out a user_request struct to modify an existing file's
 * contents, given the previously generated FR certificate, and the
 * ACL node giving the user's access rights. */
struct user_request req_filemodify(const struct trusted_module *tm,
                                   const struct tm_cert *fr_cert, hash_t fr_hmac,
                                   const struct iomt_node *file_node,
                                   const hash_t *file_comp, const int *file_orders, size_t file_n,
                                   const struct iomt_node *acl_node,
                                   const hash_t *acl_comp, const int *acl_orders, size_t acl_n,
                                   hash_t fileval);

/* Fill out a user_request struct to modify a file's ACL. Same
 * parameters as req_filemodify(), except the hash is the root of the
 * new ACL. */
struct user_request req_aclmodify(const struct trusted_module *tm,
                                  const struct tm_cert *fr_cert, hash_t fr_hmac,
                                  const struct iomt_node *file_node,
                                  const hash_t *file_comp, const int *file_orders, size_t file_n,
                                  const struct iomt_node *oldacl_node,
                                  const hash_t *oldacl_comp, const int *oldacl_orders, size_t oldacl_n,
                                  hash_t newacl_root);
