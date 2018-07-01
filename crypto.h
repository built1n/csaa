#ifndef CSAA_CRYPTO_H
#define CSAA_CRYPTO_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct tm_request;
struct version_info;

/* Various useful cryptographic functions; shared between TM and SP. */

/* we use SHA256 for h() */
typedef struct hash_t {
    /* a hash of all zeros is given a special meaning */
    unsigned char hash[32];
} hash_t;

/* guaranteed to be zero */
static const struct hash_t hash_null = { { 0 } };

bool encloses(uint64_t b, uint64_t bprime, uint64_t a);
bool hash_equals(hash_t a, hash_t b);
bool is_zero(hash_t u);

hash_t hash_xor(hash_t a, hash_t b);

hash_t sha256(const void *data, size_t datalen);
hash_t hmac_sha256(const void *data, size_t datalen, const void *key, size_t keylen);

hash_t merkle_compute(hash_t node, const hash_t *comp, const int *orders, size_t n);
hash_t merkle_parent(hash_t u, hash_t v, int order);

/* Calculate the indicies of the complementary nodes to a
 * leaf. `leafidx' is 0 for the rightmost leaf node. This function
 * will return an array with a length equal to the number of levels in
 * the tree minus one (the root is not a complentary node). The 0th
 * element of the returned array will be the index of the immediate
 * sibling, while the 1st element will be the index of the
 * complementary node one level above the leaf node, and so on. Note
 * that logleaves = log2(nleaves). If `orders' is not NULL, the
 * function will additionally allocate an array of `logleaves' *
 * sizeof(int) with each element representing whether each
 * complementary node is a left or right child. */
int *bintree_complement(int leafidx, int logleaves, int **orders);
int *bintree_complement_ordersonly(int leafidx, int logleaves);

/* Return an array of indices of tree nodes that are dependent on a
 * given leaf node. Will be ordered from nearest relative to root. */
int *bintree_ancestors(int leafidx, int logleaves);

int bintree_parent(int idx);
int bintree_sibling(int idx);

uint64_t hash_to_u64(hash_t h);
hash_t u64_to_hash(uint64_t n);
void dump_hash(hash_t u);

struct hashstring {
    char str[32 * 2 + 1];
};

struct hashstring hash_format(hash_t h, int n);

hash_t crypt_secret(hash_t encrypted_secret,
                    uint64_t file_idx, uint64_t file_version,
                    const void *key, size_t keylen);

struct iomt;

hash_t calc_lambda(hash_t gamma, const struct iomt *buildcode, const struct iomt *composefile, hash_t kf);

/* Generate a signed acknowledgement for successful completion of a
 * request. We append a zero byte to the user request and take the
 * HMAC. */
hash_t ack_sign(const struct tm_request *req, int nzeros, const void *key, size_t keylen);
bool ack_verify(const struct tm_request *req,
                const void *secret, size_t secret_len,
                hash_t hmac);

void write_to_fd(void *userdata, const void *data, size_t len);
int read_from_fd(void *userdata, void *buf, size_t len);

void dump_versioninfo(const struct version_info *verinfo);

void crypt_bytes(unsigned char *data, size_t len, hash_t key);
hash_t generate_nonce(void);
hash_t derive_key(const char *passphrase, hash_t nonce);
hash_t calc_kf(hash_t encryption_key, uint64_t file_idx);

void warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* self-test */
void crypto_test(void);
#endif
