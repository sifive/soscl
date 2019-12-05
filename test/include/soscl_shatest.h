#include <soscl_test_config.h>
#include <soscl/soscl_hash.h>

int test_sha256(void);
int test_hmac256(void);

int test_sha384(void);
int test_hmac384(void);

int test_sha512(void);
int test_hmac512(void);


int test_hash_kat(char *filename);
int test_hmac_kat(char *filename);

int test_hash_selftests(void);

