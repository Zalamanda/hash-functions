# Multi-platform Hash Functions
Convenient MD2, MD5, SHA1, SHA256, SHA3 (incl. Keccak) and Blake2b multi-platform hash functions for C.

### Basic usage
Hash functions can be easily used by calling their convenient one-liners...
```c
void md2(const void *in, size_t inlen, void *out);
void md5(const void *in, size_t inlen, void *out);
void sha1(const void *in, size_t inlen, void *out);
void sha256(const void *in, size_t inlen, void *out);
void sha3(const void *in, size_t inlen, void *out, int outlen);
void keccak(const void *in, size_t inlen, void *out, int outlen);
void blake2b(const void *in, size_t inlen, const void *key, int keylen, void *out, int outlen);
   /* for keyless blake2b, simply set (key = NULL) and (keylen = 0) */
```

### Advanced usage
For more control over initialization, input and finalization...
```c
/* MD2 functions */
void md2_init(MD2_CTX *ctx);
void md2_update(MD2_CTX *ctx, const void *in, size_t inlen);
void md2_final(MD2_CTX *ctx, void *out);
/* MD5 */
void md5_init(MD5_CTX *ctx);
void md5_update(MD5_CTX *ctx, const void *in, size_t inlen);
void md5_final(MD5_CTX *ctx, void *out);
/* SHA1 */
void sha1_init(SHA1_CTX *ctx);
void sha1_update(SHA1_CTX *ctx, const void *in, size_t inlen);
void sha1_final(SHA1_CTX *ctx, void *out);
/* SHA256 */
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const void *in, size_t inlen);
void sha256_final(SHA256_CTX *ctx, void *out);
/* SHA3 */
void sha3_init(SHA3_CTX *ctx, int outlen);
void sha3_update(SHA3_CTX *ctx, const void *in, size_t inlen);
void sha3_final(SHA3_CTX *ctx, void *out);
/* Keccak */
void Keccak_init(SHA3_CTX *ctx, int outlen);
void Keccak_update(SHA3_CTX *ctx, const void *in, size_t inlen);
void Keccak_final(SHA3_CTX *ctx, void *out);
/* Blake2b */
void blake2b_init(BLAKE2B_CTX *ctx, const void *key, int keylen, int outlen);
void blake2b_update(BLAKE2B_CTX *ctx, const void *in, size_t inlen);
void blake2b_final(BLAKE2B_CTX *ctx, void *out);
```

### Example usage
The [Hash Test](test/hashtest.c) file is provided as an example of basic usage and testing, which validates known hashes against several standard test vectors used in [RFC 1321](https://tools.ietf.org/html/rfc1321).
#### Self Compilation and Execution:
Self compilation helper files, [testWIN.bat](testWIN.bat) & [testUNIX.bat](testUNIX.bat), are provided for easy compilation and execution of the [Hash Test](testhash.c) file.  
> testWIN.bat; Requires `Microsoft Visual Studio 2017 Community Edition` installed. Tested on x86_64 architecture running Windows 10 Pro v10.0.18362.  
> testUNIX.sh; Requires the `build-essential` package installed. Tested on x86_64 architecture running Ubuntu 16.04.1.

### More information
Hash lengths and context structs are also provided with each file.  
See the header comments of each file for more information.
