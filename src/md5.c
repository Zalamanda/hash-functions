/* ****************************************************************
 * MD5 hash function support.
 *  - md5.c (8 April 2020)
 *
 * Based on Brad Conte's (brad@bradconte.com) basic implementations
 * of cryptography algorithms,
 *    https://github.com/B-Con/crypto-algorithms
 * which was released into the Public Domain and is therefore used
 * with permission, and with much gratitude.  \(^-^)/
 *
 * This implementation supports MD5 message digests on x86_64
 * little endian hardware, using modified routines for faster
 * MD5 transformations.
 *
 * ****************************************************************/

#ifndef _MD5_C_
#define _MD5_C_  /* include guard */


#include <stddef.h>
#include <stdint.h>

#ifndef MD5_LENGTH
#define MD5_LENGTH  16
#endif

#ifndef ROTLEFT
#define ROTLEFT(a,b)  ( (a << b) | (a >> (32-b)) )
#endif

#define F(x,y,z)  ( (x & y) | (~x & z) )
#define G(x,y,z)  ( (x & z) | (y & ~z) )
#define H(x,y,z)  ( x ^ y ^ z )
#define I(x,y,z)  ( y ^ (x | ~z) )

#define FF(a,b,c,d,m,s,t)  { a += F(b,c,d) + m + t; a = b + ROTLEFT(a,s); }
#define GG(a,b,c,d,m,s,t)  { a += G(b,c,d) + m + t; a = b + ROTLEFT(a,s); }
#define HH(a,b,c,d,m,s,t)  { a += H(b,c,d) + m + t; a = b + ROTLEFT(a,s); }
#define II(a,b,c,d,m,s,t)  { a += I(b,c,d) + m + t; a = b + ROTLEFT(a,s); }

/* MD5 context */
typedef struct {
   uint8_t data[64];
   uint32_t datalen;
   uint64_t bitlen;
   uint32_t state[4];
} MD5_CTX;

/* MD5 transformation */
static void md5_transform(MD5_CTX *ctx, const uint8_t data[])
{
   uint32_t a, b, c, d, m[16];
   int i;

   for(i = 0; i < 8; i++)
      ((uint64_t *) m)[i] = ((uint64_t *) data)[i];

   a = ctx->state[0];
   b = ctx->state[1];
   c = ctx->state[2];
   d = ctx->state[3];

   FF(a,b,c,d,m[0],  7,0xd76aa478);
   FF(d,a,b,c,m[1], 12,0xe8c7b756);
   FF(c,d,a,b,m[2], 17,0x242070db);
   FF(b,c,d,a,m[3], 22,0xc1bdceee);
   FF(a,b,c,d,m[4],  7,0xf57c0faf);
   FF(d,a,b,c,m[5], 12,0x4787c62a);
   FF(c,d,a,b,m[6], 17,0xa8304613);
   FF(b,c,d,a,m[7], 22,0xfd469501);
   FF(a,b,c,d,m[8],  7,0x698098d8);
   FF(d,a,b,c,m[9], 12,0x8b44f7af);
   FF(c,d,a,b,m[10],17,0xffff5bb1);
   FF(b,c,d,a,m[11],22,0x895cd7be);
   FF(a,b,c,d,m[12], 7,0x6b901122);
   FF(d,a,b,c,m[13],12,0xfd987193);
   FF(c,d,a,b,m[14],17,0xa679438e);
   FF(b,c,d,a,m[15],22,0x49b40821);

   GG(a,b,c,d,m[1],  5,0xf61e2562);
   GG(d,a,b,c,m[6],  9,0xc040b340);
   GG(c,d,a,b,m[11],14,0x265e5a51);
   GG(b,c,d,a,m[0], 20,0xe9b6c7aa);
   GG(a,b,c,d,m[5],  5,0xd62f105d);
   GG(d,a,b,c,m[10], 9,0x02441453);
   GG(c,d,a,b,m[15],14,0xd8a1e681);
   GG(b,c,d,a,m[4], 20,0xe7d3fbc8);
   GG(a,b,c,d,m[9],  5,0x21e1cde6);
   GG(d,a,b,c,m[14], 9,0xc33707d6);
   GG(c,d,a,b,m[3], 14,0xf4d50d87);
   GG(b,c,d,a,m[8], 20,0x455a14ed);
   GG(a,b,c,d,m[13], 5,0xa9e3e905);
   GG(d,a,b,c,m[2],  9,0xfcefa3f8);
   GG(c,d,a,b,m[7], 14,0x676f02d9);
   GG(b,c,d,a,m[12],20,0x8d2a4c8a);

   HH(a,b,c,d,m[5],  4,0xfffa3942);
   HH(d,a,b,c,m[8], 11,0x8771f681);
   HH(c,d,a,b,m[11],16,0x6d9d6122);
   HH(b,c,d,a,m[14],23,0xfde5380c);
   HH(a,b,c,d,m[1],  4,0xa4beea44);
   HH(d,a,b,c,m[4], 11,0x4bdecfa9);
   HH(c,d,a,b,m[7], 16,0xf6bb4b60);
   HH(b,c,d,a,m[10],23,0xbebfbc70);
   HH(a,b,c,d,m[13], 4,0x289b7ec6);
   HH(d,a,b,c,m[0], 11,0xeaa127fa);
   HH(c,d,a,b,m[3], 16,0xd4ef3085);
   HH(b,c,d,a,m[6], 23,0x04881d05);
   HH(a,b,c,d,m[9],  4,0xd9d4d039);
   HH(d,a,b,c,m[12],11,0xe6db99e5);
   HH(c,d,a,b,m[15],16,0x1fa27cf8);
   HH(b,c,d,a,m[2], 23,0xc4ac5665);

   II(a,b,c,d,m[0],  6,0xf4292244);
   II(d,a,b,c,m[7], 10,0x432aff97);
   II(c,d,a,b,m[14],15,0xab9423a7);
   II(b,c,d,a,m[5], 21,0xfc93a039);
   II(a,b,c,d,m[12], 6,0x655b59c3);
   II(d,a,b,c,m[3], 10,0x8f0ccc92);
   II(c,d,a,b,m[10],15,0xffeff47d);
   II(b,c,d,a,m[1], 21,0x85845dd1);
   II(a,b,c,d,m[8],  6,0x6fa87e4f);
   II(d,a,b,c,m[15],10,0xfe2ce6e0);
   II(c,d,a,b,m[6], 15,0xa3014314);
   II(b,c,d,a,m[13],21,0x4e0811a1);
   II(a,b,c,d,m[4],  6,0xf7537e82);
   II(d,a,b,c,m[11],10,0xbd3af235);
   II(c,d,a,b,m[2], 15,0x2ad7d2bb);
   II(b,c,d,a,m[9], 21,0xeb86d391);

   ctx->state[0] += a;
   ctx->state[1] += b;
   ctx->state[2] += c;
   ctx->state[3] += d;
}

/* Initialize the hashing context `ctx` */
void md5_init(MD5_CTX *ctx)
{
   ctx->datalen = 0;
   ctx->bitlen = 0;
   ctx->state[0] = 0x67452301;
   ctx->state[1] = 0xEFCDAB89;
   ctx->state[2] = 0x98BADCFE;
   ctx->state[3] = 0x10325476;
}

/* Add `inlen` bytes from `in` into the hash */
void md5_update(MD5_CTX *ctx, const void *in, size_t inlen)
{
   size_t i;

   for(i = 0; i < inlen; ++i) {
      ctx->data[ctx->datalen] = ((const uint8_t *) in)[i];
      ctx->datalen++;
      if(ctx->datalen == 64) {
         md5_transform(ctx, ctx->data);
         ctx->bitlen += 512;
         ctx->datalen = 0;
      }
   }
}

/* Generate the message digest and place in `out` */
void md5_final(MD5_CTX *ctx, void *out)
{
   uint32_t i;

   i = ctx->datalen;

   /* Pad whatever data is left in the buffer. */
   if(ctx->datalen < 56) {
      ctx->data[i++] = 0x80;
      while (i < 56)
         ctx->data[i++] = 0x00;
   } else if(ctx->datalen >= 56) {
      ctx->data[i++] = 0x80;
      while(i < 64)
         ctx->data[i++] = 0x00;
      md5_transform(ctx, ctx->data);
      memset(ctx->data, 0, 56);
   }

   /* Append to the padding the total message's length in bits and
    * transform. */
   ctx->bitlen += ctx->datalen << 3;
   *((uint64_t *) &ctx->data[56]) = ctx->bitlen;
   md5_transform(ctx, ctx->data);

   ((uint64_t *) out)[0] = ((uint64_t *) ctx->state)[0];
   ((uint64_t *) out)[1] = ((uint64_t *) ctx->state)[1];
}

/* Convenient all-in-one MD5 computation */
void md5(const void *in, size_t inlen, void *out)
{
   MD5_CTX ctx;

   md5_init(&ctx);
   md5_update(&ctx, in, inlen);
   md5_final(&ctx, out);
}


#endif  /* end _MD5_C_ */
