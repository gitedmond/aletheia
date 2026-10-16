#include "program.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
/* Algorithms: FIPS 180-4, Sections 4-6; original loop implementations. */
// @algorithm none
// @category util.other
static uint32_t left(uint32_t value, unsigned n) {return (value << n) | (value >> (32-n));}
// @algorithm none
// @category util.other
static uint32_t right(uint32_t value, unsigned n) {return (value >> n) | (value << (32-n));}
// @algorithm none
// @category util.other
static uint32_t load_be(const uint8_t *p) {return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];}
// @algorithm none
// @category crypto.hash.sha1.transform
ALETHEIA_TARGET void sha1_transform(sha1_t *ctx, const uint8_t *block) {
    uint32_t words[80];
    for (unsigned i = 0; i < 16; ++i) words[i]=load_be(block+4*i);
    for (unsigned i = 16; i < 80; ++i) words[i]=left(words[i-3]^words[i-8]^words[i-14]^words[i-16],1);
    uint32_t a=ctx->state[0], b=ctx->state[1], c=ctx->state[2], d=ctx->state[3], e=ctx->state[4];
    for (unsigned i = 0; i < 80; ++i) {
        uint32_t f, constant;
        if (i < 20) {f=(b&c)|(~b&d); constant=UINT32_C(0x5a827999);}
        else if (i < 40) {f=b^c^d; constant=UINT32_C(0x6ed9eba1);}
        else if (i < 60) {f=(b&c)|(b&d)|(c&d); constant=UINT32_C(0x8f1bbcdc);}
        else {f=b^c^d; constant=UINT32_C(0xca62c1d6);}
        uint32_t next=left(a,5)+f+e+constant+words[i];
        e=d; d=c; c=left(b,30); b=a; a=next;
    }
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;ctx->state[4]+=e;
}
// @algorithm sha1/std
// @category crypto.hash.sha1.init
// @roles ctx
ALETHEIA_TARGET void sha1_init(sha1_t *ctx) {
    ctx->state[0]=UINT32_C(0x67452301);ctx->state[1]=UINT32_C(0xefcdab89);ctx->state[2]=UINT32_C(0x98badcfe);ctx->state[3]=UINT32_C(0x10325476);ctx->state[4]=UINT32_C(0xc3d2e1f0);
    ctx->total=0;ctx->used=0;
}
// @algorithm sha1/std
// @category crypto.hash.sha1.update
// @roles ctx,buf,len
ALETHEIA_TARGET void sha1_update(sha1_t *ctx, const uint8_t *buf, size_t len) {
    ctx->total+=len;
    for (size_t i=0;i<len;++i) {ctx->block[ctx->used++]=buf[i];if(ctx->used==64){sha1_transform(ctx,ctx->block);ctx->used=0;}}
}
// @algorithm sha1/std
// @category crypto.hash.sha1.final
// @roles ctx,out
ALETHEIA_TARGET void sha1_final(sha1_t *ctx, uint8_t *out) {
    uint64_t bits=ctx->total*8;uint8_t pad[64]={0x80},length[8];
    size_t n=ctx->used<56?56-ctx->used:120-ctx->used;sha1_update(ctx,pad,n);
    for(unsigned i=0;i<8;++i)length[7-i]=(uint8_t)(bits>>(8*i));
    sha1_update(ctx,length,8);
    for(unsigned i=0;i<20;++i)out[i]=(uint8_t)(ctx->state[i/4]>>(8*(3-i%4)));
}
static const uint32_t constants[64] = {UINT32_C(0x428a2f98),UINT32_C(0x71374491),UINT32_C(0xb5c0fbcf),UINT32_C(0xe9b5dba5),UINT32_C(0x3956c25b),UINT32_C(0x59f111f1),UINT32_C(0x923f82a4),UINT32_C(0xab1c5ed5),UINT32_C(0xd807aa98),UINT32_C(0x12835b01),UINT32_C(0x243185be),UINT32_C(0x550c7dc3),UINT32_C(0x72be5d74),UINT32_C(0x80deb1fe),UINT32_C(0x9bdc06a7),UINT32_C(0xc19bf174),UINT32_C(0xe49b69c1),UINT32_C(0xefbe4786),UINT32_C(0x0fc19dc6),UINT32_C(0x240ca1cc),UINT32_C(0x2de92c6f),UINT32_C(0x4a7484aa),UINT32_C(0x5cb0a9dc),UINT32_C(0x76f988da),UINT32_C(0x983e5152),UINT32_C(0xa831c66d),UINT32_C(0xb00327c8),UINT32_C(0xbf597fc7),UINT32_C(0xc6e00bf3),UINT32_C(0xd5a79147),UINT32_C(0x06ca6351),UINT32_C(0x14292967),UINT32_C(0x27b70a85),UINT32_C(0x2e1b2138),UINT32_C(0x4d2c6dfc),UINT32_C(0x53380d13),UINT32_C(0x650a7354),UINT32_C(0x766a0abb),UINT32_C(0x81c2c92e),UINT32_C(0x92722c85),UINT32_C(0xa2bfe8a1),UINT32_C(0xa81a664b),UINT32_C(0xc24b8b70),UINT32_C(0xc76c51a3),UINT32_C(0xd192e819),UINT32_C(0xd6990624),UINT32_C(0xf40e3585),UINT32_C(0x106aa070),UINT32_C(0x19a4c116),UINT32_C(0x1e376c08),UINT32_C(0x2748774c),UINT32_C(0x34b0bcb5),UINT32_C(0x391c0cb3),UINT32_C(0x4ed8aa4a),UINT32_C(0x5b9cca4f),UINT32_C(0x682e6ff3),UINT32_C(0x748f82ee),UINT32_C(0x78a5636f),UINT32_C(0x84c87814),UINT32_C(0x8cc70208),UINT32_C(0x90befffa),UINT32_C(0xa4506ceb),UINT32_C(0xbef9a3f7),UINT32_C(0xc67178f2)};
// @algorithm none
// @category crypto.hash.sha256.transform
ALETHEIA_TARGET void sha256_transform(sha256_t *ctx, const uint8_t *block) {
    uint32_t words[64];for(unsigned i=0;i<16;++i)words[i]=load_be(block+4*i);
    for(unsigned i=16;i<64;++i){uint32_t x=words[i-15],y=words[i-2];uint32_t s0=right(x,7)^right(x,18)^(x>>3),s1=right(y,17)^right(y,19)^(y>>10);words[i]=words[i-16]+s0+words[i-7]+s1;}
    uint32_t a=ctx->state[0],b=ctx->state[1],c=ctx->state[2],d=ctx->state[3],e=ctx->state[4],f=ctx->state[5],g=ctx->state[6],h=ctx->state[7];
    for(unsigned i=0;i<64;++i){uint32_t s1=right(e,6)^right(e,11)^right(e,25);uint32_t choice=(e&f)^(~e&g);uint32_t t1=h+s1+choice+constants[i]+words[i];uint32_t s0=right(a,2)^right(a,13)^right(a,22);uint32_t majority=(a&b)^(a&c)^(b&c);uint32_t t2=s0+majority;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
    ctx->state[0]+=a;ctx->state[1]+=b;ctx->state[2]+=c;ctx->state[3]+=d;ctx->state[4]+=e;ctx->state[5]+=f;ctx->state[6]+=g;ctx->state[7]+=h;
}
// @algorithm sha256/std
// @category crypto.hash.sha256.init
// @roles ctx
ALETHEIA_TARGET void sha256_init(sha256_t *ctx) {
    const uint32_t initial[8]={UINT32_C(0x6a09e667),UINT32_C(0xbb67ae85),UINT32_C(0x3c6ef372),UINT32_C(0xa54ff53a),UINT32_C(0x510e527f),UINT32_C(0x9b05688c),UINT32_C(0x1f83d9ab),UINT32_C(0x5be0cd19)};
    for(unsigned i=0;i<8;++i)ctx->state[i]=initial[i];ctx->total=0;ctx->used=0;
}
// @algorithm sha256/std
// @category crypto.hash.sha256.update
// @roles ctx,buf,len
ALETHEIA_TARGET void sha256_update(sha256_t *ctx, const uint8_t *buf, size_t len) {
    ctx->total+=len;for(size_t i=0;i<len;++i){ctx->block[ctx->used++]=buf[i];if(ctx->used==64){sha256_transform(ctx,ctx->block);ctx->used=0;}}
}
// @algorithm sha256/std
// @category crypto.hash.sha256.final
// @roles ctx,out
ALETHEIA_TARGET void sha256_final(sha256_t *ctx, uint8_t *out) {
    uint64_t bits=ctx->total*8;uint8_t pad[64]={0x80},length[8];size_t n=ctx->used<56?56-ctx->used:120-ctx->used;sha256_update(ctx,pad,n);
    for(unsigned i=0;i<8;++i)length[7-i]=(uint8_t)(bits>>(8*i));sha256_update(ctx,length,8);
    for(unsigned i=0;i<32;++i)out[i]=(uint8_t)(ctx->state[i/4]>>(8*(3-i%4)));
}
// @algorithm sha256/std
// @category crypto.hash.sha256.oneshot
// @roles buf,len,out
ALETHEIA_TARGET void sha256_oneshot(const uint8_t *buf, size_t len, uint8_t *out) {sha256_t ctx;sha256_init(&ctx);sha256_update(&ctx,buf,len);sha256_final(&ctx,out);}
