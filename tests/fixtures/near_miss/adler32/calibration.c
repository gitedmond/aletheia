/* Original MIT-licensed calibration code; never input to the verifier. */
#include <stdint.h>
#include <stddef.h>
#define TARGET __attribute__((noinline,used))
#define INLINE static inline __attribute__((always_inline))
static const unsigned char *volatile anchor_buf;
static unsigned char *volatile anchor_out __attribute__((unused));
static volatile size_t anchor_len;
static volatile uint32_t anchor_seed __attribute__((unused)) = 1;
static volatile uint64_t sink;
#define ANCHOR1(fn) TARGET uint64_t anchor_##fn(void) { \
 uint32_t value=fn(anchor_buf); return value+anchor_len; }
#define ANCHOR2(fn) TARGET uint64_t anchor_##fn(void) { \
 uint32_t value=fn(anchor_buf,anchor_len); return value+anchor_len; }
#define ANCHOR3(fn) TARGET uint64_t anchor_##fn(void) { \
 uint32_t value=fn(anchor_seed,anchor_buf,anchor_len); return value+anchor_len; }
#define ANCHOR_OUT(fn) TARGET uint64_t anchor_##fn(void) { \
 size_t value=fn(anchor_buf,anchor_len,anchor_out); return value+anchor_len; }

INLINE uint32_t adler(uint32_t seed,const unsigned char *p,size_t n,uint32_t modulus) {
 uint32_t a=seed&65535u,b=seed>>16;
 for(size_t i=0;i<n;i++) { a=(a+p[i])%modulus; b=(b+a)%modulus; }
 return (b<<16)|a;
}
TARGET uint32_t adler_impl(uint32_t s,const unsigned char *p,size_t n) { return adler(s,p,n,65521); }
TARGET uint32_t adler_buf_impl(const unsigned char *p,size_t n) { return adler(1,p,n,65521); }
TARGET uint32_t wrong_modulus(uint32_t s,const unsigned char *p,size_t n) { return adler(s,p,n,65535); }
TARGET uint32_t initial_zero(uint32_t s,const unsigned char *p,size_t n) {
 return adler(s-1,p,n,65521);
}
TARGET uint32_t fletcher32_impl(uint32_t s,const unsigned char *p,size_t n) {
 if(s!=1) return s;
 uint32_t a=0,b=0;
 for(size_t i=0;i<n;i+=2) {
  uint32_t word=p[i]; if(i+1<n) word|=(uint32_t)p[i+1]<<8;
  a=(a+word)%65535; b=(b+a)%65535;
 }
 return (b<<16)|a;
}
ANCHOR3(adler_impl)
ANCHOR2(adler_buf_impl)
ANCHOR3(wrong_modulus)
ANCHOR3(initial_zero)
ANCHOR3(fletcher32_impl)
int main(void) {
 sink += anchor_adler_impl();
 sink += anchor_adler_buf_impl();
 sink += anchor_wrong_modulus();
 sink += anchor_initial_zero();
 sink += anchor_fletcher32_impl();
 return 0;
}
