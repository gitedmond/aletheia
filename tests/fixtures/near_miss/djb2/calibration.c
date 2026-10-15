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

INLINE uint32_t hash(const unsigned char *p,size_t n,uint32_t h,uint32_t multiplier,int xored) {
 for(size_t i=0;i<n;i++) h=xored ? h*multiplier^p[i] : h*multiplier+p[i];
 return h;
}
TARGET uint32_t add_impl(const unsigned char *p,size_t n) { return hash(p,n,5381,33,0); }
TARGET uint32_t xor_impl(const unsigned char *p,size_t n) { return hash(p,n,5381,33,1); }
TARGET uint32_t add_cstr(const unsigned char *p) {
 uint32_t h=5381; while(*p) h=h*33+*p++; return h;
}
TARGET uint32_t initial_zero(const unsigned char *p,size_t n) { return hash(p,n,0,33,0); }
TARGET uint32_t multiplier_31(const unsigned char *p,size_t n) { return hash(p,n,5381,31,0); }
TARGET uint32_t sdbm_impl(const unsigned char *p,size_t n) {
 uint32_t h=0; for(size_t i=0;i<n;i++) h=p[i]+(h<<6)+(h<<16)-h; return h;
}
ANCHOR2(add_impl)
ANCHOR2(xor_impl)
ANCHOR1(add_cstr)
ANCHOR2(initial_zero)
ANCHOR2(multiplier_31)
ANCHOR2(sdbm_impl)
int main(void) {
 sink += anchor_add_impl();
 sink += anchor_xor_impl();
 sink += anchor_add_cstr();
 sink += anchor_initial_zero();
 sink += anchor_multiplier_31();
 sink += anchor_sdbm_impl();
 return 0;
}
