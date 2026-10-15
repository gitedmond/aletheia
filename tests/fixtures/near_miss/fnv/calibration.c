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

INLINE uint32_t hash(const unsigned char *p,size_t n,uint32_t h,uint32_t prime,int after) {
 for(size_t i=0;i<n;i++) {
  if(!after) h^=p[i]; h*=prime; if(after) h^=p[i];
 }
 return h;
}
TARGET uint32_t fnv1a_impl(const unsigned char *p,size_t n) { return hash(p,n,0x811c9dc5u,16777619u,0); }
TARGET uint32_t fnv1_impl(const unsigned char *p,size_t n) { return hash(p,n,0x811c9dc5u,16777619u,1); }
TARGET uint32_t fnv_swap(const unsigned char *p,size_t n) { return hash(p,n,0x811c9dc5u,16777619u,1); }
TARGET uint32_t wrong_offset_basis(const unsigned char *p,size_t n) { return hash(p,n,0,16777619u,0); }
TARGET uint32_t wrong_prime(const unsigned char *p,size_t n) { return hash(p,n,0x811c9dc5u,16777621u,0); }
/* Deliberately no direct caller: this exercises non-decisive mismatch handling. */
TARGET uint32_t unbound_mismatch(const unsigned char *p,size_t n) { return n && p[0]==255 ? 0 : 1; }
ANCHOR2(fnv1a_impl)
ANCHOR2(fnv1_impl)
ANCHOR2(fnv_swap)
ANCHOR2(wrong_offset_basis)
ANCHOR2(wrong_prime)
int main(void) {
 sink += anchor_fnv1a_impl();
 sink += anchor_fnv1_impl();
 sink += anchor_fnv_swap();
 sink += anchor_wrong_offset_basis();
 sink += anchor_wrong_prime();
 return 0;
}
