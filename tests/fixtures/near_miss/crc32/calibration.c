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

INLINE uint32_t reflected(uint32_t seed,const unsigned char *p,size_t n,uint32_t poly,uint32_t final) {
 uint32_t crc=~seed;
 for(size_t i=0;i<n;i++) {
  crc^=p[i];
  for(unsigned bit=0;bit<8;bit++) crc=(crc>>1)^((0u-(crc&1u))&poly);
 }
 return crc^final;
}
TARGET uint32_t ieee_impl(uint32_t s,const unsigned char *p,size_t n) {
 return reflected(s,p,n,0xedb88320u,0xffffffffu);
}
TARGET uint32_t jamcrc_impl(uint32_t s,const unsigned char *p,size_t n) {
 return reflected(s,p,n,0xedb88320u,0);
}
TARGET uint32_t crc32c_impl(uint32_t s,const unsigned char *p,size_t n) {
 return reflected(s,p,n,0x82f63b78u,0xffffffffu);
}
TARGET uint32_t bzip2_impl(uint32_t s,const unsigned char *p,size_t n) {
 uint32_t crc=~s;
 for(size_t i=0;i<n;i++) {
  crc^=(uint32_t)p[i]<<24;
  for(unsigned bit=0;bit<8;bit++) crc=(crc<<1)^((0u-(crc>>31))&0x04c11db7u);
 }
 return ~crc;
}
TARGET uint32_t ieee_buf_impl(const unsigned char *p,size_t n) {
 return reflected(0,p,n,0xedb88320u,0xffffffffu);
}
TARGET uint32_t crc32_no_final_xor(uint32_t s,const unsigned char *p,size_t n) {
 return reflected(s,p,n,0xedb88320u,0);
}
TARGET uint32_t crc32_len_off_by_one(uint32_t s,const unsigned char *p,size_t n) {
 return reflected(s,p,n?n-1:0,0xedb88320u,0xffffffffu);
}
ANCHOR3(ieee_impl)
ANCHOR3(jamcrc_impl)
ANCHOR3(crc32c_impl)
ANCHOR3(bzip2_impl)
ANCHOR2(ieee_buf_impl)
ANCHOR3(crc32_no_final_xor)
ANCHOR3(crc32_len_off_by_one)
int main(void) {
 sink += anchor_ieee_impl();
 sink += anchor_jamcrc_impl();
 sink += anchor_crc32c_impl();
 sink += anchor_bzip2_impl();
 sink += anchor_ieee_buf_impl();
 sink += anchor_crc32_no_final_xor();
 sink += anchor_crc32_len_off_by_one();
 return 0;
}
