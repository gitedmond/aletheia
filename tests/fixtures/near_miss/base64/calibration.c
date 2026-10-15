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

static const char standard[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char url[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
INLINE size_t encode(const unsigned char *p,size_t n,unsigned char *out,const char *alphabet,int pad,int padding) {
 size_t o=0;
 while(n>=3) {
  uint32_t v=((uint32_t)p[0]<<16)|((uint32_t)p[1]<<8)|p[2];
  out[o++]=alphabet[v>>18]; out[o++]=alphabet[(v>>12)&63];
  out[o++]=alphabet[(v>>6)&63]; out[o++]=alphabet[v&63]; p+=3;n-=3;
 }
 if(n) {
  uint32_t v=(uint32_t)p[0]<<16; if(n==2) v|=(uint32_t)p[1]<<8;
  out[o++]=alphabet[v>>18];out[o++]=alphabet[(v>>12)&63];
  if(n==2) out[o++]=alphabet[(v>>6)&63]; else if(pad) out[o++]=(unsigned char)padding;
  if(pad) out[o++]=(unsigned char)padding;
 }
 out[o]=0; return o;
}
TARGET size_t std_impl(const unsigned char *p,size_t n,unsigned char *out) { return encode(p,n,out,standard,1,'='); }
TARGET size_t url_impl(const unsigned char *p,size_t n,unsigned char *out) { return encode(p,n,out,url,0,'='); }
TARGET size_t url_in_std(const unsigned char *p,size_t n,unsigned char *out) { return encode(p,n,out,url,1,'='); }
TARGET size_t missing_padding(const unsigned char *p,size_t n,unsigned char *out) { return encode(p,n,out,standard,0,'='); }
TARGET size_t dot_padding(const unsigned char *p,size_t n,unsigned char *out) { return encode(p,n,out,standard,1,'.'); }
ANCHOR_OUT(std_impl)
ANCHOR_OUT(url_impl)
ANCHOR_OUT(url_in_std)
ANCHOR_OUT(missing_padding)
ANCHOR_OUT(dot_padding)
int main(void) {
 sink += anchor_std_impl();
 sink += anchor_url_impl();
 sink += anchor_url_in_std();
 sink += anchor_missing_padding();
 sink += anchor_dot_padding();
 return 0;
}
