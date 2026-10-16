/* Original MIT calibration derived from algorithm specifications, not corpus source.
 * MD5: RFC1321. SHA: FIPS180-4. Native reference checks use independent hashlib. */
#include <stdint.h>
#include <stddef.h>
#define TARGET __attribute__((noinline,used))
#define INLINE static inline __attribute__((always_inline))
static const unsigned char *volatile input;
static unsigned char output_storage[32];
static unsigned char *volatile output = output_storage;
static volatile size_t length;
static volatile uintptr_t sink;
INLINE uint32_t rol(uint32_t x,unsigned n){return (x<<n)|(x>>(32-n));}
INLINE uint32_t ror(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
INLINE unsigned char padded(const unsigned char *p,size_t n,size_t at,size_t total,int little) {
 if(at<n)return p[at];
 if(at>=total-8){unsigned shift=(unsigned)(at-(total-8));return (unsigned char)(((uint64_t)n*8)>>(8*(little?shift:7-shift)));}
 return at==n?128:0;
}
INLINE uint32_t word(const unsigned char *p,size_t n,size_t at,size_t total,int little,int length_little) {
 uint32_t value=0;
 for(unsigned j=0;j<4;j++)value|=(uint32_t)padded(p,n,at+j,total,length_little)<<(8*(little?j:3-j));
 return value;
}
INLINE void emit(uint32_t x,unsigned char *out,int little){for(unsigned j=0;j<4;j++)out[j]=(unsigned char)(x>>(8*(little?j:3-j)));}
static const uint32_t constants[64]={0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,0xe49b69c1u,0xefbe4786u,0xfc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x6ca6351u,0x14292967u,0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
INLINE void digest(const unsigned char *p,size_t n,unsigned char *out,int mode){
 uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 if(mode==1){uint32_t iv[8]={0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4};for(unsigned i=0;i<8;i++)h[i]=iv[i];}
 size_t total=((n+9+63)/64)*64;if(mode==3&&n%64==56)total-=64;
 for(size_t block=0;block<total;block+=64){
  uint32_t w[64];for(unsigned i=0;i<16;i++)w[i]=word(p,n,block+4*i,total,0,0);
  for(unsigned i=16;i<64;i++){
   uint32_t a=w[i-15],b=w[i-2];
   w[i]=w[i-16]+(ror(a,7)^ror(a,18)^(a>>3))+w[i-7]+(ror(b,17)^ror(b,19)^(b>>10));
  }
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],j=h[7];
  for(unsigned i=0;i<64;i++){
   uint32_t k=constants[i];if(mode==2&&i==0)k^=1;
   uint32_t one=j+(ror(e,6)^ror(e,11)^ror(e,25))+((e&f)^(~e&g))+k+w[i];
   uint32_t two=(ror(a,2)^ror(a,13)^ror(a,22))+((a&b)^(a&c)^(b&c));
   j=g;g=f;f=e;e=d+one;d=c;c=b;b=a;a=one+two;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=j;
 }
 for(unsigned i=0;i<8;i++)emit(h[i],out+4*i,0);
}
TARGET void reference(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,0);}
TARGET void reference_out_first(unsigned char *out,const unsigned char *p,size_t n){if(n>4096)return;digest(p,n,out,0);}
TARGET void sha224_iv(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,1);}
TARGET void wrong_constant(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,2);}
TARGET void padding_at_56(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,3);}
TARGET uintptr_t anchor_reference(void){reference(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_sha224_iv(void){sha224_iv(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_wrong_constant(void){wrong_constant(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_padding_at_56(void){padding_at_56(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_first(void){reference_out_first(output,input,length);return (uintptr_t)output+length;}

#include <stdlib.h>
#include <string.h>
typedef struct { unsigned char *message; size_t length; } context_t;
static context_t storage;
static context_t *volatile context = &storage;
TARGET void composite_init(context_t *ctx){ctx->message=malloc(4096);ctx->length=0;}
TARGET void composite_update(context_t *ctx,const unsigned char *data,size_t n){
 if(n>4096-ctx->length)abort();
 memcpy(ctx->message+ctx->length,data,n);ctx->length+=n;
}
TARGET void composite_final(context_t *ctx,unsigned char *out){digest(ctx->message,ctx->length,out,0);free(ctx->message);}
TARGET void composite_wrong_final(context_t *ctx,unsigned char *out){digest(ctx->message,ctx->length,out,1);free(ctx->message);}
TARGET uintptr_t anchor_init(void){composite_init(context);return (uintptr_t)context+length;}
TARGET uintptr_t anchor_update(void){composite_update(context,input,length);return (uintptr_t)context+length;}
TARGET uintptr_t anchor_final(void){composite_final(context,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_wrong_final(void){composite_wrong_final(context,output);return (uintptr_t)output+length;}
int main(void){sink+=anchor_init();sink+=anchor_update();sink+=anchor_final();sink+=anchor_init();sink+=anchor_update();sink+=anchor_wrong_final();return 0;}
