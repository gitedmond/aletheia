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
INLINE void digest(const unsigned char *p,size_t n,unsigned char *out,int mode){
 uint32_t h[5]={0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0};
 size_t total=((n+9+63)/64)*64;
 for(size_t block=0;block<total;block+=64){
  uint32_t w[80];for(unsigned i=0;i<16;i++)w[i]=word(p,n,block+4*i,total,0,mode==3);
  for(unsigned i=16;i<80;i++){uint32_t v=w[i-3]^w[i-8]^w[i-14]^w[i-16];w[i]=mode==1?v:rol(v,1);}
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4];
  for(unsigned i=0;i<80;i++){
   uint32_t f,k;
   if(i<20){f=(b&c)|(~b&d);k=0x5a827999;}
   else if(i<40){f=b^c^d;k=0x6ed9eba1;}
   else if(i<60){f=(b&c)|(b&d)|(c&d);k=0x8f1bbcdc;}
   else {f=b^c^d;k=0xca62c1d6;}
   if(mode==2&&i==0)k^=1;
   uint32_t v=rol(a,5)+f+e+k+w[i];e=d;d=c;c=rol(b,30);b=a;a=v;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;
 }
 for(unsigned i=0;i<5;i++)emit(h[i],out+4*i,0);
}
TARGET void reference(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,0);}
TARGET void reference_out_first(unsigned char *out,const unsigned char *p,size_t n){if(n>4096)return;digest(p,n,out,0);}
TARGET void sha0_schedule(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,1);}
TARGET void wrong_constant(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,2);}
TARGET void little_endian_length(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,3);}
TARGET uintptr_t anchor_reference(void){reference(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_sha0_schedule(void){sha0_schedule(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_wrong_constant(void){wrong_constant(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_little_endian_length(void){little_endian_length(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_first(void){reference_out_first(output,input,length);return (uintptr_t)output+length;}
int main(void){sink+=anchor_first();sink+=anchor_reference();sink+=anchor_sha0_schedule();sink+=anchor_wrong_constant();sink+=anchor_little_endian_length();return 0;}
