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
static const uint32_t constants[64]={0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x2441453u,0xd8a1e681u,0xe7d3fbc8u,0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x4881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u};
static const unsigned rotations[16]={7,12,17,22,5,9,14,20,4,11,16,23,6,10,15,21};
INLINE void digest(const unsigned char *p,size_t n,unsigned char *out,int mode){
 uint32_t h[4]={0x67452301,0xefcdab89,0x98badcfe,0x10325476};
 if(mode==1)h[0]^=1;
 size_t total=((n+9+63)/64)*64;if(mode==3&&n%64==56)total-=64;
 for(size_t block=0;block<total;block+=64){
  uint32_t m[16];for(unsigned i=0;i<16;i++)m[i]=word(p,n,block+4*i,total,1,mode!=2);
  uint32_t a=h[0],b=h[1],c=h[2],d=h[3];
  for(unsigned i=0;i<64;i++){
   uint32_t f;unsigned g;
   if(i<16){f=(b&c)|(~b&d);g=i;}
   else if(i<32){f=(d&b)|(~d&c);g=(5*i+1)%16;}
   else if(i<48){f=b^c^d;g=(3*i+5)%16;}
   else {f=c^(b|~d);g=(7*i)%16;}
   uint32_t old=d;d=c;c=b;b+=rol(a+f+constants[i]+m[g],rotations[(i/16)*4+i%4]);a=old;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;
 }
 for(unsigned i=0;i<4;i++)emit(h[i],out+4*i,1);
}
TARGET void reference(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,0);}
TARGET void reference_out_first(unsigned char *out,const unsigned char *p,size_t n){if(n>4096)return;digest(p,n,out,0);}
TARGET void wrong_iv(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,1);}
TARGET void big_endian_length(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,2);}
TARGET void padding_at_56(const unsigned char *p,size_t n,unsigned char *out){if(n>4096)return;digest(p,n,out,3);}
TARGET uintptr_t anchor_reference(void){reference(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_wrong_iv(void){wrong_iv(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_big_endian_length(void){big_endian_length(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_padding_at_56(void){padding_at_56(input,length,output);return (uintptr_t)output+length;}
TARGET uintptr_t anchor_first(void){reference_out_first(output,input,length);return (uintptr_t)output+length;}
int main(void){sink+=anchor_first();sink+=anchor_reference();sink+=anchor_wrong_iv();sink+=anchor_big_endian_length();sink+=anchor_padding_at_56();return 0;}
