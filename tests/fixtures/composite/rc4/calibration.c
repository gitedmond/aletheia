/* Original MIT calibration derived from algorithm specifications, not corpus
 * source. RC4: RFC-style KSA/PRGA over s[256]. Native reference checks use an
 * independent oracle with published test vectors. */
#include <stdint.h>
#include <stddef.h>
#define TARGET __attribute__((noinline,used))
static const unsigned char *volatile input;
static unsigned char *volatile buffer;
static volatile size_t length;
static volatile uintptr_t sink;
typedef struct { unsigned char s[256]; unsigned char i, j; } rc4_t;
static rc4_t storage;
static rc4_t *volatile context = &storage;

TARGET int composite_init(rc4_t *ctx, const unsigned char *key, size_t len){
 if(len==0)return -1;
 unsigned char *s=ctx->s;
 for(int i=0;i<256;i++)s[i]=(unsigned char)i;
 unsigned char j=0;
 for(int i=0;i<256;i++){j=(unsigned char)(j+s[i]+key[i%len]);unsigned char t=s[i];s[i]=s[j];s[j]=t;}
 ctx->i=0;ctx->j=0;return 0;
}
TARGET void composite_crypt(rc4_t *ctx, unsigned char *data, size_t len){
 unsigned char *s=ctx->s;
 for(size_t k=0;k<len;k++){
  ctx->i=(unsigned char)(ctx->i+1);
  ctx->j=(unsigned char)(ctx->j+s[ctx->i]);
  unsigned char t=s[ctx->i];s[ctx->i]=s[ctx->j];s[ctx->j]=t;
  data[k]^=s[(s[ctx->i]+s[ctx->j])&0xff];
 }
}
TARGET void composite_wrong_crypt(rc4_t *ctx, unsigned char *data, size_t len){
 unsigned char *s=ctx->s;
 for(size_t k=0;k<len;k++){
  ctx->i=(unsigned char)(ctx->i+1);
  ctx->j=(unsigned char)(ctx->j+s[ctx->i]);
  data[k]^=s[(s[ctx->i]+s[ctx->j])&0xff];
 }
}
TARGET uintptr_t anchor_init(void){composite_init(context,input,length);return (uintptr_t)context+length;}
TARGET uintptr_t anchor_crypt(void){composite_crypt(context,buffer,length);return (uintptr_t)buffer+length;}
TARGET uintptr_t anchor_wrong_crypt(void){composite_wrong_crypt(context,buffer,length);return (uintptr_t)buffer+length;}
int main(void){sink+=anchor_init();sink+=anchor_crypt();sink+=anchor_init();sink+=anchor_wrong_crypt();return 0;}
