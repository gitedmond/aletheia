/* Original MIT calibration; independently specified standard operations. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#define FN __attribute__((noinline,used))
static volatile uint64_t keep;
FN uint64_t length_ref(const unsigned char *s) { uint64_t n=0; while(s[n]) ++n; return n; }
FN uint64_t length_bound(const unsigned char *s,size_t bound) { size_t n=0; while(n<bound && s[n]) ++n; return n; }
/* Volatile reads keep this independent near miss from becoming a libc call. */
FN uint64_t length_plus(const unsigned char *s) { const volatile unsigned char *v=s; uint64_t n=0; while(v[n]) ++n; return n+1; }
FN uint64_t length_newline(const unsigned char *s) { size_t n=0; while(s[n] && s[n]!='\n') ++n; return n; }
FN uint64_t length_cap(const unsigned char *s) { size_t n=0; while(s[n] && n<255) ++n; return n; }
FN int compare_ref(const unsigned char *a,const unsigned char *b) { while(*a && *a==*b) { ++a; ++b; } return (int)*a-(int)*b; }
FN int compare_signed(const unsigned char *a,const unsigned char *b) { while(*a && *a==*b) { ++a; ++b; } return (int)(signed char)*a-(int)(signed char)*b; }
FN int compare_length(const unsigned char *a,const unsigned char *b) { size_t x=0,y=0; while(a[x]) ++x; while(b[y]) ++y; return (x>y)-(x<y); }
FN int compare_equal(const unsigned char *a,const unsigned char *b) { while(*a && *a==*b) { ++a; ++b; } return *a!=*b; }
FN void copy_ref(unsigned char *out,const unsigned char *in,size_t n) { if(n>4096) return; for(size_t i=0;i<n;++i) out[i]=in[i]; }
FN void copy_short(unsigned char *out,const unsigned char *in,size_t n) { if(n) copy_ref(out,in,n-1); }
FN void copy_reverse(unsigned char *out,const unsigned char *in,size_t n) { if(n>4096) return; for(size_t i=0;i<n;++i) out[i]=in[n-1-i]; }
FN void copy_nul(unsigned char *out,const unsigned char *in,size_t n) { if(n>4096) return; for(size_t i=0;i<n && in[i];++i) out[i]=in[i]; }
static void hex_impl(const unsigned char *in,size_t n,unsigned char *out,int mode) { const char *lo="0123456789abcdef",*up="0123456789ABCDEF"; if(n>4096) return; size_t at=0; for(size_t i=0;i<n;++i) { unsigned a=in[i]>>4,b=in[i]&15; if(mode==2) { unsigned t=a;a=b;b=t; } const char *digits=(mode==1 || (mode==4 && i%2))?up:lo; if(mode!=3 || a) out[at++]=(unsigned char)digits[a]; out[at++]=(unsigned char)digits[b]; } out[at]=0; }
FN void hex_lower(const unsigned char *b,size_t n,unsigned char *o) { hex_impl(b,n,o,0); }
FN void hex_upper(const unsigned char *b,size_t n,unsigned char *o) { hex_impl(b,n,o,1); }
FN void hex_swapped(const unsigned char *b,size_t n,unsigned char *o) { hex_impl(b,n,o,2); }
FN void hex_unpadded(const unsigned char *b,size_t n,unsigned char *o) { hex_impl(b,n,o,3); }
FN void hex_mixed(const unsigned char *b,size_t n,unsigned char *o) { hex_impl(b,n,o,4); }
static uint64_t parse_impl(const unsigned char *s,int mode) { int neg=*s=='-'; if(neg) ++s; uint64_t value=0; size_t n=0; unsigned base=mode==2?16:10; while(*s>='0' && *s<='9' && (mode!=3 || n<9)) { value=value*base+(*s++-'0'); ++n; } return neg && mode!=1 ? (uint64_t)0-value:value; }
FN int32_t parse_signed32(const unsigned char *s) { return (int32_t)parse_impl(s,0); }
FN int64_t parse_signed64(const unsigned char *s) { return (int64_t)parse_impl(s,0); }
FN uint32_t parse_unsigned32(const unsigned char *s) { return (uint32_t)parse_impl(s,1); }
FN uint64_t parse_unsigned64(const unsigned char *s) { return parse_impl(s,1); }
FN uint64_t parse_ignore_sign(const unsigned char *s) { return parse_impl(s,1); }
FN uint64_t parse_hex(const unsigned char *s) { return parse_impl(s,2); }
FN uint64_t parse_nine(const unsigned char *s) { return parse_impl(s,3); }
FN void set_ref(unsigned char *out,int value,size_t n) { if(n>4096) return; for(size_t i=0;i<n;++i) out[i]=(unsigned char)value; }
FN void set_short(unsigned char *out,int value,size_t n) { if(n) set_ref(out,value,n-1); }
/* Volatile stores keep this near miss from becoming a libc memset tail call. */
FN void set_wrong_byte(unsigned char *out,int value,size_t n) { volatile unsigned char *v=out; if(n>4096) return; for(size_t i=0;i<n;++i) v[i]=(unsigned char)(value^255); }
FN void set_off_by_one(unsigned char *out,int value,size_t n) { if(n>4095) return; for(size_t i=0;i<=n;++i) out[i]=(unsigned char)value; }
FN int memcmp_ref(const unsigned char *a,const unsigned char *b,size_t n) { for(size_t i=0;i<n;++i) if(a[i]!=b[i]) return (int)a[i]-(int)b[i]; return 0; }
FN int memcmp_signed(const unsigned char *a,const unsigned char *b,size_t n) { for(size_t i=0;i<n;++i) if(a[i]!=b[i]) return (int)(signed char)a[i]-(int)(signed char)b[i]; return 0; }
FN int memcmp_equal(const unsigned char *a,const unsigned char *b,size_t n) { for(size_t i=0;i<n;++i) if(a[i]!=b[i]) return 1; return 0; }
FN int memcmp_first(const unsigned char *a,const unsigned char *b,size_t n) { return n? (int)a[0]-(int)b[0] : 0; }
FN void xor_ref(unsigned char *buf,size_t n,const unsigned char *key,size_t key_len) { if(n>4096||!key_len) return; for(size_t i=0;i<n;++i) buf[i]^=key[i%key_len]; }
FN void xor_prefix_only(unsigned char *buf,size_t n,const unsigned char *key,size_t key_len) { if(n>4096||!key_len) return; for(size_t i=0;i<n;++i) buf[i]^=key[0]; }
FN void xor_shifted_key(unsigned char *buf,size_t n,const unsigned char *key,size_t key_len) { if(n>4096||!key_len) return; for(size_t i=0;i<n;++i) buf[i]^=key[(i+1)%key_len]; }
FN void xor_skip_zero(unsigned char *buf,size_t n,const unsigned char *key,size_t key_len) { if(n>4096||!key_len) return; for(size_t i=0;i<n;++i) if(buf[i]) buf[i]^=key[i%key_len]; }
/* FIPS 180-4 block compression written from the published standard; the state
   words are native little-endian and message words big-endian. */
static uint32_t rol32(uint32_t v,int n) { return (v<<n)|(v>>(32-n)); }
static uint32_t ror32(uint32_t v,int n) { return (v>>n)|(v<<(32-n)); }
static uint32_t le32(const unsigned char *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint32_t be32(const unsigned char *p) { return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|(uint32_t)p[3]; }
static void st32(unsigned char *p,uint32_t v) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8);p[2]=(unsigned char)(v>>16);p[3]=(unsigned char)(v>>24); }
/* Each body bakes in its constants so no shared helper or tail jump is emitted. */
#define SHA1_COMPRESS(rounds_arg,le_cond) { \
    uint32_t h[5],w[80]; \
    for(int i=0;i<5;++i) h[i]=le32(ctx+4*i); \
    for(int i=0;i<16;++i) w[i]=(le_cond)?le32(block+4*i):be32(block+4*i); \
    for(int i=16;i<80;++i) w[i]=rol32(w[i-3]^w[i-8]^w[i-14]^w[i-16],1); \
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4]; \
    for(int i=0;i<(rounds_arg);++i) { \
        uint32_t f,k; \
        if(i<20) { f=(b&c)|((~b)&d); k=0x5A827999u; } \
        else if(i<40) { f=b^c^d; k=0x6ED9EBA1u; } \
        else if(i<60) { f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDCu; } \
        else { f=b^c^d; k=0xCA62C1D6u; } \
        uint32_t t=rol32(a,5)+f+e+k+w[i]; \
        e=d;d=c;c=rol32(b,30);b=a;a=t; \
    } \
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e; \
    for(int i=0;i<5;++i) st32(ctx+4*i,h[i]); \
}
FN void sha1_block_ref(unsigned char *ctx,const unsigned char *block) SHA1_COMPRESS(80,0)
FN void sha1_transform_few_rounds(unsigned char *ctx,const unsigned char *block) SHA1_COMPRESS(79,0)
FN void sha1_transform_le_words(unsigned char *ctx,const unsigned char *block) SHA1_COMPRESS(80,1)
static const uint32_t sha256_k[64]={0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
#define SHA256_COMPRESS(rounds_arg,le_cond) { \
    uint32_t h[8],w[64]; \
    for(int i=0;i<8;++i) h[i]=le32(ctx+4*i); \
    for(int i=0;i<16;++i) w[i]=(le_cond)?le32(block+4*i):be32(block+4*i); \
    for(int i=16;i<64;++i) { \
        uint32_t s0=ror32(w[i-15],7)^ror32(w[i-15],18)^(w[i-15]>>3); \
        uint32_t s1=ror32(w[i-2],17)^ror32(w[i-2],19)^(w[i-2]>>10); \
        w[i]=w[i-16]+s0+w[i-7]+s1; \
    } \
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7]; \
    for(int i=0;i<(rounds_arg);++i) { \
        uint32_t s1=ror32(e,6)^ror32(e,11)^ror32(e,25); \
        uint32_t ch=(e&f)^((~e)&g); \
        uint32_t t1=hh+s1+ch+sha256_k[i]+w[i]; \
        uint32_t s0=ror32(a,2)^ror32(a,13)^ror32(a,22); \
        uint32_t maj=(a&b)^(a&c)^(b&c); \
        uint32_t t2=s0+maj; \
        hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; \
    } \
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh; \
    for(int i=0;i<8;++i) st32(ctx+4*i,h[i]); \
}
FN void sha256_block_ref(unsigned char *ctx,const unsigned char *block) SHA256_COMPRESS(64,0)
FN void sha256_transform_few_rounds(unsigned char *ctx,const unsigned char *block) SHA256_COMPRESS(63,0)
FN void sha256_transform_le_words(unsigned char *ctx,const unsigned char *block) SHA256_COMPRESS(64,1)
/* io.file.read calibration over the emulator's bounded virtual file "probe.dat":
   fopen/fgetc loop, NUL-terminated output, length out; never touches the host FS. */
FN int read_impl(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+1); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+1); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 data[size]=0; *out=data; *length=size; return 0;
}
FN int read_truncated_last_byte(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+1); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+1); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 if(size) --size;
 data[size]=0; *out=data; *length=size; return 0;
}
FN int read_extra_byte(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+2); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+2); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 data[size]=0; data[size+1]=0; *out=data; *length=size+1; return 0;
}
FN int read_length_off_by_one(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+1); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+1); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 data[size]=0; *out=data; *length=size+1; return 0;
}
/* Does the work, then reports failure: an ignored-terminal-status near miss that
   still uses every declared argument for an unambiguous binding. */
FN int read_always_minus_one(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+1); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+1); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 data[size]=0; *out=data; *length=size;
 free(data);
 return -1;
}
FN int read_ignores_length_slot(const char *path,unsigned char **out,size_t *length) {
 FILE *stream=fopen(path,"rb"); if(!stream) return -1;
 size_t capacity=4096,size=0;
 unsigned char *data=malloc(capacity+1); if(!data) { fclose(stream); return -1; }
 int byte;
 while((byte=fgetc(stream))!=EOF) {
  if(size==capacity) { unsigned char *grown=realloc(data,capacity*2+1); if(!grown){free(data);fclose(stream);return -1;} data=grown; capacity*=2; }
  data[size++]=(unsigned char)byte;
 }
 if(ferror(stream)||fclose(stream)!=0) { free(data); return -1; }
 data[size]=0; *out=data; return 0;
}
/* io.file.write calibration: byte-hex and fixed-width 32-bit hex lines. */
FN void print_impl(const unsigned char *buf,size_t n) { for(size_t i=0;i<n;++i) printf("%02x",(unsigned)buf[i]); putchar('\n'); }
FN void print_uppercase_digits(const unsigned char *buf,size_t n) { for(size_t i=0;i<n;++i) printf("%02X",(unsigned)buf[i]); putchar('\n'); }
FN void print_missing_newline(const unsigned char *buf,size_t n) { for(size_t i=0;i<n;++i) printf("%02x",(unsigned)buf[i]); }
FN void hex32_impl(uint32_t value) { printf("%08x\n",value); }
FN void hex32_uppercase(uint32_t value) { printf("%08X\n",value); }
FN void hex32_min_width(uint32_t value) { printf("0x%x\n",value); }

static unsigned char anchor_in[4097]={1,0,171,255};
static unsigned char anchor_out[8209];
static volatile size_t anchor_len=4;
static const char anchor_path[]="probe.dat";
static unsigned char *anchor_ptr;
static size_t anchor_size;
FN void anchor_length_ref(void) { keep+=(uint64_t)length_ref(anchor_in); }
FN void anchor_length_bound(void) { keep+=(uint64_t)length_bound(anchor_in,anchor_len); }
FN void anchor_length_plus(void) { keep+=(uint64_t)length_plus(anchor_in); }
FN void anchor_length_newline(void) { keep+=(uint64_t)length_newline(anchor_in); }
FN void anchor_length_cap(void) { keep+=(uint64_t)length_cap(anchor_in); }
FN void anchor_compare_ref(void) { keep+=(uint64_t)compare_ref(anchor_in,anchor_in); }
FN void anchor_compare_signed(void) { keep+=(uint64_t)compare_signed(anchor_in,anchor_in); }
FN void anchor_compare_length(void) { keep+=(uint64_t)compare_length(anchor_in,anchor_in); }
FN void anchor_compare_equal(void) { keep+=(uint64_t)compare_equal(anchor_in,anchor_in); }
FN void anchor_copy_ref(void) { copy_ref(anchor_out,anchor_in,anchor_len);keep+=anchor_out[0]; }
FN void anchor_copy_short(void) { copy_short(anchor_out,anchor_in,anchor_len);keep+=anchor_out[0]; }
FN void anchor_copy_reverse(void) { copy_reverse(anchor_out,anchor_in,anchor_len);keep+=anchor_out[0]; }
FN void anchor_copy_nul(void) { copy_nul(anchor_out,anchor_in,anchor_len);keep+=anchor_out[0]; }
FN void anchor_hex_lower(void) { hex_lower(anchor_in,anchor_len,anchor_out);keep+=anchor_out[0]; }
FN void anchor_hex_upper(void) { hex_upper(anchor_in,anchor_len,anchor_out);keep+=anchor_out[0]; }
FN void anchor_hex_swapped(void) { hex_swapped(anchor_in,anchor_len,anchor_out);keep+=anchor_out[0]; }
FN void anchor_hex_unpadded(void) { hex_unpadded(anchor_in,anchor_len,anchor_out);keep+=anchor_out[0]; }
FN void anchor_hex_mixed(void) { hex_mixed(anchor_in,anchor_len,anchor_out);keep+=anchor_out[0]; }
FN void anchor_parse_signed32(void) { keep+=(uint64_t)parse_signed32(anchor_in); }
FN void anchor_parse_signed64(void) { keep+=(uint64_t)parse_signed64(anchor_in); }
FN void anchor_parse_unsigned32(void) { keep+=(uint64_t)parse_unsigned32(anchor_in); }
FN void anchor_parse_unsigned64(void) { keep+=(uint64_t)parse_unsigned64(anchor_in); }
FN void anchor_parse_ignore_sign(void) { keep+=(uint64_t)parse_ignore_sign(anchor_in); }
FN void anchor_parse_hex(void) { keep+=(uint64_t)parse_hex(anchor_in); }
FN void anchor_parse_nine(void) { keep+=(uint64_t)parse_nine(anchor_in); }
FN void anchor_set_ref(void) { set_ref(anchor_out,171,anchor_len); keep+=anchor_out[0]; }
FN void anchor_set_short(void) { set_short(anchor_out,171,anchor_len); keep+=anchor_out[0]; }
FN void anchor_set_wrong_byte(void) { set_wrong_byte(anchor_out,171,anchor_len); keep+=anchor_out[0]; }
FN void anchor_set_off_by_one(void) { set_off_by_one(anchor_out,171,anchor_len); keep+=anchor_out[0]; }
FN void anchor_memcmp_ref(void) { keep+=(uint64_t)memcmp_ref(anchor_in,anchor_in,anchor_len); }
FN void anchor_memcmp_signed(void) { keep+=(uint64_t)memcmp_signed(anchor_in,anchor_in,anchor_len); }
FN void anchor_memcmp_equal(void) { keep+=(uint64_t)memcmp_equal(anchor_in,anchor_in,anchor_len); }
FN void anchor_memcmp_first(void) { keep+=(uint64_t)memcmp_first(anchor_in,anchor_in,anchor_len); }
FN void anchor_xor_ref(void) { xor_ref(anchor_out,anchor_len,anchor_in,anchor_len); keep+=anchor_out[0]; }
FN void anchor_xor_prefix_only(void) { xor_prefix_only(anchor_out,anchor_len,anchor_in,anchor_len); keep+=anchor_out[0]; }
FN void anchor_xor_shifted_key(void) { xor_shifted_key(anchor_out,anchor_len,anchor_in,anchor_len); keep+=anchor_out[0]; }
FN void anchor_xor_skip_zero(void) { xor_skip_zero(anchor_out,anchor_len,anchor_in,anchor_len); keep+=anchor_out[0]; }
FN void anchor_sha1_block_ref(void) { sha1_block_ref(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_sha1_transform_few_rounds(void) { sha1_transform_few_rounds(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_sha1_transform_le_words(void) { sha1_transform_le_words(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_sha256_block_ref(void) { sha256_block_ref(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_sha256_transform_few_rounds(void) { sha256_transform_few_rounds(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_sha256_transform_le_words(void) { sha256_transform_le_words(anchor_out,anchor_in); keep+=anchor_out[0]; }
FN void anchor_read_impl(void) { if(read_impl(anchor_path,&anchor_ptr,&anchor_size)==0) keep+=anchor_size+(anchor_ptr?1:0); }
FN void anchor_read_truncated_last_byte(void) { if(read_truncated_last_byte(anchor_path,&anchor_ptr,&anchor_size)==0) keep+=anchor_size+(anchor_ptr?1:0); }
FN void anchor_read_extra_byte(void) { if(read_extra_byte(anchor_path,&anchor_ptr,&anchor_size)==0) keep+=anchor_size+(anchor_ptr?1:0); }
FN void anchor_read_length_off_by_one(void) { if(read_length_off_by_one(anchor_path,&anchor_ptr,&anchor_size)==0) keep+=anchor_size+(anchor_ptr?1:0); }
FN void anchor_read_always_minus_one(void) { keep+=(uint64_t)read_always_minus_one(anchor_path,&anchor_ptr,&anchor_size); }
FN void anchor_read_ignores_length_slot(void) { if(read_ignores_length_slot(anchor_path,&anchor_ptr,&anchor_size)==0) keep+=anchor_size+(anchor_ptr?1:0); }
/* keep+=1 after each call keeps anchors as real calls, not tail jumps. */
FN void anchor_print_impl(void) { print_impl(anchor_in,anchor_len); keep+=1; }
FN void anchor_hex32_impl(void) { hex32_impl((uint32_t)anchor_len); keep+=1; }
FN void anchor_print_uppercase_digits(void) { print_uppercase_digits(anchor_in,anchor_len); keep+=1; }
FN void anchor_print_missing_newline(void) { print_missing_newline(anchor_in,anchor_len); keep+=1; }
FN void anchor_hex32_uppercase(void) { hex32_uppercase((uint32_t)anchor_len); keep+=1; }
FN void anchor_hex32_min_width(void) { hex32_min_width((uint32_t)anchor_len); keep+=1; }
int main(void) {anchor_length_ref();anchor_length_bound();anchor_length_plus();anchor_length_newline();anchor_length_cap();anchor_compare_ref();anchor_compare_signed();anchor_compare_length();anchor_compare_equal();anchor_copy_ref();anchor_copy_short();anchor_copy_reverse();anchor_copy_nul();anchor_hex_lower();anchor_hex_upper();anchor_hex_swapped();anchor_hex_unpadded();anchor_hex_mixed();anchor_parse_signed32();anchor_parse_signed64();anchor_parse_unsigned32();anchor_parse_unsigned64();anchor_parse_ignore_sign();anchor_parse_hex();anchor_parse_nine();anchor_set_ref();anchor_set_short();anchor_set_wrong_byte();anchor_set_off_by_one();anchor_memcmp_ref();anchor_memcmp_signed();anchor_memcmp_equal();anchor_memcmp_first();anchor_xor_ref();anchor_xor_prefix_only();anchor_xor_shifted_key();anchor_xor_skip_zero();anchor_sha1_block_ref();anchor_sha1_transform_few_rounds();anchor_sha1_transform_le_words();anchor_sha256_block_ref();anchor_sha256_transform_few_rounds();anchor_sha256_transform_le_words();anchor_read_impl();anchor_read_truncated_last_byte();anchor_read_extra_byte();anchor_read_length_off_by_one();anchor_read_always_minus_one();anchor_read_ignores_length_slot();anchor_print_impl();anchor_hex32_impl();anchor_print_uppercase_digits();anchor_print_missing_newline();anchor_hex32_uppercase();anchor_hex32_min_width();return 0;}
