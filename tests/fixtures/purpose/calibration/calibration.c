/* Original MIT calibration; independently specified standard operations. */
#include <stdint.h>
#include <stddef.h>
#define FN __attribute__((noinline,used))
static volatile uint64_t keep;
FN uint64_t length_ref(const unsigned char *s) { uint64_t n=0; while(s[n]) ++n; return n; }
FN uint64_t length_bound(const unsigned char *s,size_t bound) { size_t n=0; while(n<bound && s[n]) ++n; return n; }
FN uint64_t length_plus(const unsigned char *s) { return length_ref(s)+1; }
FN uint64_t length_newline(const unsigned char *s) { size_t n=0; while(s[n] && s[n]!='\n') ++n; return n; }
FN uint64_t length_cap(const unsigned char *s) { size_t n=0; while(s[n] && n<255) ++n; return n; }
FN int compare_ref(const unsigned char *a,const unsigned char *b) { while(*a && *a==*b) { ++a; ++b; } return (int)*a-(int)*b; }
FN int compare_signed(const unsigned char *a,const unsigned char *b) { while(*a && *a==*b) { ++a; ++b; } return (int)(signed char)*a-(int)(signed char)*b; }
FN int compare_length(const unsigned char *a,const unsigned char *b) { size_t x=0,y=0; while(a[x]) ++x; while(b[y]) ++y; return (x>y)-(x<y); }
FN int compare_equal(const unsigned char *a,const unsigned char *b) { return compare_ref(a,b)!=0; }
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

static unsigned char anchor_in[4097]={1,0,171,255};
static unsigned char anchor_out[8209];
static volatile size_t anchor_len=4;
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
int main(void) {anchor_length_ref();anchor_length_bound();anchor_length_plus();anchor_length_newline();anchor_length_cap();anchor_compare_ref();anchor_compare_signed();anchor_compare_length();anchor_compare_equal();anchor_copy_ref();anchor_copy_short();anchor_copy_reverse();anchor_copy_nul();anchor_hex_lower();anchor_hex_upper();anchor_hex_swapped();anchor_hex_unpadded();anchor_hex_mixed();anchor_parse_signed32();anchor_parse_signed64();anchor_parse_unsigned32();anchor_parse_unsigned64();anchor_parse_ignore_sign();anchor_parse_hex();anchor_parse_nine();return 0;}
