/* Original MIT calibration: explicit x86-64 widths and independently specified call sites. */
#include <stdint.h>
#include <stddef.h>
#define TARGET __attribute__((noinline,used))
#define NAKED __attribute__((naked,noinline,used))
static volatile uint32_t input32=0x01020304;
static volatile uint64_t input64=0x0102030405060708;
static volatile float input_float=1.25f;
static volatile double input_double=2.5;
static const unsigned char bytes[2]={1,2};
static volatile uint64_t sink;
static volatile float float_sink;
static volatile double double_sink;
static volatile uint32_t event;
TARGET uint32_t sig_ret32(uint32_t x){return x^0x13579u;}
TARGET uint64_t sig_ret64(uint64_t x){return x^0x13579u;}
TARGET const unsigned char *sig_retptr(const unsigned char *p){return p+1;}
TARGET float sig_retfloat(float x){return x+1.0f;}
TARGET double sig_retdouble(double x){return x+1.0;}
NAKED uint8_t sig_ret8(uint8_t x){__asm__("movb %dil,%al; ret");}
NAKED uint16_t sig_ret16(uint16_t x){__asm__("movw %di,%ax; ret");}
NAKED uint64_t sig_write32_read64(uint32_t x){__asm__("movl %edi,%eax; ret");}
NAKED uint32_t sig_write64_read32(uint64_t x){__asm__("movq %rdi,%rax; ret");}
NAKED void sig_void_written(void){__asm__("movl $1,%eax; ret");}
NAKED void sig_no_write(void){__asm__("ret");}
TARGET uint32_t sig_tail_helper(uint32_t x){return x^0x2468u;}
TARGET uint32_t sig_tail(uint32_t x){return sig_tail_helper(x);}
NAKED uint32_t sig_mixed(uint32_t x){__asm__("testl %edi,%edi; jz 1f; movb $1,%al; ret; 1: movl $1,%eax; ret");}
TARGET uint32_t sig_unread(uint32_t x){event^=x;return x^0x13579u;}
TARGET uint32_t sig_pointer(const uint32_t *p){return *p;}
/* This diagnostic has an integer ABI parameter despite its address use. */
TARGET uint32_t sig_integer_address(uintptr_t p){return *(const uint32_t*)p;}
TARGET void anchor_sig_ret32(void){sink+=sig_ret32(input32);}
TARGET void anchor_sig_ret64(void){sink+=sig_ret64(input64);}
TARGET void anchor_sig_retptr(void){sink+=(uintptr_t)sig_retptr(bytes);}
TARGET void anchor_sig_retfloat(void){float_sink=sig_retfloat(input_float);}
TARGET void anchor_sig_retdouble(void){double_sink=sig_retdouble(input_double);}
TARGET void anchor_sig_ret8(void){sink+=sig_ret8((uint8_t)input32);}
TARGET void anchor_sig_ret16(void){sink+=sig_ret16((uint16_t)input32);}
TARGET void anchor_sig_write32_read64(void){sink+=sig_write32_read64(input32);}
TARGET void anchor_sig_write64_read32(void){sink+=sig_write64_read32(input64);}
NAKED uint32_t anchor_sig_void_written(void){__asm__("subq $8,%rsp; call sig_void_written; addq $8,%rsp; addl $1,%eax; ret");}
NAKED uint32_t anchor_sig_no_write(void){__asm__("subq $8,%rsp; call sig_no_write; addq $8,%rsp; xorl %eax,%eax; ret");}
TARGET void anchor_sig_tail(void){sink+=sig_tail(input32);}
TARGET void anchor_sig_mixed(void){sink+=sig_mixed(input32);}
TARGET void anchor_sig_unread(void){sig_unread(input32);sink+=input32;}
TARGET void anchor_sig_pointer(void){const uint32_t value=0x01020304;sink+=sig_pointer(&value);}
TARGET void anchor_sig_integer_address(void){const uint32_t value=0x01020304;sink+=sig_integer_address((uintptr_t)&value);}
int main(void){
 anchor_sig_ret32();anchor_sig_ret64();anchor_sig_retptr();anchor_sig_retfloat();anchor_sig_retdouble();
 anchor_sig_ret8();anchor_sig_ret16();anchor_sig_write32_read64();anchor_sig_write64_read32();
 sink+=anchor_sig_void_written();sink+=anchor_sig_no_write();anchor_sig_tail();anchor_sig_mixed();
 anchor_sig_unread();anchor_sig_pointer();anchor_sig_integer_address();return 0;
}
