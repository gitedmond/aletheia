/* Original MIT calibration; independent of corpus implementations. */
#include <stdint.h>
#include <stddef.h>
#define TARGET __attribute__((noinline,used))
static const unsigned char *volatile input;
static volatile size_t length;
static volatile uint64_t sink;
static inline __attribute__((always_inline)) uint16_t compute(const unsigned char *p,size_t n,unsigned modulus,unsigned initial,int swap) {
 unsigned a=initial,b=initial;
 for(size_t i=0;i<n;i++){a=(a+p[i])%modulus;b=(b+a)%modulus;}
 return (uint16_t)(swap ? (a<<8)|b : (b<<8)|a);
}
TARGET uint16_t std_impl(const unsigned char *p,size_t n){return compute(p,n,255,0,0);}
TARGET uint16_t mod256(const unsigned char *p,size_t n){return compute(p,n,256,0,0);}
TARGET uint16_t swapped_halves(const unsigned char *p,size_t n){return compute(p,n,255,0,1);}
TARGET uint16_t initial_one(const unsigned char *p,size_t n){return compute(p,n,255,1,0);}
#define ANCHOR(fn) TARGET uint64_t anchor_##fn(void){uint16_t v=fn(input,length);return v+length;}
ANCHOR(std_impl)
ANCHOR(mod256)
ANCHOR(swapped_halves)
ANCHOR(initial_one)
int main(void){sink+=anchor_std_impl();sink+=anchor_mod256();sink+=anchor_swapped_halves();sink+=anchor_initial_one();return 0;}
