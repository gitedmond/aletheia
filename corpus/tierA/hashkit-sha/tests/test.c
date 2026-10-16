#include "program.h"
#include "native-check.h"
#include <string.h>
#include <stdlib.h>
int main(void) {
    uint8_t input[128], out[32]; memset(input, 0x61, sizeof input); sha1_t a; sha256_t b;
    {const uint8_t expected1[20]={218,57,163,238,94,107,75,13,50,85,191,239,149,96,24,144,175,216,7,9};const uint8_t expected2[32]={227,176,196,66,152,252,28,20,154,251,244,200,153,111,185,36,39,174,65,228,100,155,147,76,164,149,153,27,120,82,184,85};
    sha1_init(&a);sha1_update(&a,input,0);sha1_update(&a,input+0,0);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,0);sha256_update(&b,input+0,0);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,0,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={169,153,62,54,71,6,129,106,186,62,37,113,120,80,194,108,156,208,216,157};const uint8_t expected2[32]={186,120,22,191,143,1,207,234,65,65,64,222,93,174,34,35,176,3,97,163,150,23,122,156,180,16,255,97,242,0,21,173};
    sha1_init(&a);sha1_update(&a,(const uint8_t *)"abc",3);sha1_update(&a,(const uint8_t *)"abc"+3,0);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,(const uint8_t *)"abc",3);sha256_update(&b,(const uint8_t *)"abc"+3,0);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot((const uint8_t *)"abc",3,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={193,200,187,220,34,121,110,40,192,225,81,99,210,8,153,182,86,33,214,90};const uint8_t expected2[32]={159,67,144,248,211,12,45,217,46,201,240,149,182,94,43,154,233,176,169,37,165,37,142,36,28,159,30,145,15,115,67,24};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,38);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,38);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,55,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={194,219,51,15,96,131,133,76,153,212,181,191,182,232,242,159,32,27,230,153};const uint8_t expected2[32]={179,84,57,164,172,111,9,72,182,214,249,227,198,175,15,95,89,12,226,15,27,222,112,144,239,121,112,104,110,198,115,138};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,39);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,39);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,56,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={3,240,159,91,21,138,122,140,218,217,32,189,220,41,184,28,24,165,81,245};const uint8_t expected2[32]={125,62,116,160,93,125,177,91,206,74,217,236,6,88,234,152,227,240,110,238,207,22,180,198,255,242,218,69,125,220,47,52};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,46);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,46);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,63,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={0,152,186,130,75,92,22,66,123,215,161,18,42,90,68,42,37,236,100,77};const uint8_t expected2[32]={255,224,84,254,122,224,203,109,198,92,58,249,182,29,82,9,244,57,133,29,180,61,11,165,153,115,55,223,21,70,104,235};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,47);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,47);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,64,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={17,101,83,38,199,8,215,3,25,190,38,16,232,165,125,154,91,149,157,59};const uint8_t expected2[32]={99,83,97,196,139,185,234,177,65,152,231,110,168,171,127,26,65,104,93,106,214,42,169,20,109,48,29,79,23,235,10,224};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,48);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,48);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,65,out);CHECK(memcmp(out,expected2,32)==0);}
    {const uint8_t expected1[20]={243,76,20,136,56,83,70,165,87,9,186,5,109,221,8,40,13,212,198,214};const uint8_t expected2[32]={47,61,51,84,50,199,11,88,10,240,232,225,179,103,74,124,2,13,104,58,165,247,58,170,237,253,197,90,249,4,194,28};
    sha1_init(&a);sha1_update(&a,input,17);sha1_update(&a,input+17,103);sha1_final(&a,out);CHECK(memcmp(out,expected1,20)==0);
    sha256_init(&b);sha256_update(&b,input,17);sha256_update(&b,input+17,103);sha256_final(&b,out);CHECK(memcmp(out,expected2,32)==0);
    sha256_oneshot(input,120,out);CHECK(memcmp(out,expected2,32)==0);}

    printf("ok %u\n", checks);
    return 0;
}
