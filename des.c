/* Data Encryption Standard */
#include <stdint.h>
#include <stdio.h>
#include "box.h"
void int2hex(uint64_t input) {
    uint64_t i, di, tmp;
    char hex[20];
    char index[] = "0123456789ABCDEF";
    di = 0x1000000000000000;
    for(i=0; i<16; i++) {
        tmp = input / di;
        //printf("%llu %llu\n",tmp, i);
        hex[i] = index[tmp];
        printf("%c", hex[i]);
        input = input % di; di = di >> 4;
    }
    printf(" ");
}
void int2bin(uint64_t input) {
    uint8_t i;
    char bin[70];
    for(i=0; i<64; i++) {
        bin[63-i] = (input % 2) + '0';
        input /= 2;
    }
    bin[64] = 0;
    for(i=0; i<64; i++) printf("%c",bin[i]);
}
// Standard Pbox permutation
uint64_t std_permute(uint64_t input, uint8_t* box, uint8_t size) {
    uint8_t i, j, b;
    uint64_t a, output;
    output = 0;
    for(i=0; i<size; i++) {
        b = input % 2; 
        for(j=0; j<size; j++) if((size-1-i) == (box[j]-1)) break;
        a = 1; a = a << (size-1-j);
        if(b == 1) output |= a;
        input = input >> 1; // to next bit
    }
    return output;
}
// ############## DES-Function ############## 
// The first part of DES function: Extended 32 bits to 48 bits
uint64_t ext_permute(uint32_t input) {
    uint8_t i, j, a, b, idx;
    // Extended P-box
    uint8_t* Ext_Pbox;
    Ext_Pbox = calloc(48, sizeof(uint8_t));
    idx = 0;
    for(i=31; idx<48; i+=4) 
        for(j=i; j<i+6; j++) 
            Ext_Pbox[idx++] = j % 32;
    // Output
    uint64_t output = 0;
    for(i=0; i<48; i++) {
        for(j=0; j<32; j++) if(j == Ext_Pbox[i]) break;
        b = (input >> (31-j)) % 2;
        if(b == 1) output |= 1;
        output = output << 1;
    }    
    output = output >> 1;
    return output;
}
// The second part: right 48 bits XOR round key
uint64_t Whitener(uint64_t r, uint64_t k) {
    return r ^ k;
}
// The third part: S-box confusion & shrink 48 bits to 32 bits
uint32_t Substitution(uint64_t input48) {
    uint8_t i, j, tw, fo, in[8];
    uint32_t output32;
    for(i=0; i<8; i++) in[i] = (input48 >> (6*i)) % 64;
    for(i=0; i<8; i++) {
        output32 = output32 << 4;
        // 2 bits - 4 bits
        tw = ((in[7-i] >> 5) << 1) ^ (in[7-i] % 2);
        fo = (in[7-i] % 32) >> 1;
        //printf("%d %d\n", tw, fo);
        output32 |= Sbox[i][tw][fo];
    }
    return output32;
}
// The final part: Standard P-box 
// Using the function above
uint32_t DES_Function(uint32_t input32, uint64_t rkey) {
    uint32_t output32;
    uint64_t ext48, inter48;
    // 1. Extend P-box (32b -> 48b)
    ext48 = ext_permute(input32);  
    // 2. Add(XOR) round key
    inter48 = Whitener(ext48, rkey); 
    // 3. Substitution (48b -> 32b)
    output32 = Substitution(inter48); 
    // 4. Standard P-box 
    output32 = std_permute(output32, std_Pbox32, 32);
    return output32;
}

// ############## Round key generator ############## 
// First step: Parity bit drop
uint64_t parity_drop(uint64_t input64) {
    uint8_t i, j;
    uint64_t output56;
    output56 = 0;
    for(i=0; i<56; i++) {
        for(j=0; j<64; j++) if(j == (shrink_Pbox56[i]-1)) break;
        if(j<64){
            if(((input64) >> (63-j)) % 2 == 1) output56 |= 1;
            output56 = output56 << 1;
        }
    }
    output56 = output56 >> 1;
    return output56;
}
// Second step: Depart & left shift & Combine
uint32_t circular_left_shift(uint32_t input, uint8_t cnt, uint8_t size) {
    uint32_t output, mask = 1 << size; 
    output = (input << cnt) % mask;
    output += input >> (size-cnt);  
    return output;
}
uint64_t left_shift(uint64_t input56, uint8_t cnt) {
    uint64_t L, R;
    uint64_t output56;
    L = input56 >> 28;
    R = input56 % 0x10000000;
    L = circular_left_shift(L, cnt, 28); 
    R = circular_left_shift(R, cnt, 28); 
    output56 = (L << 28) + R;
    return output56;
} 
// Third Step: Shrink Pbox: 56 -> 48
uint64_t shrink_pbox(uint64_t input56) {
    uint8_t i, j;
    uint64_t output48;
    output48 = 0;
    for(i=0; i<48; i++) {
        for(j=0; j<56; j++) if(j == (shrink_Pbox48[i]-1)) break;
        if(j<56){
            if(((input56) >> (55-j)) % 2 == 1) output48 |= 1;
            output48 = output48 << 1;
        }
    }
    output48 = output48 >> 1;
    return output48;
}
uint64_t* Round_Key_Generator(uint64_t key) {
    uint8_t i;
    uint64_t inter56;
    uint64_t *output48;
    output48 = calloc(16, sizeof(uint64_t));
    inter56 = parity_drop(key);

    int2hex(inter56); printf("\n");
    for(i=0; i<16; i++) {
        output48[i] = shrink_pbox(left_shift(inter56, shift_table[i]));
        inter56 = left_shift(inter56, shift_table[i]);
    }
    
    return output48;
}
uint64_t DES_Block(uint64_t input, uint64_t key) {
    uint64_t output, *L, *R, *K;
    uint32_t tmp32;
    uint8_t i;
    L = calloc(20, sizeof(uint64_t)); // Left part of inter
    R = calloc(20, sizeof(uint64_t)); // Right part of inter
    K = calloc(16, sizeof(uint64_t));
    K = Round_Key_Generator(key);
    printf("Input: "); int2hex(input); printf("\n");
    // ### Init permutation ### 
    output = std_permute(input, init_Pbox, 64); printf("After initial permutation: "); int2hex(output); printf("\n");
    // ### Round ### 
    L[0] = output >> 32; R[0] = output % 0x100000000;   
    //printf("Round  0 (After init permute): "); int2hex(L[0]); int2hex(R[0]); printf("\n");
    for(i=1; i<17; i++) {
        L[i] = R[i-1]; 
        R[i] = DES_Function(R[i-1], K[i-1]) ^ L[i-1];
        printf("Round %2d: ", i); int2hex(L[i]); int2hex(R[i]); printf("\n");
    }
    tmp32 = L[16]; L[16] = R[16]; R[16] = tmp32;
    output = (L[16] << 32) + R[16]; printf("Final: "); int2hex(output); printf("\n");
    // ### Final permutation ###
    output = std_permute(output, final_Pbox, 64); printf("Output (After final permutation): "); int2hex(output);printf("\n");
    return output;
}

int main() {
    uint64_t input, output, key;
    input = 0x123456abcd132536;
    key = 0xaabb09182736ccdd;
    output = DES_Block(input, key);
    
    return 0;
}
