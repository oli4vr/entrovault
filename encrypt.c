/* encrypt.c
 *
 * Custom encryption 
 * by Olivier Van Rompuy
 *
 * Per iteration/round the following is done to the data :
 * - 1st round only : Starting InvertXOR with 8192bit key
 * - Byte substitution (different translation tables per round)
 * - Leftway bitwise rotation *A (per 64bit words)
 * - InvertXOR with 8192bit key
 * - Rightway bitwise rotation *B (per 64bit words)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 65536

unsigned char key[1024]={0};
unsigned char ttable[256][256]={0};
unsigned char dtable[256][256]={0};
int rounds=4;

int buildkey(unsigned char * keystring) {
 int se=strlen(keystring),n=0;
 int sp1=0;
 int cval;
 unsigned char * kp=key;
 unsigned char last,cur1;

 if (keystring==NULL) return -1;

 last=keystring[se-1];
 cval=(last-keystring[0])&255;

 for(;n<1024;n++) {
  cur1=keystring[sp1];
  cval=((n>>8)+(n&255)^last^((n&1)?(cval+cur1+1)&255:(cval-cur1-127)))&255;
  *kp=cval;
  last=cur1;
  sp1=(sp1+1)%se;
  kp++;
 }

 return 0;
}

/*
void print_key() {
 int n=0,m=0,ssize;
 unsigned char * kp=key;
 fprintf(stderr,"Generated KEY = %s\n",*kp);
 for(;n<1024;n++) {
  if ((n&31)==0 & n!=0) fprintf(stderr,"\n");
  fprintf(stderr,"%02x ",*kp);
  kp++;
 }
 fprintf(stderr,"\nTranslation Tables =\n");
 for(n=0;n<256;n++) {
  kp=ttable[n];
  fprintf(stderr,"Table ID = %02x\n",n);
  for(m=0;m<256;m++) {
  if ((m&31)==0 & m!=0) fprintf(stderr,"\n");
   fprintf(stderr,"%02x ",*kp);
   kp++;
  }
  fprintf(stderr,"\n");
 }
}*/

unsigned char tt_findchar(unsigned char input, int *table) {
 unsigned char found=1;
 unsigned char curr;
 int n;
 curr=input;
 while (found) {
  found=0;
  for(n=0;n<256;n++) {
   if (table[n]==curr) found=1;
  }
  if (found) {curr=(curr+1)&255;}
 }
 return curr;
}

void buildtrans() {
 int n,m,kp=0;
 int ctable[256];
 unsigned char cval,curr,fval;
 cval=(key[1023]+key[0]-127);
 for(n=0;n<256;n++) {
  for(m=0;m<256;m++) {ctable[m]=-1;}
  for(m=0;m<256;m++) {
   curr=key[kp];
   cval=((n>>8)+(n&255)^((n&1)?(cval+curr+1)&255:(cval-curr-127)))&255;
   fval=tt_findchar(cval,ctable);
   ttable[n][m]=fval;
   dtable[n][fval]=m;
   ctable[m]=ttable[n][m];
   kp=(kp+1)&1023;
  }
 }
}

int invertxor(unsigned char * string, int se) {
 int sp=0,kp=0;
 unsigned char * spp=string;
 uint64_t * sp64=(uint64_t *)spp;

 for(;sp<se-8;sp+=8) {
  *sp64=*sp64^*(uint64_t *)(key+kp)^0xffffffffffffffff;
  sp64++;
  kp=(kp+8)&1023;
 }
 spp=(unsigned char *)sp64;

 for(;sp<se;sp++) {
  *spp=*spp^*(key+kp)^0xff;
  kp=(kp+1)&1023;
  spp++;
 }

 return 0;
}

void translate_fw(unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * tt=ttable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=tt[*sp];
  sp++;
 }
}

void translate_bw(unsigned char * str,int len,unsigned char phase) {
 int n=0;
 unsigned char * dt=dtable[phase];
 unsigned char * sp=str;
 for(;n<len;n++) {
  *sp=dt[*sp];
  sp++;
 }
}

void obscure_fw(unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<8) return;
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)<<(tt[sc>>4]&63))|((*bp)>>(64-(tt[sc>>4]&63)));
 }
 bp=(uint64_t *)(str);
 *bp=((*bp)<<(tt[0]&63))|((*bp)>>(64-(tt[0]&63)));
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)<<(tt[1]&63))|((*bp)>>(64-(tt[1]&63)));
}

void obscure_bw(unsigned char * str,int len,unsigned char phase) {
 int sc,n,max=len-8;
 uint64_t * bp;
 unsigned char * tt=ttable[phase];
 unsigned char offset=tt[127]&7;
 if (len<8) return;
 bp=(uint64_t *)(str+(max-1));
 *bp=((*bp)>>(tt[1]&63))|((*bp)<<(64-(tt[1]&63)));
 bp=(uint64_t *)(str);
 *bp=((*bp)>>(tt[0]&63))|((*bp)<<(64-(tt[0]&63)));
 for(sc=offset;sc<max;sc+=8) {
    bp=(uint64_t *)(str+sc);
    *bp=((*bp)>>(tt[sc>>4]&63))|((*bp)<<(64-(tt[sc>>4]&63)));
 }
}

int init_encrypt(unsigned char * keystr,int nr_rounds) {
 rounds=nr_rounds;
 buildkey(keystr);
 buildtrans();
}

int encrypt_data(unsigned char * buffer,int len) {
 int n=0;
 invertxor(buffer,len);
 for(;n<rounds;n++) {
  translate_fw(buffer,len,key[n]);
  obscure_fw(buffer,len,key[n]);
  invertxor(buffer,len);
  obscure_bw(buffer,len,key[(n+512)&1023]);
 }
}

int decrypt_data(unsigned char * buffer,int len) {
 int n=rounds-1;
 for(;n>=0;n--) {
  obscure_fw(buffer,len,key[(n+512)&1023]);
  invertxor(buffer,len);
  obscure_bw(buffer,len,key[n]);
  translate_bw(buffer,len,key[n]);
 }
 invertxor(buffer,len);
}
