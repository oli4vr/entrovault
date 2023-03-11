/* entropy.c
 *
 * by Olivier Van Rompuy
 * 11/03/2023
 * 
 * Entropy Vault command line tool
 * 
 * Entropy vaults are cryptographically obscured files intended to store passwords and
 * other sensitive short strings. Every entry is stored as an encrypted entry that contains payload+hash.
 * To retrieve it theprogram must decript every possible entry per x nr of bytes with the provided keys.
 * 
 * To complicate things a random amount of random data blocks are added before and after each entry and
 * unused data in a payload is also randomized to avoid predictable data blocks.
 * 
 * The vault files are stored in ${HOME}/.entropy
 * 
 * */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include "sha512.h"
#include "encrypt.h"
#include "entropy.h"

unsigned char rnd_buff[RNDBUFF];

//Initialize the random buffer
void init_random() {
 unsigned char * end=rnd_buff+RNDBUFF;
 unsigned char * p = rnd_buff;
 int * i;
 srand(time(NULL)); 
 for(;p<end;p+=sizeof(int)) {
   i=(int*)p;
   *i=rand();
 }
}

//Print an sha512 hash -> Debug purposes
void print_hash(unsigned char * data) {
 unsigned char * end, *c;
 end=data+64;
 for(c=data;c<end;c++) {
  fprintf(stderr,"%02X",*c);
 }
 fprintf(stderr,"\n");
}

//Wipe a buffer by replacing it's content with random bytes
void wipe_buffer(unsigned char *buff)
{
 unsigned char * end=buff+PAYLOAD_SIZE;
 unsigned char * p = buff;
 int * i;
 srand(time(NULL)); 
 for(;p<end;p+=sizeof(int)) {
   i=(int*)p;
   *i=rand();
 }
}

//Search and entry
long int entropy_search(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char buff2[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 unsigned char * digest2 = buff2+PAYLOAD_SIZE;
 int len,rp,rn,n,rr;
 long int offset=0,offok=0;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Input file not found\n");
  return -1;
 }

 fp=fopen(fname,"r+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for read\n");
  return -2;
 }

 rr=fread(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 memcpy(buff2,buff1,BUFFER_SIZE);
 while (rr>0) {
  init_encrypt(keystr,rounds);
  decrypt_data(buff2,BUFFER_SIZE);
  init_encrypt(pwd,rounds);
  decrypt_data(buff2,BUFFER_SIZE);
  SHA512(buff2,PAYLOAD_SIZE,cmp);
  len=strnlen(buff2,PAYLOAD_SIZE);
  if (len<PAYLOAD_SIZE && memcmp(cmp,digest2,64)==0)
  {
   offok=offset-BUFFER_SIZE;
   memcpy(buff,buff2,PAYLOAD_SIZE);
  }
  memcpy(buff2,buff1+64,PAYLOAD_SIZE);
  rr=fread(digest2,64,1,fp);
  if (rr>0) offset+=64;
  memcpy(buff1,buff2,BUFFER_SIZE);
 }
 fclose(fp);
 return offok;
}

//Append entry to the end of the file -> Obscure by adding random blocks before and after
long int entropy_append(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 int rp,rn,n;
 long int offset=0;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -1;
 }

 fp=fopen(fname,"a+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for append\n");
  return -2;
 }

 //Starting random blocks
 init_random();
 rn=rand()&7;
 rp=(rand()&1023)<<6;
 for(n=0;n<rn;n++) {
  fwrite(rnd_buff+rp,1,64,fp);
  offset+=64;
  rp=(rp+64)&65535;
 }
 
 wipe_buffer(buff1);
 strncpy(buff1,buff,PAYLOAD_SIZE);
 SHA512(buff1,PAYLOAD_SIZE,digest1);
 init_encrypt(pwd,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 init_encrypt(keystr,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;

 //Ending random blocks
 init_random();
 rn=rand()&7;
 rp=(rand()&1023)<<6;
 for(n=0;n<rn;n++) {
  fwrite(rnd_buff+rp,1,64,fp);
  offset+=64;
  rp=(rp+64)&65535;
 }

 fclose(fp); 
 return offset-BUFFER_SIZE;
}

//Replace -> Search entry in file and replace with new data
long int entropy_replace(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 int rp,rn,n;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -1;
 }

 fp=fopen(fname,"rw+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for write\n");
  return -2;
 }

 if (fseek(fp,offset,SEEK_SET)!=0) {
  fprintf(stderr," Error: Seek failed in file\n");
  return -3;
 }
 wipe_buffer(buff1);
 strncpy(buff1,buff,PAYLOAD_SIZE);
 SHA512(buff1,PAYLOAD_SIZE,digest1);
 init_encrypt(pwd,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 init_encrypt(keystr,rounds);
 encrypt_data(buff1,BUFFER_SIZE);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 
 fclose(fp); 
 return offset-BUFFER_SIZE;
}

//Erase -> search entry and overwrite with random bytes
long int entropy_erase(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset)
{
 unsigned char buff1[BUFFER_SIZE];
 unsigned char cmp[64];
 unsigned char * digest1 = buff1+PAYLOAD_SIZE;
 int rp,rn,n;
 FILE *fp;

 if (fname==NULL) {
  fprintf(stderr," Error: Output file not found\n");
  return -1;
 }

 fp=fopen(fname,"rw+b");
 if (fp == NULL) {
  fprintf(stderr," Error: Failed to open file for write\n");
  return -2;
 }

 if (fseek(fp,offset,SEEK_SET)!=0) {
  fprintf(stderr," Error: Seek failed in file\n");
  return -3;
 }
 wipe_buffer(buff1);
 fwrite(buff1,1,BUFFER_SIZE,fp);
 offset+=BUFFER_SIZE;
 
 fclose(fp); 
 return offset-BUFFER_SIZE;
}

