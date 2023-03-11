/* entrovault.c
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
 * Meaning of entropy from Wikipedia =
 * "Entropy is a scientific concept, as well as a measurable physical property,
 *  that is most commonly associated with a state of disorder, randomness, or uncertainty."
 * 
 * The vault files are stored in ${HOME}/.entropy
 * 
 * */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>
#include <time.h>

#include "entropy.h"

int main(int argc, char **argv)
{
 unsigned char badsyntax=0;
 unsigned char mode=0;
 unsigned char imode=0;
 unsigned char *opt, * cmd=*argv;
 unsigned char basepath[256]={0};
 unsigned char filepath[512]={0};
 unsigned char keystring[256]={0};
 unsigned char password[256]={0};
 unsigned char prompt[256]={0};
 unsigned char payload[PAYLOAD_SIZE+1]={0};
 unsigned char check[PAYLOAD_SIZE+1]={0};
 unsigned char buffer[BUFFER_SIZE]={0};
 unsigned char rounds=2;
 long int offset=0,rr=0;
 snprintf(basepath,256,"%s/.entropy", getpwuid(getuid())->pw_dir);
 snprintf(filepath,256,"%s/.default.entropy",basepath); 

 //Option handling
 argc--;
 argv++;

 while (argc>1) {
  opt=*argv;
  if (*opt!='-') {badsyntax=1; argc=0;}
  else {
   switch(opt[1]) {
    case 'q':
           imode=1;
           break;
    case 'a':
           mode=1;
           break;
    case 'r':
           mode=2;
           break;
    case 'e':
           mode=3;
           break;
    case 'v':
           argc--;
           argv++;
           if (argc>0) {snprintf(filepath,256,"%s/.%s.entropy",basepath,argv[0]);}
           else {badsyntax=1;}
           break;
    case 'p':
           argc--;
           argv++;
           if (argc>0) {snprintf(password,256,"%s",argv[0]);}
           else {badsyntax=1;}
           break;
    case '%':
           argc--;
           argv++;
           if (argc>0) {rounds=atoi(argv[0]);}
           else {badsyntax=1;}
           break;
    default:
           badsyntax=1;
           break;
   }
   argc--;
   argv++;
  }
 }

 if (argc>0) {
    strncpy(keystring,argv[0],256);
    keystring[255]=0;
 } else {
    badsyntax=1;
 }

// Bad or empty options -> Display help
 if (badsyntax)
 {
    fprintf(stderr,"entrovault -> Entropy vault\n by Olivier Van Rompuy\n\nSyntax: entrovault [-a | -r | -e] [-q] [-p vault_password] [-v vault_name] [-\% rounds] keystring\n\n");
    fprintf(stderr,"Options\n -a\t\tAppend entry\n -r\t\tReplace entry\n -e\t\tErase entry\n -p\t\tVault password\n");
    fprintf(stderr," -q\t\tPassword type payload entry\n -v\t\tVault name\n -\%\t\tEncryption rounds\n\n");
    return -1;
 }

 //Create the .entropy path
 mkdir(basepath,S_IRWXU);

 //Enter the vault password
 if (*password==0) {
  if (mode==1) {
   snprintf(prompt,256,"Enter vault password for %s - 1st : ",keystring);
   strncpy(password,(unsigned char*)getpass(prompt),80);
   snprintf(prompt,256,"Enter vault password for %s - 2nd : ",keystring);
   strncpy(check   ,(unsigned char*)getpass(prompt),80);
   if (strncmp(password,check,256)!=0) {
     fprintf(stderr,"-> Error : Password entry is not identical!\n");
   }
  } else {
   snprintf(prompt,256,"Enter vault password for %s :",keystring);
   strncpy(password,(unsigned char*)getpass(prompt),80);
  }
 }

 switch(mode) {
    case 0:   //Search entry and output content
      offset=entropy_search(buffer,keystring,password,filepath,rounds);
      if (offset>0) {
      strncpy(payload,buffer,PAYLOAD_SIZE);
      payload[PAYLOAD_SIZE+1]=0;
      fwrite(payload,1,strnlen(payload,PAYLOAD_SIZE),stdout);
      }
     break;
    case 1:   //Append entry
       if (imode==1) {
        strncpy(payload,(unsigned char*)getpass("Payload 1st : "),80);
        strncpy(check  ,(unsigned char*)getpass("Payload 2nd : "),80);
       if (strncmp(payload,check,PAYLOAD_SIZE+1)!=0) {
        fprintf(stderr,"-> Error : Payload entry is not identical!\n");
        return -2;
       }
       } else {
        rr=fread(payload,1,PAYLOAD_SIZE,stdin);
       }
      wipe_buffer(buffer);
      strncpy(buffer,payload,PAYLOAD_SIZE);
      entropy_append(buffer,keystring,password,filepath,rounds);
     break;
    case 2:   //Replace entry
       offset=entropy_search(buffer,keystring,password,filepath,rounds);
       if (offset>0) {
        strncpy(payload,buffer,PAYLOAD_SIZE);
        payload[PAYLOAD_SIZE+1]=0;

       if (imode==1) {
        strncpy(payload,(unsigned char*)getpass("Payload 1st : "),80);
        strncpy(check  ,(unsigned char*)getpass("Payload 2nd : "),80);
       if (strncmp(payload,check,PAYLOAD_SIZE+1)!=0) {
        fprintf(stderr,"-> Error : Payload entry is not identical!\n");
        return -2;
       }
       } else {
        rr=fread(payload,1,PAYLOAD_SIZE,stdin);
       }
       wipe_buffer(buffer);
       strncpy(buffer,payload,PAYLOAD_SIZE);
       entropy_replace(buffer,keystring,password,filepath,rounds,offset);
       } else {
        fprintf(stderr," Error : Keystring entry not found!");
        return -5;
       }
     break;
    case 3:  //Erase entry
       offset=entropy_search(buffer,keystring,password,filepath,rounds);
       if (offset>0) {
        strncpy(payload,buffer,PAYLOAD_SIZE);
        payload[PAYLOAD_SIZE+1]=0;
        wipe_buffer(buffer);
        buffer[0]=0;
        entropy_erase(buffer,keystring,password,filepath,rounds,offset);
       } else {
        fprintf(stderr," Error : Keystring entry not found!");
        return -5;
       }
     break;
 }

 return 0;
}
