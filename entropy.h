/* entropy.h
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

#define PAYLOAD_SIZE 1024
#define BUFFER_SIZE 1088

#define RNDBUFF 65536

void init_random();
void print_hash(unsigned char * data);
void wipe_buffer(unsigned char *buff);

long int entropy_search(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds);
long int entropy_append(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds);
long int entropy_replace(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset);
long int entropy_erase(unsigned char * buff, unsigned char *keystr, unsigned char *pwd, unsigned char *fname, unsigned char rounds, long int offset);
