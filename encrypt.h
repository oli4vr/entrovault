/* encrypt.h
 * Basic encryption 
 * by Olivier Van Rompuy
 *
 * Custom encryption algorithm
 *
 * Per iteration/round the following is done to the data :
 * - 1st round only : Starting InvertXOR with 8192bit key
 * - Byte substition
 * - Bitshift obscuring offset A (per 64bit words)
 * - InvertXOR with 8192bit key
 * - Inverse Bitshift obscuring offset B (per 64bit words)
 *
 */

int init_encrypt(unsigned char * keystr,int nr_rounds);
int encrypt_data(unsigned char * buffer,int len);
int decrypt_data(unsigned char * buffer,int len);

