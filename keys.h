/* Reading/writing public and secret keys */
#pragma once
#include <gmp.h>

#define MAX_NAME 128

struct dhKey {
	char name[MAX_NAME+1];
	mpz_t PK;
	mpz_t SK;
	/* NOTE: in general would want to add pointers for g,p,q,
	 * but we will likely ever only use the ones in ./params
	 * so maybe it unnecessarily complicates things. */
};

int initKey(dhKey* k);
/* this will write 1 or two files, depending on whether or not the
 * secret key is present in the key struct.  Using the ssh convention,
 * the public key will be in fname.pub, secret key (if available) will
 * be in fname. */
int writeDH(char* fname, dhKey* k);
/* this will read either a public or private key, storing result in *k.
 * Public keys will have the SK field set to 0. */
int readDH(char* fname, dhKey* k);
/* zero memory for key: */
int shredKey(dhKey* k);
