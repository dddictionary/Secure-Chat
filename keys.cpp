#include "keys.h"
#include <assert.h>
#include <string.h>
#include <cstdlib>
#include <fcntl.h>

int initKey(dhKey* k)
{
	assert(k);
	mpz_init(k->PK);
	mpz_init(k->SK);
	strncpy(k->name,"default",MAX_NAME);
	return 0;
}

int shredKey(dhKey* k)
{
	assert(k);
	size_t nLimbs = mpz_size(k->SK);
	memset(mpz_limbs_write(k->SK,nLimbs),0,nLimbs*sizeof(mp_limb_t));
	mpz_clear(k->SK);
	nLimbs = mpz_size(k->PK);
	memset(mpz_limbs_write(k->PK,nLimbs),0,nLimbs*sizeof(mp_limb_t));
	mpz_clear(k->PK);
	memset(k->name,0,MAX_NAME);
	return 0;
}

/* straightforward, lazy key format:
 * name:<name...>
 * pk:<base 10 rep of A>
 * sk:<base 10 rep of a>
 * (where A = g^a)
 * */

int writeDH(char* fname, dhKey* k)
{
	assert(k);
	/* NOTE if fname was already PATH_MAX-3 or longer, the name will be
	 * cut off, and possibly we will have the public key overwrite the
	 * secret key... */
	if (strnlen(fname,PATH_MAX) > PATH_MAX-4) {
		fprintf(stderr, "no room for .pub suffix in filename %s\n",fname);
		return -2;
	}
	char fnamepub[PATH_MAX+1]; fnamepub[PATH_MAX] = 0;
	strncpy(fnamepub,fname,PATH_MAX);
	strncat(fnamepub,".pub",PATH_MAX);
	/* when saving secret key, make sure file isn't world-readable */
	int fd = open(fname,O_RDWR|O_CREAT|O_TRUNC,0600);
	FILE* f = fdopen(fd,"wb");
	if (!f) return -1;
	fprintf(f, "name:%s\n", k->name);
	gmp_fprintf(f, "pk:%Zd\n", k->PK);
	gmp_fprintf(f, "sk:%Zd\n", k->SK);
	fclose(f);
	f = fopen(fnamepub,"wb");
	if (!f) return -1;
	fprintf(f, "name:%s\n", k->name);
	gmp_fprintf(f, "pk:%Zd\n", k->PK);
	fprintf(f, "sk:0\n");
	fclose(f);
	return 0;
}

int readDH(char* fname, dhKey* k)
{
	assert(k);
	initKey(k);
	FILE* f = fopen(fname,"rb");
	if (!f) return -1;
	int rv = 0;
	char* name;
	/* XXX make sure %ms is working properly */
	if (fscanf(f,"name:%ms\n",&name) != 1) {
		rv = -2;
		goto end;
	}
	strncpy(k->name,name,MAX_NAME);
	free(name);
	if (gmp_fscanf(f,"pk:%Zd\n",k->PK) != 1) {
		rv = -2;
		goto end;
	}
	if (gmp_fscanf(f,"sk:%Zd\n",k->SK) != 1) {
		rv = -2;
		goto end;
	}
end:
	fclose(f);
	return rv;
}
