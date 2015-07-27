#include <stdio.h>
#include <string.h>
#include <time.h>
#include "aes_ni/aes_ni.h"
#include "aes/aes256.h"
#include "chacha/chacha.h"

#ifdef WIN32
#include <conio.h>
#include <Windows.h>
LARGE_INTEGER gFreq;
#else
unsigned long long gFreq;
#endif

static unsigned char gKeyString[] = "The light touches is our kingdom";
static int gKeyLength = 32;

static unsigned char gIvString[] = "Love you";
static size_t gIvLength = 8;

unsigned long long GetCurrentTick(void)
{
#ifdef WIN32
	LARGE_INTEGER tick;
	QueryPerformanceCounter(&tick);
	return tick.QuadPart;
#else
	struct timespec tick;
	clock_gettime(CLOCK_MONOTONIC, &tick);
	return (tick.tv_sec)*1000000000L+tick.tv_nsec;
#endif
}

void main(int argc, char **argv)
{
	int i, len;
	unsigned long long tsc_beg, tsc_end, freq;
	char *plaintext, *enctext, *dectext;
//	char *tmptext0, *tmptext1;
	int cryptmethod;
	int datasize;
	time_t t;

#ifdef WIN32
	QueryPerformanceFrequency( &gFreq ); 
	freq = gFreq.QuadPart;
#else
	freq = 1000000000L;
#endif

	// process command arguments
	if (argc < 3)
	{
		printf("Usage : %s crypt_method data_size\n", "benchmark.exe");
		return;
	}
	cryptmethod = atoi(argv[1]);
	datasize = atoi(argv[2]);

	// allocate test memory
	plaintext = malloc(datasize);
	enctext = malloc(datasize+1024);
	dectext = malloc(datasize);

	memset(plaintext, 0, datasize);
	memset(enctext, 0, datasize);
	memset(dectext, 0, datasize);

	// Initializes random number generator and generate the test content
	srand((unsigned) time(&t));
	printf("Generating RANDOM test data .");
	for (i=0; i<datasize; i++)
	{
		plaintext[i] = 'A' + rand()%58;
		if ((i%1000000) == 0)
			printf(".");
	}
	printf("\n");
	printf("test data size : %d bytes\n", datasize);

	len = datasize;

	switch (cryptmethod)
	{
	case 0:
		// AES-NI standard
		printf("\n%-20s : ", "AES-NI encryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		aesni_encrypt(plaintext, &len, enctext);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);

		printf("%-20s : ", "AES-NI decryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		aesni_decrypt(enctext, &len, dectext);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);
		//	printf("decrypted_content : %s\n", dectext);
		break;
	case 1:
		// AES standard
		memset(enctext, 0, datasize);
		memset(dectext, 0, datasize);

		printf("\n%-20s : ", "AES encryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		//tmptext0 = aes256_enc(plaintext, &len, gKeyString, gKeyLength);
		aesnoni_encrypt(plaintext, &len, enctext);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);

		printf("%-20s : ", "AES decryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		//tmptext1 = aes256_dec(tmptext0, &len, gKeyString, gKeyLength);
		aesnoni_decrypt(enctext, &len, dectext);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);
		//	printf("decrypted_content : %s\n", tmptext1);

		//	free(tmptext0);
		//	free(tmptext1);
		break;
	case 2:
		// ChaCha20
		memset(enctext, 0, datasize);
		memset(dectext, 0, datasize);

		printf("\n%-20s : ", "CHACHA encryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		CRYPTO_chacha_20(enctext, plaintext, datasize, gKeyString, gIvString, (size_t)0);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);

		printf("%-20s : ", "CHACHA decryption");
		tsc_beg = GetCurrentTick();//do_rdtsc();
		CRYPTO_chacha_20(dectext, enctext, datasize, gKeyString, gIvString, (size_t)0);
		tsc_end = GetCurrentTick();//do_rdtsc();
		printf("%8d us\n", (tsc_end-tsc_beg)*1000000/freq);
		//	printf("decrypted_content : %s\n", dectext);
		break;
	}

	free(plaintext);
	free(enctext);
	free(dectext);

	return;
}
