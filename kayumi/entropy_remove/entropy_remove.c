#include <Windows.h>
#include <stdio.h>
#include "payload.h"

unsigned char low_entropy_payload[2097152];
char* targetpath = "C:\\Users\\turbo_granny\\Desktop\\kltn_meodev\\kayumi\\loader\\payload.h";


int main()
{
	int payloadsize = sizeof(embeded_payload) - 1;
	for (int i = 0; i < payloadsize; ++i)
	{
		low_entropy_payload[i] = (embeded_payload[i] >> 4) & 0xf;
		low_entropy_payload[i + payloadsize] = embeded_payload[i] & 0xf;
	}
	
	FILE* f = fopen(targetpath, "w");
	fprintf(f, "int BUFFER_Size = %d;\n", payloadsize * 2);
	fprintf(f, "unsigned char embeded_payload[] = \n");
	for (int i = 0; i < payloadsize * 2; i +=16)
	{
		fprintf(f, "\"");
		for (int j = i; j < (i + 16) && j < (payloadsize * 2); ++j)
		{
			fprintf(f, "\\x%02x", low_entropy_payload[j]);
		}
		fprintf(f, "\"\n");
	}


	fprintf(f, ";");


	fclose(f);
	return 0;

}