/*
 *  Test.c
 *  AIMLoginCrackLib
 *
 *  Created by Mischa Spiegelmock on 5/27/06.
 *  Copyright 2006 Mischa Spiegelmock. All rights reserved.
 *
 */

#include "AIMLoginCrack.h"

u_char *makeDigest(char *p, u_char *challenge);

int main(int argc, char **argv) {	
	//u_char digest[16] =  {0xA8, 0x3D, 0xFC, 0x58, 0xBC, 0x75, 0x5E, 
	//	0x6A, 0x8D, 0x67, 0xB6, 0xD2, 0xCE, 0x67, 0x52, 0x9};
	
	u_char challenge[] = {0x33, 0x35, 0x38, 0x34, 0x35, 0x39, 0x36, 0x31, 0x37, 0x32, 0x00};
	
	u_char *digest = makeDigest("qwerty", challenge);
	
	char *password = CrackAIMLogin(challenge, digest, "dict");
	
	if (password) {
		printf("\n\nPassword: %s\n", password);
		free(password);
	} else {
		printf("\n\nCould not find password :(\n");
	}
	
	return 0;
}

u_char *makeDigest(char *p, u_char *challenge) {
	u_char *digest = malloc(16);
	u_char pass_md5[16];
	
	MD5_CTX ctx;
	
	// md5 the pass
	MD5_CTX pass_ctx;
	MD5Init(&pass_ctx);
	MD5Update(&pass_ctx, p, strlen(p));
	MD5Final(pass_md5, &pass_ctx);
	
	MD5Init(&ctx);
	MD5Update(&ctx, challenge, strlen(challenge));
	MD5Update(&ctx, pass_md5, 16);
	MD5Update(&ctx, AIM_MD5_STRING, strlen(AIM_MD5_STRING));
	MD5Final(digest, &ctx);
	
	return digest;
}
