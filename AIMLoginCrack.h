/*
 *  AIMLoginCrack.h
 *  AIMLoginCrackLib
 *
 *  Created by Mischa Spiegelmock on 5/27/06.
 *  Copyright 2006 Mischa Spiegelmock. All rights reserved.
 *
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/errno.h>
#include "md5.h"
#include <pthread.h>

#define AIM_MD5_STRING "AOL Instant Messenger (SM)"

struct crackaim_auth_info {
	const u_char *challenge;
	const u_char *digest;
};

typedef struct crackaim_auth_info crackaim_auth_info_t;

const u_char *CrackAIMLogin(const u_char *challenge, const u_char digest[16], const char *dictFile);
int CrackAIM_TestPassword(crackaim_auth_info_t *auth, const u_char *password);
