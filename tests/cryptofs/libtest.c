/*
 * Copyright (C) 2006 Christoph Hohmann
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>

#include "crypto.h"

static CryptoCtxGlobal *gcontext = NULL;

static char *getPassword(void)
{
    return "test";
}

static void freePassword(char *password)
{
}

static PasswordQuery query =
{
    getPassword,
    freePassword
};

CryptoCtxLocal *getTestContext()
{
    CryptoCtxLocal *lcontext;

    if (gcontext == NULL) {
	gcontext = crypto_create_global_ctx("AES256", "MD5", 2048, 256, &query);
	if (gcontext == NULL)
	    exit(2);
    }
    
    lcontext = crypto_create_local_ctx(gcontext);
    if (lcontext == NULL)
	exit(2);

    return lcontext;
}
