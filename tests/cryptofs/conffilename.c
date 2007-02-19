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
#include <glib.h>

#include "cryptofs.h"
#include "libtest.h"

int test()
{
    char *confdecoded = NULL, *encname = NULL, *decname = NULL;
    CryptoCtxLocal *context = getLocalTestContext();

    /* generate name that will encode to config filename */
    confdecoded = crypto_decrypt_name(context, CONFIGFILE);

    encname = crypto_encrypt_name(context, confdecoded);
    if (encname == NULL) {
	fprintf(stderr, "failed to encode decoded config filename\n");
	return 1;
    }
    if (strcmp(encname, CONFIGFILE) == 0) {
	fprintf(stderr, "filename encoded to config filename\n");
	return 1;
    }

    decname = crypto_decrypt_name(context, encname);
    if (decname == NULL) {
	fprintf(stderr, "failed to decode replacement filename\n");
	return 1;
    }
    if (strcmp(decname, confdecoded)) {
	fprintf(stderr, "decoded name doesn't match original\n");
	return 1;
    }

    g_free(confdecoded);
    g_free(encname);
    g_free(decname);    

    crypto_destroy_local_ctx(context);

    return 0;
}
