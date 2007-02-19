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
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>

#include "cryptofs.h"
#include "libtest.h"

#define FILENAME "writereadblock.data"
#define BLOCKCOUNT 5

static char bytes[] = {0x0, 0xff, 0xaa, 0x55, 0xf0, 0x0f};

int test()
{
    int i;
    CryptoCtxLocal *context = getLocalTestContext();
    int blocksize;
    char *block, *filebuf;

    blocksize = crypto_get_blocksize(context);
    block = malloc(blocksize);
    filebuf = crypto_get_filebuf(context);

    for (i = 0; i < sizeof(bytes) / sizeof(char); i++) {
	int fp, j;

	memset(block, bytes[i], blocksize);

	fp = open(FILENAME, O_RDWR | O_CREAT, S_IRWXU);
	for (j = 0; j < BLOCKCOUNT; j++) {
	    memcpy(crypto_get_filebuf(context), block, blocksize);
	    if (crypto_writeblock(context, fp, j, blocksize) != blocksize) {
		perror("Writing test data failed");
		return 1;
	    }
	}
	close(fp);

	fp = open(FILENAME, O_RDONLY);
	for (j = 0; j < BLOCKCOUNT; j++) {
	    memset(crypto_get_filebuf(context), 0, blocksize);
	    if (crypto_readblock(context, fp, j) != blocksize) {
		perror("Reading test data failed");
		return 1;
	    }
	    if (memcmp(block, crypto_get_filebuf(context), blocksize) != 0) {
		fprintf(stderr, "Comparing data failed\n");
		return 1;
	    }
	}
	close(fp);

	unlink(FILENAME);
    }

    free(block);
    crypto_destroy_local_ctx(context);

    return 0;
}
