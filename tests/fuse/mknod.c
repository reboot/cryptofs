/*
 * Copyright (C) 2007 Christoph Hohmann
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <fuse.h>

#include "libtest.h"
#include "fs.h"

int test()
{
    CryptoCtxLocal *context;
    struct fuse_operations *ops;
    mode_t mode;

    fs_init(".", getGlobalTestContext());
    ops = fs_get_fuse_operations();

    mode = S_IFREG | O_WRONLY | O_CREAT | O_EXCL; 
    if (ops->mknod("test", mode, 0) < 0) {
	perror("Cound not create file");
	return 1;
    }

    unlink("kjKk7g==");

    return 0;
}
