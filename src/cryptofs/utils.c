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
#include <unistd.h>
#include <string.h>

#include <glib.h>

#include "utils.h"

void writes(int fs, char *str)
{
    write(fs, str, strlen(str));
}

char *reads(int fd)
{
    GString *str;
    int nbytes;
    char buf;
    char *result;

    str = g_string_sized_new(64);
    while ((nbytes = read(fd, &buf, 1)) > 0) {
	g_string_append_c(str, buf);

	if (buf == '\n')
	    break;
    }

    result = str->str;
    g_string_free(str, FALSE);

    if (nbytes == 0) {
	g_free(result);
	return NULL;
    }

    return result;
}

