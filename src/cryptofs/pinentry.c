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
#include "passwordquery.h"

char *args[] = {
    "pinentry",
    NULL,
};

char *getpin(char *desc, char *prompt)
{
    int childin, childout;
    char *out, *ret = NULL;
    int state = 0;
    gboolean exit = FALSE;
    GPid pid;

    if (!g_spawn_async_with_pipes(NULL, args, NULL, G_SPAWN_STDERR_TO_DEV_NULL | G_SPAWN_SEARCH_PATH, NULL, NULL, &pid, &childin, &childout, NULL, NULL))
	return NULL;

    while(!exit && ((out = reads(childout)) != NULL)) {
	 /* printf("%s", out); */

	if (strncmp(out, "OK\n", 3) == 0 || strncmp(out, "OK ", 3) == 0)
	{
	    switch(state) {
	    case 0:
		writes(childin, "SETDESC ");
		writes(childin, desc);
		writes(childin, "\n");
		break;
	    case 1:
		writes(childin, "SETPROMPT ");
		writes(childin, prompt);
		writes(childin, "\n");
		break;
	    case 2: 
	    {
		char *tty;

		tty = ttyname(0);
		if (tty != NULL) {
		    writes(childin, "OPTION ttyname=");
		    writes(childin, tty);
		    writes(childin, "\n");
		    break; 
		}
		state++;
	    }
	    case 3:
		writes(childin, "GETPIN\n");
		break;
	    case 4:
		exit = TRUE;
	    }
	    state++;
	} else if (strncmp(out, "D ", 2) == 0) {
	    if (state == 4) {
		g_free(ret);
	        ret = g_strndup(out + 2, strlen(out) - 3);
	    }
	} else {
	    g_free(out);
	    break;
	}
	g_free(out);
    }

    g_spawn_close_pid(pid);
    close(childin);
    close(childout);

    return ret;
}

static char *getPassword(void)
{
    return getpin("Enter password for filesystem", "Password:");
}

static void freePassword(char *password)
{
    memset(password, '\0', strlen(password));
    g_free(password);
}

static PasswordQuery query =
{
    getPassword,
    freePassword
};

PasswordQuery *getDefaultPasswordQuery(void)
{
	return &query;
}
