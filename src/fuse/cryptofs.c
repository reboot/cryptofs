/*
 * Copyright (C) 2006-2013 Christoph Hohmann
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

#include <config.h>

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#include <fuse.h>

#include "cryptofs.h"
#include "crypto.h"
#include "utils.h"
#include "fs.h"

static const gchar *SHOW_FUSE_OPTIONS = "Show FUSE options";

static const gchar *help_fuse(const gchar *str, gpointer data);

static gchar *rootpath = NULL;

static GOptionEntry entries[] = 
{
  { "root", 'r', 0, G_OPTION_ARG_STRING, &rootpath, "Path of encrypted directory", "R" },
  { NULL }
};

static GOptionEntry entries_fuse[] =
{
    { "help-fuse", 0, 0, 0, NULL, "none", NULL },
    { NULL }
};

static char *help_fuse_argv[] = {
    NULL,
    "--help",
    NULL,
};

typedef void (*freeFunc) (void *);

int main(int argc, char *argv[])
{
    GError *error = NULL;
    GOptionContext *context;
    GOptionGroup *group_fuse;
    gchar *cryptofs_cfg;
    gchar *cipheralgo, *mdalgo;
    long int fileblocksize;
    long int num_of_salts;

    umask(0);
    g_slice_set_config(G_SLICE_CONFIG_ALWAYS_MALLOC, TRUE);

    help_fuse_argv[0] = argv[0];

    context = g_option_context_new ("[FUSE OPTIONS...]");
    g_option_context_set_ignore_unknown_options(context, TRUE);
    g_option_context_add_main_entries (context, entries, NULL);
    group_fuse = g_option_group_new("fuse", "x", SHOW_FUSE_OPTIONS, NULL, NULL);
    g_option_group_add_entries(group_fuse, entries_fuse);
    g_option_group_set_translate_func(group_fuse, help_fuse, NULL, NULL);
    g_option_context_add_group(context, group_fuse);
    g_option_context_parse (context, &argc, &argv, &error);
    g_option_context_free(context);

    if (rootpath == NULL) {
	fprintf(stderr, "No path for encrypted directory specified (see --help)\n");
	exit(1);
    }

    if (!g_path_is_absolute(rootpath)) {
	gchar *oldpath = rootpath;
	gchar *curpath = g_get_current_dir();

	rootpath = g_strconcat(curpath, G_DIR_SEPARATOR_S, rootpath, NULL);
	g_free(curpath);
	g_free(oldpath);
    }

    cryptofs_cfg = g_strconcat(rootpath, G_DIR_SEPARATOR_S, CONFIGFILE, NULL);
    if (!read_config(cryptofs_cfg, &cipheralgo, &mdalgo, &fileblocksize, &num_of_salts)) {
	fprintf(stderr, "Could not read config for encrypted directory\n"
			"Check that %s/" CONFIGFILE " is available and correct\n", rootpath);
	exit(1);
    }
    g_free(cryptofs_cfg);

    fs_init(rootpath, crypto_create_global_ctx_default(cipheralgo, mdalgo, fileblocksize, num_of_salts));

    return fuse_main(argc, argv, fs_get_fuse_operations(), NULL);
}

static const gchar *help_fuse(const gchar *str, gpointer data)
{
    if (g_str_equal(str, SHOW_FUSE_OPTIONS))
	return SHOW_FUSE_OPTIONS;

    fuse_main(2, help_fuse_argv, NULL, NULL);
    exit(0);
}
