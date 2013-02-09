/*
 * Copyright (C) 2003-2013 Christoph Hohmann
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

/* #define DEBUG */

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>
#include <glib.h>

#include <fs.h>
#include <proto.h>

#include "cryptofs.h"
#include "crypto.h"
#include "utils.h"

typedef struct _Ctx Ctx;

struct _Ctx {
    CryptoCtxLocal	*cryptoctx;
    gchar		*root;
};

/* helper functions */

static int lufs_stat(char *name, struct lufs_fattr *fattr)
{
    struct stat stat;

    if(lstat(name, &stat) < 0) {
        return -1;
    }

    fattr->f_mode = stat.st_mode;
    fattr->f_nlink = stat.st_nlink;
    fattr->f_uid = (getuid() == stat.st_uid) ? 1 : 0;
    fattr->f_gid = (getgid() == stat.st_gid) ? 1 : 0;
    fattr->f_size = stat.st_size;
    fattr->f_atime = stat.st_atime;
    fattr->f_mtime = stat.st_mtime;
    fattr->f_ctime = stat.st_ctime;

    return 0;
}

static gchar *translate_path(Ctx *ctx, char *path)
{
    const gchar *root;
    gchar *pathp = path;
    gchar *retstr;
    gboolean addroot = FALSE;

    root = ctx->root;

    if (!strncmp(pathp, root, strlen(root))) {
	pathp += strlen(root);
	addroot = TRUE;
    } else if (pathp[0] == '/') {
	pathp += 1;
	addroot = TRUE;
    }

    retstr = crypto_translate_path(ctx->cryptoctx, pathp);

    if (addroot) {
	char *tmp;

	tmp = g_strconcat(root, G_DIR_SEPARATOR_S, retstr, NULL);
	g_free(retstr);
	retstr = tmp;
    }

    return retstr;
}

/* LUFS functions */

void *cryptofs_init(struct list_head *cfg, struct dir_cache *cache, struct credentials *cred, void **global_ctx)
{
    Ctx *ctx;

    if (!(*global_ctx)) {
	gchar *cryptofs_cfg;
	const char *root;
	const gchar *cipheralgo, *mdalgo;
	long int fileblocksize;
	long int num_of_salts;

        g_slice_set_config(G_SLICE_CONFIG_ALWAYS_MALLOC, TRUE);

	root = lu_opt_getchar(cfg, "MOUNT", "root");

	cryptofs_cfg = g_strconcat(root, G_DIR_SEPARATOR_S, CONFIGFILE, NULL);
	if (!read_config(cryptofs_cfg, &cipheralgo, &mdalgo, &fileblocksize, &num_of_salts)) {
	    /* Try old config file */
	    if (lu_opt_loadcfg(cfg, cryptofs_cfg) < 0) {
		printf("cryptofs cfg not found");
	        g_free(cryptofs_cfg);
	        return NULL;
	    }

	    if ((cipheralgo = lu_opt_getchar(cfg, "CRYPTOFS", "cipher")) == NULL) {
    		printf("CRYPTOFS::cipher missing in config file\n");
    	        return NULL;
	    }
	    if ((mdalgo = lu_opt_getchar(cfg, "CRYPTOFS", "md")) == NULL) {
		printf("CRYPTOFS::md missing in config file\n");
	        return NULL;
	    }
	    if (lu_opt_getint(cfg, "CRYPTOFS", "blocksize", &fileblocksize, 0) < 0) {
		printf("CRYPTOFS::blocksize missing in config file\n");
	        return NULL;
	    }
	    if (lu_opt_getint(cfg, "CRYPTOFS", "salts", &num_of_salts, 0) < 0) {
		printf("CRYPTOFS::salts missing in config file\n");
		return NULL;
	    }
	}
        g_free(cryptofs_cfg);

	*global_ctx = crypto_create_global_ctx_default(cipheralgo, mdalgo, fileblocksize, num_of_salts);
	if (*global_ctx == NULL) {
	    TRACE("creating global context failed");
	    return NULL;
	}
    }

    ctx = g_new0(Ctx, 1);
    ctx->cryptoctx = crypto_create_local_ctx(*global_ctx);
    if (ctx->cryptoctx == NULL) {
        TRACE("creating global context failed");
	g_free(ctx);
	return NULL;
    }
    ctx->root = g_strdup(lu_opt_getchar(cfg, "MOUNT", "root"));
    if (ctx->root[strlen(ctx->root) - 1] == '/')
        ctx->root[strlen(ctx->root) - 1] = '\0';
    return ctx;
}

void cryptofs_free(void *c)
{
    Ctx *ctx = (Ctx *) c;

    crypto_destroy_local_ctx(ctx->cryptoctx);
    g_free(ctx->root);
    g_free(ctx);
}

int cryptofs_mount(Ctx *ctx)
{
    return 1;
}

void cryptofs_umount(Ctx *ctx)
{
}

int cryptofs_stat(Ctx *ctx, char *name, struct lufs_fattr *fattr)
{
    gchar *transname;
    gint ret;

    TRACE("stating file %s", name);

    transname = translate_path(ctx, name);
    TRACE("translated to %s", transname);

    ret = lufs_stat(transname, fattr);

    g_free(transname);

    return ret;
}

int cryptofs_readdir(Ctx *ctx, char *_dir_name, struct directory *ddir)
{
    gchar *dir_name;
    DIR *dir;
    struct lufs_fattr fattr;
    struct dirent *dent;
    int res;

    dir_name = translate_path(ctx, _dir_name);

    if(chdir(dir_name) < 0) {
	g_free(dir_name);
        return -1;
    }

    if(!(dir = opendir(dir_name))) {
	g_free(dir_name);
        return -1;
    }
    g_free(dir_name);

    while((dent = readdir(dir))){
	gchar *decname;

        if((res = lufs_stat(dent->d_name, &fattr)) < 0) {
            closedir(dir);
            return -1;
        }

	if (!strcmp(dent->d_name, CONFIGFILE))
	    continue;
        
	decname = crypto_decrypt_name(ctx->cryptoctx, dent->d_name);
        lu_cache_add2dir(ddir, decname, NULL, &fattr);
	g_free(decname);
    }

    closedir(dir);

    return 0;
}

int cryptofs_mkdir(Ctx *ctx, char *_dir, int mode)
{
    gchar *dir;
    int ret;

    dir = translate_path(ctx, _dir);
    ret = mkdir(dir, mode);
    g_free(dir);

    return ret;
}

int cryptofs_rmdir(Ctx *ctx, char *_dir, int mode)
{
    gchar *dir;
    int ret;

    dir = translate_path(ctx, _dir);
    ret = rmdir(dir);
    g_free(dir);

    return ret;
}

int cryptofs_create(Ctx *ctx, char *_file, int mode)
{
    gchar *file;
    int ret;

    file = translate_path(ctx, _file);
    ret = mknod(file, mode, 0);
    g_free(file);

    return ret;
}

int cryptofs_unlink(Ctx *ctx, char *_file)
{
    gchar *file;
    int ret;

    file = translate_path(ctx, _file);
    ret = unlink(file);
    g_free(file);

    return ret;
}

int cryptofs_rename(Ctx *ctx, char *_old_name, char *_new_name)
{
    gchar *old_name;
    gchar *new_name;
    int ret;

    old_name = translate_path(ctx, _old_name);
    new_name = translate_path(ctx, _new_name);
    ret = rename(old_name, new_name);
    g_free(new_name);
    g_free(old_name);

    return ret;
}

int cryptofs_open(Ctx *ctx, char *file, unsigned mode)
{
    return 1;
}

int cryptofs_release(Ctx *ctx, char *file) {
    return 1;
}

int cryptofs_read(Ctx *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    int result;
    int fp;
    gchar *file;

    file = translate_path(ctx, _file);
    if ((fp = open(file, 0)) < 0){
	g_free(file);
	return -1;
    }
    g_free(file);

    result = crypto_read(ctx->cryptoctx, fp, buf, count, offset);

    close(fp);

    return result;
}

int cryptofs_write(Ctx *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    int result;
    int fp;
    gchar *file;

    file = translate_path(ctx, _file);
    if ((fp = open(file, O_RDWR)) < 0){
	g_free(file);
	return -1;
    }
    g_free(file);

    result = crypto_write(ctx->cryptoctx, fp, buf, count, offset);

    close(fp);

    return result;
}

int cryptofs_readlink(Ctx *ctx, char *_link, char *buf, int buflen)
{
    gchar *link;
    gchar *tmpbuf;
    gint ret;

    link = translate_path(ctx, _link);
    tmpbuf = g_malloc0(buflen * 2);

    ret = readlink(link, tmpbuf, buflen * 2);
    g_free(link);

    if (ret >= 0) {
	gboolean abspath = FALSE;
	gchar *tmpbufp = tmpbuf;
	GString *target;
	gchar **names, **cur;

	target = g_string_new("");

	if (tmpbufp[0] == '/') {
	    abspath = TRUE;
    	    tmpbufp++;
	}

	names = g_strsplit(tmpbufp, G_DIR_SEPARATOR_S, -1);
	for (cur = names; *cur != NULL; cur++) {
	    gchar *decname;

	    decname = crypto_decrypt_name(ctx->cryptoctx, *cur);
	    if (decname == NULL)
		continue;
	    if (target->len > 0 || abspath)
		g_string_append(target, G_DIR_SEPARATOR_S);
	    g_string_append(target, decname);
	    g_free(decname);
	}
	g_strfreev(names);

	strncpy(buf, target->str, buflen);
	g_string_free(target, TRUE);
    }
    g_free(tmpbuf);

    return ret;
}

int cryptofs_link(Ctx *ctx, char *_target, char *_lnk)
{
    gchar *target;
    gchar *lnk;
    gint ret;

    target = translate_path(ctx, _target);
    lnk = translate_path(ctx, _lnk);
    ret = link(target, lnk);
    g_free(target);
    g_free(lnk);

    return ret;
}

int cryptofs_symlink(Ctx *ctx, char *_target, char *_link)
{
    gchar *link, *target;
    gint ret;

    target = crypto_translate_path(ctx->cryptoctx, _target);
    if (target == NULL)
	return -1;

    link = translate_path(ctx, _link);
    if (link == NULL) {
	g_free(target);
	return -1;
    }
    ret = symlink(target, link);
    g_free(target);
    g_free(link);

    return ret;
}

int cryptofs_setattr(Ctx *ctx, char *_file, struct lufs_fattr *fattr)
{
    struct stat stat;
    int res;
    gchar *file;

    file = translate_path(ctx, _file);

    if((res = lstat(file, &stat)) < 0)
        goto out;

    if(stat.st_size > fattr->f_size) {
        TRACE("truncating file to %Ld bytes", fattr->f_size);
        if((res = truncate(file, fattr->f_size)) < 0)
            goto out;
    }

    if(stat.st_mode != fattr->f_mode) {
        TRACE("set mode %o, old=%o", (unsigned)fattr->f_mode, (unsigned)stat.st_mode);
        if((res = chmod(file, fattr->f_mode)) < 0)
            goto out;
    }

    if((stat.st_atime != (time_t)fattr->f_atime) || (stat.st_mtime != (time_t)fattr->f_mtime)) {
        struct utimbuf utim = {fattr->f_atime, fattr->f_mtime};

        if((res = utime(file, &utim)) < 0)
            goto out;
    }

  out:
    g_free(file);
    return res;    
}
