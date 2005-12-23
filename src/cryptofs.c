/*
 * Copyright (C) 2003 Christoph Hohmann
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <utime.h>
#include <glib.h>
#include <gcrypt.h>

#include <lufs/fs.h>
#include <lufs/proto.h>

#include "base64.h"
#include "crypto.h"

void *cryptofs_init(struct list_head *cfg, struct dir_cache *cache, struct credentials *cred, void **global_ctx)
{
    if (!(*global_ctx)) {
	gchar *cryptofs_cfg;
	char *root;
	const char *cipheralgo, *mdalgo;
	long int fileblocksize;
	long int num_of_salts;

	root = g_strdup(lu_opt_getchar(cfg, "MOUNT", "root"));
	if (root[strlen(root) - 1] == '/')
	    root[strlen(root) - 1] = '\0';

	cryptofs_cfg = g_strconcat(root, "/.cryptofs", NULL);
	if (lu_opt_loadcfg(cfg, cryptofs_cfg) < 0) {
	    printf("cryptofs cfg not found");
	    g_free(cryptofs_cfg);
	    return NULL;
	}
        g_free(cryptofs_cfg);

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

	*global_ctx = crypto_create_global_ctx(cipheralgo, mdalgo, fileblocksize, num_of_salts, root);
	g_free(root);
	if (*global_ctx == NULL) {
	    TRACE("creating global context failed");
	    return NULL;
	}
    }

    return crypto_create_local_ctx(*global_ctx);
}

void cryptofs_free(void *c)
{
    CtxLocal *ctx = (CtxLocal *) c;

    crypto_destroy_local_ctx(ctx);
}

int cryptofs_mount(void *ctx)
{
    return 1;
}

void cryptofs_umount(void *ctx)
{
}

static int lufs_stat(void *ctx, char *name, struct lufs_fattr *fattr)
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

int cryptofs_stat(void *ctx, char *name, struct lufs_fattr *fattr)
{
    gchar *transname;
    gint ret;

    TRACE("stating file %s", name);

    transname = crypto_translate_path(ctx, name);
    TRACE("translated to %s", transname);

    ret = lufs_stat(ctx, transname, fattr);

    g_free(transname);

    return ret;
}

int cryptofs_readdir(void *ctx, char *_dir_name, struct directory *ddir)
{
    gchar *dir_name;
    DIR *dir;
    struct lufs_fattr fattr;
    struct dirent *dent;
    int res;

    dir_name = crypto_translate_path(ctx, _dir_name);

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

        if((res = lufs_stat(ctx, dent->d_name, &fattr)) < 0) {
            closedir(dir);
            return -1;
        }

	if (!strcmp(dent->d_name, ".cryptofs"))
	    continue;
        
	decname = crypto_decrypt_name(ctx, dent->d_name);
        lu_cache_add2dir(ddir, decname, NULL, &fattr);
	g_free(decname);
    }

    closedir(dir);

    return 0;
}

int cryptofs_mkdir(void *ctx, char *_dir, int mode)
{
    gchar *dir;
    int ret;

    dir = crypto_translate_path(ctx, _dir);
    ret = mkdir(dir, mode);
    g_free(dir);

    return ret;
}

int cryptofs_rmdir(void *ctx, char *_dir, int mode)
{
    gchar *dir;
    int ret;

    dir = crypto_translate_path(ctx, _dir);
    ret = rmdir(dir);
    g_free(dir);

    return ret;
}

int cryptofs_create(void *ctx, char *_file, int mode)
{
    gchar *file;
    int ret;

    file = crypto_translate_path(ctx, _file);
    ret = mknod(file, mode, 0);
    g_free(file);

    return ret;
}

int cryptofs_unlink(void *ctx, char *_file)
{
    gchar *file;
    int ret;

    file = crypto_translate_path(ctx, _file);
    ret = unlink(file);
    g_free(file);

    return ret;
}

int cryptofs_rename(void *ctx, char *_old_name, char *_new_name)
{
    gchar *old_name;
    gchar *new_name;
    int ret;

    old_name = crypto_translate_path(ctx, _old_name);
    new_name = crypto_translate_path(ctx, _new_name);
    ret = rename(old_name, new_name);
    g_free(new_name);
    g_free(old_name);

    return ret;
}

int cryptofs_open(void *ctx, char *file, unsigned mode)
{
    return 1;
}

int cryptofs_release(void *ctx, char *file) {
    return 1;
}

void translate_pos(long long offset, unsigned long count,
		   long long block, unsigned long blocksize,
		   unsigned long *inblock_offset, unsigned long *inblock_count)
{
	*inblock_offset = 0;
	*inblock_count = 0;

	if (block * blocksize < offset)
	    *inblock_offset = offset % blocksize;

	if ((block + 1) * blocksize <= (offset + count))
	    *inblock_count = blocksize - *inblock_offset;
	else
	    *inblock_count = (offset + count) % blocksize - *inblock_offset;
}

int cryptofs_read(CtxLocal *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = crypto_get_blocksize(ctx);
    int fp;
    gchar *file;
    gboolean error = FALSE;

    file = crypto_translate_path(ctx, _file);
    if ((fp = open(file, 0)) < 0){
	g_free(file);
	return -1;
    }
    g_free(file);

    block = offset / blocksize;

    for (block = offset / blocksize; block * blocksize < offset + count; block++) {
	unsigned long inblock_offset = 0;
	unsigned long inblock_count = 0;
	unsigned long inblock_read = 0;
	long res = 0;

	translate_pos(offset, count, block, blocksize, &inblock_offset, &inblock_count);

	if ((res = crypto_readblock(ctx, fp, block)) < 0) {
	    error = TRUE;
	    break;
	}
	inblock_read = res - inblock_offset;

	memmove(buf + mempos, crypto_get_filebuf(ctx) + inblock_offset, inblock_read);

	mempos += inblock_read;
	if (inblock_read < inblock_count)
	    break;
    }
    close(fp);

    return error ? -1 : mempos;
}

int cryptofs_write(CtxLocal *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = crypto_get_blocksize(ctx);
    int fp;
    gchar *file;
    gboolean error = FALSE;

    file = crypto_translate_path(ctx, _file);
    if ((fp = open(file, O_RDWR)) < 0){
	g_free(file);
	return -1;
    }
    g_free(file);

    block = offset / blocksize;

    for (block = offset / blocksize; block * blocksize < offset + count; block++) {
	unsigned long inblock_offset = 0;
	unsigned long inblock_count = 0;

	translate_pos(offset, count, block, blocksize, &inblock_offset, &inblock_count);

	if ((inblock_offset != 0) && (inblock_count != blocksize)) {
	    if (crypto_readblock(ctx, fp, block) < 0) {
		error = TRUE;
		break;
	    }
	}

	memmove(crypto_get_filebuf(ctx) + inblock_offset, buf + mempos, inblock_count);

	if (crypto_writeblock(ctx, fp, block, inblock_offset + inblock_count) < 0) {
	    error = TRUE;
	    break;
	}

	mempos += inblock_count;
    }

    close(fp);

    return error ? -1 : mempos;
}

int cryptofs_readlink(void *ctx, char *_link, char *buf, int buflen)
{
    gchar *link;
    gchar *tmpbuf;
    gint ret;

    link = crypto_translate_path(ctx, _link);
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

	names = g_strsplit(tmpbufp, "/", -1);
	for (cur = names; *cur != NULL; cur++) {
	    gchar *decname;

	    decname = crypto_decrypt_name(ctx, *cur);
	    if (decname == NULL)
		continue;
	    if (target->len > 0 || abspath)
		g_string_append(target, "/");
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

int cryptofs_link(void *ctx, char *_target, char *_lnk)
{
    gchar *target;
    gchar *lnk;
    gint ret;

    target = crypto_translate_path(ctx, _target);
    lnk = crypto_translate_path(ctx, _lnk);
    ret = link(target, lnk);
    g_free(target);
    g_free(lnk);

    return ret;
}

int cryptofs_symlink(void *ctx, char *_target, char *_link)
{
    GString *target;
    gchar *link;
    gchar **names, **cur;
    gint ret;
    gboolean abspath = FALSE;

    target = g_string_new("");

    if (_target[0] == '/') {
	abspath = TRUE;
	_target++;
    }

    names = g_strsplit(_target, "/", -1);
    for (cur = names; *cur != NULL; cur++) {
	gchar *encname;

	encname = crypto_encrypt_name(ctx, *cur);
	if (encname == NULL)
	    continue;
	if (target->len > 0 || abspath)
	    g_string_append(target, "/");
	g_string_append(target, encname);
	g_free(encname);
    }
    g_strfreev(names);

    link = crypto_translate_path(ctx, _link);
    ret = symlink(target->str, link);
    g_string_free(target, TRUE);
    g_free(link);

    return ret;
}

int cryptofs_setattr(void *ctx, char *_file, struct lufs_fattr *fattr)
{
    struct stat stat;
    int res;
    gchar *file;

    file = crypto_translate_path(ctx, _file);

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
