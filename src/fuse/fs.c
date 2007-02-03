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

#include <config.h>

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#ifdef BSD
#include <sys/statvfs.h>
#else
#include <sys/statfs.h>
#endif /* BSD */
#include <pthread.h>

#include <fuse.h>

#include "cryptofs.h"
#include "crypto.h"
#include "utils.h"
#include "fs.h"

static gchar *rootpath = NULL;
static CryptoCtxGlobal *global_ctx = NULL;
static pthread_key_t context_key;

CryptoCtxLocal *get_ctx()
{
    CryptoCtxLocal *ctx;

    ctx = (CryptoCtxLocal *) pthread_getspecific(context_key);
    if (ctx == NULL) {
	ctx = crypto_create_local_ctx(global_ctx);
	pthread_setspecific(context_key, ctx);
    }

    return ctx;
}

static gchar *translate_path(CryptoCtxLocal *ctx, const char *path)
{
    gchar *tmp, *retstr;

    tmp = crypto_translate_path(ctx, path);

    retstr = g_strconcat(rootpath, G_DIR_SEPARATOR_S, tmp, NULL);
    g_free(tmp);

    return retstr;
}

static int cryptofs_getattr(const char *_path, struct stat *stbuf)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = lstat(path, stbuf);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_readlink(const char *_path, char *buf, size_t size)
{
    gchar *path;
    int res;
    gchar *tmpbuf;
    CryptoCtxLocal *ctx;
    GString *target;
    gchar **names, **cur;

    ctx = get_ctx();

    tmpbuf = g_malloc0(size * 2);
    path = translate_path(ctx, _path);
    res = readlink(path, tmpbuf, size - 1);
    g_free(path);
    if(res == -1) {
	g_free(tmpbuf);
        return -errno;
    }
    tmpbuf[res] = '\0';

    target = g_string_new("");

    names = g_strsplit(tmpbuf, G_DIR_SEPARATOR_S, -1);
    for (cur = names; *cur != NULL; cur++) {
	gchar *decname;

	decname = crypto_decrypt_name(ctx, *cur);
	if (decname == NULL)
	    continue;
	if (target->len > 0)
	    g_string_append(target, G_DIR_SEPARATOR_S);
	g_string_append(target, decname);
	g_free(decname);
    }
    g_strfreev(names);

    strncpy(buf, target->str, size);
    g_string_free(target, TRUE);

    g_free(tmpbuf);

    return 0;
}

static int cryptofs_opendir(const char *_path, struct fuse_file_info *fi)
{
    gchar *path;

    path = translate_path(get_ctx(), _path);
    DIR *dp = opendir(path);
    g_free(path);
    if (dp == NULL)
        return -errno;

    fi->fh = (unsigned long) dp;
    return 0;
}

static int cryptofs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    gchar *decname;
    DIR *dp = (DIR *) fi->fh;
    struct dirent *de;
    gboolean is_root_dir = FALSE;

    if(strlen(path) == 1 && path[0] == '/')
	is_root_dir = TRUE;

    seekdir(dp, offset);
    while ((de = readdir(dp)) != NULL) {
        struct stat st;

	// skip the config file
	if(is_root_dir && strcmp(de->d_name, CONFIGFILE) == 0)
	    continue;

        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
	decname = crypto_decrypt_name(get_ctx(), de->d_name);
        if (filler(buf, decname, &st, telldir(dp))) {
	    g_free(decname);
            break;
	}
	g_free(decname);
    }

    return 0;
}

static int cryptofs_releasedir(const char *path, struct fuse_file_info *fi)
{
    DIR *dp = (DIR *) fi->fh;
    (void) path;
    closedir(dp);
    return 0;
}

static int cryptofs_mknod(const char *_path, mode_t mode, dev_t rdev)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    /* On Linux this could just be 'mknod(path, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(path, mode);
    else
        res = mknod(path, mode, rdev);
    g_free(path);
    if (res == -1)
        return -errno;

    return 0;
}

static int cryptofs_mkdir(const char *_path, mode_t mode)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = mkdir(path, mode);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_unlink(const char *_path)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = unlink(path);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_rmdir(const char *_path)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = rmdir(path);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_symlink(const char *_from, const char *_to)
{
    gchar *from, *to;
    int res;
    CryptoCtxLocal *ctx;

    ctx = get_ctx();
    from = translate_path(ctx, _from);
    to = translate_path(ctx, _to);
    res = symlink(from, to);
    g_free(from);
    g_free(to);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_rename(const char *_from, const char *_to)
{
    gchar *from, *to;
    int res;
    CryptoCtxLocal *ctx;

    ctx = get_ctx();
    from = translate_path(ctx, _from);
    to = translate_path(ctx, _to);
    res = rename(from, to);
    g_free(from);
    g_free(to);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_link(const char *_from, const char *_to)
{
    gchar *from, *to;
    int res;
    CryptoCtxLocal *ctx;

    ctx = get_ctx();
    from = translate_path(ctx, _from);
    to = translate_path(ctx, _to);
    res = link(from, to);
    g_free(from);
    g_free(to);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_chmod(const char *_path, mode_t mode)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = chmod(path, mode);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_chown(const char *_path, uid_t uid, gid_t gid)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = lchown(path, uid, gid);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_truncate(const char *_path, off_t size)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = truncate(path, size);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_utime(const char *_path, struct utimbuf *buf)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = utime(path, buf);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}


static int cryptofs_open(const char *_path, struct fuse_file_info *fi)
{
    gchar *path;
    int fd;
    int flags;

    path = translate_path(get_ctx(), _path);
    flags = fi->flags;
    if(flags & O_WRONLY) {
    	flags &= ~O_WRONLY;
	flags |= O_RDWR;
    }
    fd = open(path, flags);
    g_free(path);
    if(fd == -1)
        return -errno;

    fi->fh = fd;
    return 0;
}

static int cryptofs_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = crypto_read(get_ctx(), fi->fh, buf, size, offset);
    if(res == -1)
        res = -errno;

    return res;
}

static int cryptofs_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int res;

    (void) path;
    res = crypto_write(get_ctx(), fi->fh, (void *) buf, size, offset);
    if(res == -1)
        res = -errno;

    return res;
}

static int cryptofs_statfs(const char *_path, struct statvfs *stbuf)
{
    gchar *path;
    int res;

    path = translate_path(get_ctx(), _path);
    res = statvfs(path, stbuf);
    g_free(path);
    if(res == -1)
        return -errno;

    return 0;
}

static int cryptofs_release(const char *path, struct fuse_file_info *fi)
{
    (void) path;
    close(fi->fh);

    return 0;
}

static int cryptofs_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    int res;
    (void) path;

    if (isdatasync)
#ifdef BSD
	res = fsync(fi->fh);
#else
        res = fdatasync(fi->fh);
#endif /* BSD */
    else
        res = fsync(fi->fh);
    if(res == -1)
        return -errno;

    return 0;
}

static struct fuse_operations cryptofs_oper = {
    .getattr	= cryptofs_getattr,
    .readlink	= cryptofs_readlink,
    .opendir	= cryptofs_opendir,
    .readdir	= cryptofs_readdir,
    .releasedir	= cryptofs_releasedir,
    .mknod	= cryptofs_mknod,
    .mkdir	= cryptofs_mkdir,
    .symlink	= cryptofs_symlink,
    .unlink	= cryptofs_unlink,
    .rmdir	= cryptofs_rmdir,
    .rename	= cryptofs_rename,
    .link	= cryptofs_link,
    .chmod	= cryptofs_chmod,
    .chown	= cryptofs_chown,
    .truncate	= cryptofs_truncate,
    .utime	= cryptofs_utime,
    .open	= cryptofs_open,
    .read	= cryptofs_read,
    .write	= cryptofs_write,
    .statfs	= cryptofs_statfs,
    .release	= cryptofs_release,
    .fsync	= cryptofs_fsync,
};

typedef void (*freeFunc) (void *);

void fs_init(gchar *_rootpath, CryptoCtxGlobal *_global_ctx)
{
    rootpath = _rootpath;
    global_ctx = _global_ctx;

    pthread_key_create(&context_key, (freeFunc) crypto_destroy_local_ctx);
}

struct fuse_operations *fs_get_fuse_operations()
{
    return &cryptofs_oper;
}
