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
#include "getpw.h"

struct cryptofs_global {
    int				  count;

    gchar			 *root;
    int				  cipher;
    gchar			 *key;
    guint			  keylen;
    guchar			**salts;
    int			  	  blocksize;
    long int			  fileblocksize;
    long int			  num_of_salts;
};

struct cryptofs_context {
    struct cryptofs_global	 *global;

    GcryCipherHd 	  	  cipher_hd;
    struct list_head 	 	 *cfg;
    void			 *filebuf;
};

void generate_key(int cipher, int md, const gchar *pass, gchar **key, guint *keylen)
{
    int i;
    int mdlen, buflen;
    gchar *keybuf;

    *keylen = gcry_cipher_algo_info(cipher, GCRYCTL_GET_KEYLEN, NULL, 0);
    mdlen = gcry_md_get_algo_dlen(md);

    buflen = mdlen < *keylen ? *keylen : mdlen;
    keybuf = g_new0(unsigned char, buflen);
    memset(keybuf, 0, buflen);

    gcry_md_hash_buffer(md, keybuf, pass, strlen(pass));
    if (mdlen < *keylen)
	for (i = mdlen; i < *keylen; i++)
	    keybuf[i] = keybuf[i % mdlen];

    *key = keybuf;
}

GcryCipherHd open_cipher(struct cryptofs_global *gctx, int cipher)
{
    GcryCipherHd cipherhd = NULL;

    cipherhd = gcry_cipher_open(cipher, GCRY_CIPHER_MODE_CFB, 0);
    if ((cipherhd != NULL) && (gcry_cipher_setkey(cipherhd, gctx->key, gctx->keylen) != GCRYERR_SUCCESS)) {
	gcry_cipher_close(cipherhd);
	cipherhd  = NULL;
    }

    return cipherhd;
}

void *cryptofs_init(struct list_head *cfg, struct dir_cache *cache, struct credentials *cred, void **global_ctx)
{
    struct cryptofs_global *gctx;
    struct cryptofs_context *ctx;
    GcryCipherHd cipher_hd;

    if (!(*global_ctx)) {
	gchar *cryptofs_cfg;
	char *root;
	char *salts;
	const char *cipheralgo, *mdalgo;
	int cipher, md;
	long int fileblocksize;
	long int num_of_salts;
	int i;
	char *pass;

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
	cipher = gcry_cipher_map_name(cipheralgo);
	if ((mdalgo = lu_opt_getchar(cfg, "CRYPTOFS", "md")) == NULL) {
	    printf("CRYPTOFS::md missing in config file\n");
	    return NULL;
	}
	md = gcry_md_map_name(mdalgo);
	if (lu_opt_getint(cfg, "CRYPTOFS", "blocksize", &fileblocksize, 0) < 0) {
	    printf("CRYPTOFS::blocksize missing in config file\n");
	    return NULL;
	}
	if (lu_opt_getint(cfg, "CRYPTOFS", "salts", &num_of_salts, 0) < 0) {
	    printf("CRYPTOFS::salts missing in config file\n");
	    return NULL;
	}

	gctx = g_new0(struct cryptofs_global, 1);
	gctx->cipher = cipher;
	gctx->root = root;
	gctx->fileblocksize = fileblocksize;
	gctx->num_of_salts = num_of_salts;

	pass = getpwd("Enter password:");
	generate_key(gctx->cipher, md, pass, &gctx->key, &gctx->keylen);
	putpwd(pass);

	cipher_hd = open_cipher(gctx, gctx->cipher);
	gctx->blocksize = gcry_cipher_algo_info(gctx->cipher, GCRYCTL_GET_BLKLEN, NULL, 0);
	salts = g_malloc0(num_of_salts * gctx->blocksize);
	gcry_cipher_setiv(cipher_hd, salts, gctx->blocksize);
	gcry_cipher_encrypt(cipher_hd, salts, num_of_salts * gctx->blocksize, NULL, 0);
	gctx->salts = g_new0(guchar *, num_of_salts);
	for (i = 0; i < num_of_salts; i++)
	    gctx->salts[i] = &salts[i * gctx->blocksize];
	gctx->count = 1;
	*global_ctx = gctx;
	gcry_cipher_close(cipher_hd);
	cipher_hd = NULL;
    } else {
	gctx = (struct cryptofs_global *) *global_ctx;
	gctx->count++;
    }

    cipher_hd = open_cipher(gctx, gctx->cipher);
    if (cipher_hd == NULL) {
        printf("failed to initialize cipher\n");
        return NULL;
    }

    ctx = g_new0(struct cryptofs_context, 1);
    ctx->cfg = cfg;
    ctx->global = gctx;
    ctx->cipher_hd = cipher_hd;
    ctx->filebuf = g_malloc0(gctx->fileblocksize);

    return ctx;
}

void cryptofs_free(void *c)
{
    struct cryptofs_context *ctx = (struct cryptofs_context *) c;

    g_free(ctx->filebuf);
    gcry_cipher_close(ctx->cipher_hd);
    ctx->global->count--;
    if (ctx->global->count == 0) {
	g_free(ctx->global->salts[0]);
	g_free(ctx->global->salts);
	g_free(ctx->global->key);
	g_free(ctx->global->root);
	g_free(ctx->global);
    }
    g_free(ctx);
}

int cryptofs_mount(void *ctx)
{
    return 1;
}

void cryptofs_umount(void *ctx)
{
}

static char *encrypt_name(struct cryptofs_context *ctx, char *name)
{
    char *tmpname, *ret;
    int len;
    gboolean hidden = FALSE;

    g_return_val_if_fail(ctx != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(name[0] != '\0', NULL);

    if (!strcmp(name, ".") || !strcmp(name, ".."))
	return g_strdup(name);

    if (name[0] == '.')
	hidden = TRUE;

    tmpname = alloca(strlen(name) + 1);
    strcpy(tmpname, name + (hidden ? 1 : 0));
    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[0], ctx->global->blocksize);
    gcry_cipher_encrypt(ctx->cipher_hd, tmpname, strlen(name) - (hidden ? 1 : 0), NULL, 0);

    ret = g_new0(char, norm2baselen(strlen(name)) + 5);
    len = base64_encode(ret + (hidden ? 1 : 0), tmpname, strlen(name) - (hidden ? 1 : 0));

    if (hidden)
	ret[0] = '.';

    *(ret + len + (hidden ? 1 : 0)) = '\0';

    return ret;
}

static char *decrypt_name(struct cryptofs_context *ctx, char *name)
{
    char *tmpname, *ret;
    int len;
    gboolean hidden = FALSE;

    g_return_val_if_fail(ctx != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(name[0] != '\0', NULL);

    if (!strcmp(name, ".") || !strcmp(name, ".."))
	return g_strdup(name);

    if (name[0] == '.')
	hidden = TRUE;

    tmpname = alloca(base2normlen(strlen(name)) + 5);
    len = base64_decode(tmpname, name + (hidden ? 1 : 0), strlen(name) - (hidden ? 1 : 0));

    ret = g_new0(char, len + 1 + (hidden ? 1 : 0));
    memmove(ret + (hidden ? 1 : 0), tmpname, len);
    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[0], ctx->global->blocksize);
    gcry_cipher_decrypt(ctx->cipher_hd, ret + (hidden ? 1 : 0), len, NULL, 0);

    if (hidden)
	ret[0] = '.';

    return ret;
}

static char *translate_path(struct cryptofs_context *ctx, char *name)
{
    GString *ret;
    const gchar *root;
    gchar *namep = name;
    gchar *retstr;
    gchar **names, **cur;

    ret = g_string_new("");
    root = ctx->global->root;

    if (!strncmp(namep, root, strlen(root))) {
	namep += strlen(root);
	g_string_append(ret, root);
	if (namep[0] == '/')
	    namep++;
    } else if (namep[0] == '/') {
	/* pathes must be relative to cryptofs root */
	return NULL;
    }

    names = g_strsplit(namep, "/", -1);
    for (cur = names; *cur != NULL; cur++) {
	gchar *encname;

	if (*cur[0] == '\0')
	    continue;

	encname = encrypt_name(ctx, *cur);
	if (encname == NULL)
	    continue;
	if (ret->len > 0)
	    g_string_append(ret, "/");
	g_string_append(ret, encname);
	g_free(encname);
    }
    g_strfreev(names);

    retstr = ret->str;
    g_string_free(ret, FALSE);

    return retstr;
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

    transname = translate_path(ctx, name);

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

        if((res = lufs_stat(ctx, dent->d_name, &fattr)) < 0) {
            closedir(dir);
            return -1;
        }

	if (!strcmp(dent->d_name, ".cryptofs"))
	    continue;
        
	decname = decrypt_name(ctx, dent->d_name);
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

    dir = translate_path(ctx, _dir);
    ret = mkdir(dir, mode);
    g_free(dir);

    return ret;
}

int cryptofs_rmdir(void *ctx, char *_dir, int mode)
{
    gchar *dir;
    int ret;

    dir = translate_path(ctx, _dir);
    ret = rmdir(dir);
    g_free(dir);

    return ret;
}

int cryptofs_create(void *ctx, char *_file, int mode)
{
    gchar *file;
    int ret;

    file = translate_path(ctx, _file);
    ret = mknod(file, mode, 0);
    g_free(file);

    return ret;
}

int cryptofs_unlink(void *ctx, char *_file)
{
    gchar *file;
    int ret;

    file = translate_path(ctx, _file);
    ret = unlink(file);
    g_free(file);

    return ret;
}

int cryptofs_rename(void *ctx, char *_old_name, char *_new_name)
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

static int readblock(struct cryptofs_context *ctx, int fp, int block, void *buf)
{
    unsigned long res;

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    if ((res = read(fp, buf, ctx->global->fileblocksize)) < 0)
	return -1;

    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_decrypt(ctx->cipher_hd, buf, res, NULL, 0);

    return res;
}

int cryptofs_read(struct cryptofs_context *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = ctx->global->fileblocksize;
    int fp;
    gchar *file;
    gboolean error = FALSE;

    file = translate_path(ctx, _file);
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

	if ((res = readblock(ctx, fp, block, ctx->filebuf)) < 0) {
	    error = TRUE;
	    break;
	}
	inblock_read = res - inblock_offset;

	memmove(buf + mempos, ctx->filebuf + inblock_offset, inblock_read);

	mempos += inblock_read;
	if (inblock_read < inblock_count)
	    break;
    }
    close(fp);

    return error ? -1 : mempos;
}

static int writeblock(struct cryptofs_context *ctx, int fp, int block, void *buf, unsigned long size)
{
    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_encrypt(ctx->cipher_hd, buf, size, NULL, 0);

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    return write(fp, buf, size);
}

int cryptofs_write(struct cryptofs_context *ctx, char *_file, long long offset, unsigned long count, char *buf)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = ctx->global->fileblocksize;
    int fp;
    gchar *file;
    gboolean error = FALSE;

    file = translate_path(ctx, _file);
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
	    if (readblock(ctx, fp, block, ctx->filebuf) < 0) {
		error = TRUE;
		break;
	    }
	}

	memmove(ctx->filebuf + inblock_offset, buf + mempos, inblock_count);

	if (writeblock(ctx, fp, block, ctx->filebuf, inblock_offset + inblock_count) < 0) {
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

	names = g_strsplit(tmpbufp, "/", -1);
	for (cur = names; *cur != NULL; cur++) {
	    gchar *decname;

	    decname = decrypt_name(ctx, *cur);
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

    target = translate_path(ctx, _target);
    lnk = translate_path(ctx, _lnk);
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

	encname = encrypt_name(ctx, *cur);
	if (encname == NULL)
	    continue;
	if (target->len > 0 || abspath)
	    g_string_append(target, "/");
	g_string_append(target, encname);
	g_free(encname);
    }
    g_strfreev(names);

    link = translate_path(ctx, _link);
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
