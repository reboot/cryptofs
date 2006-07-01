/*
 * Copyright (C) 2003-2006 Christoph Hohmann
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

#include "config.h"

#include <stdio.h>

#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>
#include <gcrypt.h>

#include "cryptofs.h"
#include "crypto.h"
#include "base64.h"
#include "utils.h"

struct _CryptoCtxGlobal {
    int				  count;

    int				  cipher;
    gchar			 *key;
    guint			  keylen;
    guchar			**salts;
    unsigned int		  blocksize;
    long int			  fileblocksize;
    long int			  num_of_salts;
};

struct _CryptoCtxLocal {
    CryptoCtxGlobal	 	 *global;

    gcry_cipher_hd_t 	  	  cipher_hd;
    void			 *filebuf;
};

static void generate_key(int cipher, int md, const gchar *pass, gchar **key, guint *keylen)
{
    int i;
    int mdlen, buflen;
    gchar *keybuf;

    gcry_cipher_algo_info(cipher, GCRYCTL_GET_KEYLEN, NULL, keylen);
    mdlen = gcry_md_get_algo_dlen(md);

    buflen = mdlen < *keylen ? *keylen : mdlen;
    keybuf = g_new0(gchar, buflen);
    memset(keybuf, 0, buflen);

    gcry_md_hash_buffer(md, keybuf, pass, strlen(pass));
    if (mdlen < *keylen)
	for (i = mdlen; i < *keylen; i++)
	    keybuf[i] = keybuf[i % mdlen];

    *key = keybuf;
}

static gcry_cipher_hd_t open_cipher(CryptoCtxGlobal *gctx, int cipher)
{
    gcry_cipher_hd_t cipherhd = NULL;

    if (gcry_cipher_open(&cipherhd, cipher, GCRY_CIPHER_MODE_CFB, 0) != GPG_ERR_NO_ERROR)
	return NULL;

    if (gcry_cipher_setkey(cipherhd, gctx->key, gctx->keylen) != GPG_ERR_NO_ERROR) {
	gcry_cipher_close(cipherhd);
	cipherhd  = NULL;
    }

    return cipherhd;
}

CryptoCtxGlobal *crypto_create_global_ctx(const gchar *cipheralgo, const gchar *mdalgo, long int fileblocksize, long int num_of_salts, PasswordQuery *query)
{
    int cipher, md, i;
    char *pass;
    guchar *salts;
    CryptoCtxGlobal *gctx;
    gcry_cipher_hd_t cipher_hd;

    gcry_check_version("1.1.44");

    cipher = gcry_cipher_map_name(cipheralgo);
    md = gcry_md_map_name(mdalgo);

    pass = query->getPassword();
    if (pass == NULL)
	return NULL;

    gctx = g_new0(CryptoCtxGlobal, 1);
    gctx->cipher = cipher;
    gctx->fileblocksize = fileblocksize;
    gctx->num_of_salts = num_of_salts;

    generate_key(gctx->cipher, md, pass, &gctx->key, &gctx->keylen);
    query->freePassword(pass);

    cipher_hd = open_cipher(gctx, gctx->cipher);
    gcry_cipher_algo_info(gctx->cipher, GCRYCTL_GET_BLKLEN, NULL, &gctx->blocksize);
    salts = g_malloc0(num_of_salts * gctx->blocksize);
    gcry_cipher_setiv(cipher_hd, salts, gctx->blocksize);
    gcry_cipher_encrypt(cipher_hd, salts, num_of_salts * gctx->blocksize, NULL, 0);
    gctx->salts = g_new0(guchar *, num_of_salts);
    for (i = 0; i < num_of_salts; i++)
        gctx->salts[i] = &salts[i * gctx->blocksize];
    gctx->count = 0;
    gcry_cipher_close(cipher_hd);
    cipher_hd = NULL;

    return gctx;
}

CryptoCtxGlobal *crypto_create_global_ctx_default(const gchar *cipheralgo, const gchar *mdalgo, long int fileblocksize, long int num_of_salts)
{
    return crypto_create_global_ctx(cipheralgo, mdalgo, fileblocksize, num_of_salts, getDefaultPasswordQuery());
}

CryptoCtxLocal *crypto_create_local_ctx(CryptoCtxGlobal *gctx)
{
    gcry_cipher_hd_t cipher_hd;
    CryptoCtxLocal *ctx;

    cipher_hd = open_cipher(gctx, gctx->cipher);
    if (cipher_hd == NULL) {
        printf("failed to initialize cipher\n");
        return NULL;
    }

    ctx = g_new0(CryptoCtxLocal, 1);
    ctx->global = gctx;
    ctx->cipher_hd = cipher_hd;
    ctx->filebuf = g_malloc0(gctx->fileblocksize);

    gctx->count++;

    return ctx;
}

void crypto_destroy_local_ctx(CryptoCtxLocal *ctx)
{
    g_free(ctx->filebuf);
    gcry_cipher_close(ctx->cipher_hd);
    ctx->global->count--;
    if (ctx->global->count == 0) {
	g_free(ctx->global->salts[0]);
	g_free(ctx->global->salts);
	g_free(ctx->global->key);
	g_free(ctx->global);
    }
    g_free(ctx);
}

#define CONFIGFILE_REPLACEMENT ".!ryptofs"

char *crypto_encrypt_name(CryptoCtxLocal *ctx, const char *name)
{
    gchar *tmpname, *ret;
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

    ret = g_new0(gchar, norm2baselen(strlen(name)) + 5);
    len = base64_encode(ret + (hidden ? 1 : 0), tmpname, strlen(name) - (hidden ? 1 : 0));

    if (hidden)
	ret[0] = '.';

    *(ret + len + (hidden ? 1 : 0)) = '\0';

    if (strcmp(ret, CONFIGFILE) == 0) {
	g_free(ret);
	ret = g_strdup(CONFIGFILE_REPLACEMENT);
    }

    return ret;
}

char *crypto_decrypt_name(CryptoCtxLocal *ctx, const char *name)
{
    char *tmpname, *ret;
    int len;
    gboolean hidden = FALSE;

    g_return_val_if_fail(ctx != NULL, NULL);
    g_return_val_if_fail(name != NULL, NULL);
    g_return_val_if_fail(name[0] != '\0', NULL);

    if (!strcmp(name, ".") || !strcmp(name, ".."))
	return g_strdup(name);

    if (strcmp(name, CONFIGFILE_REPLACEMENT) == 0)
	name = CONFIGFILE;

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

char *crypto_translate_path(CryptoCtxLocal *ctx, const char *path)
{
    GString *ret;
    gchar *retstr;
    gchar **names, **cur;

    ret = g_string_new("");

    names = g_strsplit(path, "/", -1);
    for (cur = names; *cur != NULL; cur++) {
	gchar *encname;

	if (*cur[0] == '\0')
	    continue;

	encname = crypto_encrypt_name(ctx, *cur);
	if (encname == NULL)
	    continue;
	if (cur != names)
	    g_string_append(ret, "/");
	g_string_append(ret, encname);
	g_free(encname);
    }
    g_strfreev(names);

    retstr = ret->str;
    g_string_free(ret, FALSE);

    return retstr;
}

int crypto_get_blocksize(CryptoCtxLocal *ctx)
{
    return ctx->global->fileblocksize;
}

void *crypto_get_filebuf(CryptoCtxLocal *ctx)
{
    return ctx->filebuf;
}

int crypto_readblock(CryptoCtxLocal *ctx, int fp, int block)
{
    int res;

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    if ((res = read(fp, ctx->filebuf, ctx->global->fileblocksize)) < 0)
	return -1;

    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_decrypt(ctx->cipher_hd, ctx->filebuf, res, NULL, 0);

    return res;
}

int crypto_writeblock(CryptoCtxLocal *ctx, int fp, int block, unsigned long size)
{
    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_encrypt(ctx->cipher_hd, ctx->filebuf, size, NULL, 0);

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    return write(fp, ctx->filebuf, size);
}

static void translate_pos(long long offset, unsigned long count,
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

int crypto_read(CryptoCtxLocal *ctx, int fp, void *buf, unsigned long count, long long offset)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = ctx->global->fileblocksize;
    gboolean error = FALSE;

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

	memmove(buf + mempos, ctx->filebuf + inblock_offset, inblock_read);

	mempos += inblock_read;
	if (inblock_read < inblock_count)
	    break;
    }

    return error ? -1 : mempos;
}

int crypto_write(CryptoCtxLocal *ctx, int fp, void *buf, unsigned long count, long long offset)
{
    long long block;
    unsigned long mempos = 0;
    unsigned long blocksize = ctx->global->fileblocksize;
    gboolean error = FALSE;

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

	memmove(ctx->filebuf + inblock_offset, buf + mempos, inblock_count);

	if (crypto_writeblock(ctx, fp, block, inblock_offset + inblock_count) < 0) {
	    error = TRUE;
	    break;
	}

	mempos += inblock_count;
    }

    return error ? -1 : mempos;
}
