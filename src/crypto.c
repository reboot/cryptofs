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
#include <unistd.h>
#include <fcntl.h>

#include <glib.h>
#include <gcrypt.h>

#include "crypto.h"
#include "getpw.h"
#include "base64.h"

struct _CtxGlobal {
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

struct _CtxLocal {
    CtxGlobal	 		 *global;

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
    keybuf = g_new0(unsigned char, buflen);
    memset(keybuf, 0, buflen);

    gcry_md_hash_buffer(md, keybuf, pass, strlen(pass));
    if (mdlen < *keylen)
	for (i = mdlen; i < *keylen; i++)
	    keybuf[i] = keybuf[i % mdlen];

    *key = keybuf;
}

static gcry_cipher_hd_t open_cipher(CtxGlobal *gctx, int cipher)
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

CtxGlobal *crypto_create_global_ctx(const gchar *cipheralgo, const gchar *mdalgo, long int fileblocksize, long int num_of_salts, const gchar *root)
{
    int cipher, md, i;
    char *pass, *salts;
    CtxGlobal *gctx;
    gcry_cipher_hd_t cipher_hd;

    gcry_check_version("1.1.44");

    cipher = gcry_cipher_map_name(cipheralgo);
    md = md = gcry_md_map_name(mdalgo);

    gctx = g_new0(CtxGlobal, 1);
    gctx->cipher = cipher;
    gctx->root = g_strdup(root);
    gctx->fileblocksize = fileblocksize;
    gctx->num_of_salts = num_of_salts;

    pass = getpwd("Enter password:");
    generate_key(gctx->cipher, md, pass, &gctx->key, &gctx->keylen);
    putpwd(pass);

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

CtxLocal *crypto_create_local_ctx(CtxGlobal *gctx)
{
    gcry_cipher_hd_t cipher_hd;
    CtxLocal *ctx;

    cipher_hd = open_cipher(gctx, gctx->cipher);
    if (cipher_hd == NULL) {
        printf("failed to initialize cipher\n");
        return NULL;
    }

    ctx = g_new0(CtxLocal, 1);
    ctx->global = gctx;
    ctx->cipher_hd = cipher_hd;
    ctx->filebuf = g_malloc0(gctx->fileblocksize);

    gctx->count++;

    return ctx;
}

void crypto_destroy_local_ctx(CtxLocal *ctx)
{
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

char *crypto_encrypt_name(CtxLocal *ctx, char *name)
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

char *crypto_decrypt_name(CtxLocal *ctx, char *name)
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

char *crypto_translate_path(CtxLocal *ctx, char *name)
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

	encname = crypto_encrypt_name(ctx, *cur);
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

int crypto_get_blocksize(CtxLocal *ctx)
{
    return ctx->global->fileblocksize;
}

void *crypto_get_filebuf(CtxLocal *ctx)
{
    return ctx->filebuf;
}

int crypto_readblock(CtxLocal *ctx, int fp, int block)
{
    unsigned long res;

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    if ((res = read(fp, ctx->filebuf, ctx->global->fileblocksize)) < 0)
	return -1;

    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_decrypt(ctx->cipher_hd, ctx->filebuf, res, NULL, 0);

    return res;
}

int crypto_writeblock(CtxLocal *ctx, int fp, int block, unsigned long size)
{
    gcry_cipher_setiv(ctx->cipher_hd, ctx->global->salts[block % ctx->global->num_of_salts], ctx->global->blocksize);
    gcry_cipher_encrypt(ctx->cipher_hd, ctx->filebuf, size, NULL, 0);

    if (lseek(fp, block * ctx->global->fileblocksize, SEEK_SET) < 0)
	return -1;

    return write(fp, ctx->filebuf, size);
}
