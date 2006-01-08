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

#ifndef CRYPTO_H
#define CRYPTO_H 1

typedef struct _CryptoCtxGlobal	CryptoCtxGlobal;
typedef struct _CryptoCtxLocal	CryptoCtxLocal;

CryptoCtxGlobal *crypto_create_global_ctx(const gchar *cipheralgo, const gchar *mdalgo, long int fileblocksize, long int salts);
CryptoCtxLocal *crypto_create_local_ctx(CryptoCtxGlobal *gctx);
void crypto_destroy_local_ctx(CryptoCtxLocal *ctx);
char *crypto_encrypt_name(CryptoCtxLocal *ctx, char *name);
char *crypto_decrypt_name(CryptoCtxLocal *ctx, char *name);
char *crypto_translate_path(CryptoCtxLocal *ctx, char *name);
int crypto_get_blocksize(CryptoCtxLocal *ctx);
void *crypto_get_filebuf(CryptoCtxLocal *ctx);
int crypto_readblock(CryptoCtxLocal *ctx, int fp, int block);
int crypto_writeblock(CryptoCtxLocal *ctx, int fp, int block, unsigned long size);
int crypto_read(CryptoCtxLocal *ctx, int fp, void *buf, unsigned long size, long long offset);
int crypto_write(CryptoCtxLocal *ctx, int fp, void *buf, unsigned long count, long long offset);

#endif
