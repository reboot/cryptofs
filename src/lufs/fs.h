/*
 * lufs.h
 * Copyright (C) 2002 Florin Malita <mali@go.ro>
 *
 * This file is part of LUFS, a free userspace filesystem implementation.
 * See http://lufs.sourceforge.net/ for updates.
 *
 * LUFS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * LUFS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _LUFS_FS_H_
#define _LUFS_FS_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dir_cache;
struct directory;
struct lufs_fattr;
struct file_system;
struct list_head;
struct dir_cache;

#define MAX_LEN		64

struct credentials{
    char	user[MAX_LEN];
    char	group[MAX_LEN];
    uid_t	uid;
    gid_t	gid;
};


struct directory* lu_cache_mkdir(char*);
int lu_cache_add2dir(struct directory*, char*, char*, struct lufs_fattr*);
int lu_cache_lookup(struct dir_cache*, char*, char*, struct lufs_fattr*, char*, int);
void lu_cache_add_dir(struct dir_cache*, struct directory*);
void lu_cache_killdir(struct directory*);

int lu_check_to(int, int, int);
int lu_atomic_read(int, char*, int, int);
int lu_atomic_write(int, char*, int, int);

int lu_opt_loadcfg(struct list_head*, char*);
int lu_opt_parse(struct list_head*, char*, char*);
int lu_opt_getint(struct list_head*, char*, char*, long int*, int);
const char* lu_opt_getchar(struct list_head*, char*, char*);


#ifdef __cplusplus
} /* end of extern "C" { */
#endif

#ifdef TRACE
#undef TRACE
#endif
#ifdef WARN
#undef WARN
#endif
#ifdef ERROR
#undef ERROR
#endif

#ifdef __cplusplus

#include <iostream>

#ifdef DEBUG
#define TRACE(x) 	cout<<std::hex<<"["<<getpid()<<"]("<<__func__<<")"<<x<<"\n"
#define WARN(x)		cerr<<std::hex<<"["<<getpid()<<"]("<<__func__<<")"<<x<<"\n"
#define ERROR(x)	cerr<<std::hex<<"["<<getpid()<<"]("<<__func__<<")"<<x<<"\n"
#else
#define TRACE(x...)	do{}while(0)
#define WARN(x...)	do{}while(0)
#define ERROR(x...)	cerr<<x<<"\n"
#endif

#else

#include <stdio.h>

#ifdef DEBUG
#define TRACE(x...)	do{fprintf(stdout, "[%x](%s) ", getpid(), __func__); fprintf(stdout, x); fprintf(stdout, "\n");}while(0)
#define WARN(x...)	do{fprintf(stdout, "[%x](%s) ", getpid(), __func__); fprintf(stdout, x); fprintf(stdout, "\n");}while(0)
#define ERROR(x...)	do{fprintf(stderr, "[%x](%s) ", getpid(), __func__); fprintf(stdout, x); fprintf(stdout, "\n");}while(0)
#else
#define TRACE(x...)	do{}while(0)
#define WARN(x...)	do{}while(0)
#define ERROR(x...)	do{fprintf(stderr, x); fprintf(stderr, "\n");}while(0)
#endif

#endif



#endif

