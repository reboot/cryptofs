/*
 * proto.h
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

#ifndef _LU_PROTO_H_
#define _LU_PROTO_H_

#define LU_MAXDATA	4096

#define PVERSION	0x02

#define PTYPE_OK	0x00
#define PTYPE_MOUNT	0x01
#define PTYPE_READ	0x02
#define PTYPE_WRITE	0x03
#define PTYPE_READDIR	0x04
#define PTYPE_STAT	0x05
#define PTYPE_UMOUNT	0x06
#define PTYPE_SETATTR	0x07
#define PTYPE_MKDIR	0x08
#define PTYPE_RMDIR	0x09
#define PTYPE_CREATE	0x0A
#define PTYPE_UNLINK	0x0B
#define PTYPE_RENAME	0x0C
#define PTYPE_OPEN	0x0D
#define PTYPE_RELEASE	0x0E
#define PTYPE_READLINK	0x0F
#define PTYPE_LINK	0x10
#define PTYPE_SYMLINK	0x11

#define PTYPE_MAX	0x11


#define PTYPE_ERROR	0x100

#define PERROR(x)	(-(x & (PTYPE_ERROR - 1)) - 1)
#define PIS_ERROR(x)	(x & PTYPE_ERROR)

struct lu_msg {
    unsigned short	msg_version;
    unsigned short	msg_type;
    unsigned short	msg_datalen;
    unsigned short	msg_pid;
};


struct lufs_fattr{
    unsigned long	f_ino;
    unsigned long	f_mode;
    unsigned long	f_nlink;
    unsigned long	f_uid;
    unsigned long	f_gid;
    long long		f_size;
    unsigned long	f_atime;
    unsigned long	f_mtime;
    unsigned long	f_ctime;
    unsigned long	f_blksize;
    unsigned long	f_blocks;
};


struct lufs_req_readdir{
    unsigned short	offset;
    char		dirname[0];
};

struct lufs_req_mkdir{
    int		mode;
    char	dirname[0];
};

struct lufs_req_rw{
    long long		offset;
    unsigned long	count;
    char		name[0];
};

struct lufs_req_open{
    unsigned 	mode;
    char	name[0];
};

struct lufs_req_setattr{
    struct lufs_fattr 	fattr;
    char		name[0];
};

#endif
