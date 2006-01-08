/*
 * Copyright (C) 1999-2002 Hiroyuki Yamamoto
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

#ifndef __BASE64_H__
#define __BASE64_H__

#include <glib.h>

/* approximate lengths you'll get after conversions */
#define norm2baselen(x) (((x)*8+5)/6)
#define base2normlen(x) ((x)*6/8)

gint base64_encode	(gchar		*out,
			 const gchar	*in,
			 gint		 inlen);
gint base64_decode	(gchar		*out,
			 const gchar	*in,
			 gint		 inlen);

#endif /* __BASE64_H__ */
