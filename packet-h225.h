/* packet-h225.h
 * Routines for H.225 packet dissection
 * 2003  Tomas Kukosa
 *
 * $Id: packet-h225.h,v 1.3 2003/09/26 22:20:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __H225_H__
#define __H225_H__ 

extern int dissect_h225_NonStandardParameter(tvbuff_t*, int, packet_info*, proto_tree*, int);

extern int dissect_h225_AliasAddress(tvbuff_t*, int, packet_info*, proto_tree*);


#endif  /* __H225_H__ */
