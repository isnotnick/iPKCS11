/*
 * (C) Copyright 2012
 * Manne Tallmarken, mannet@kth.se.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 */

#ifndef _HTTPS_H_
#define _HTTPS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define STACK_SIZE 16
#define TIMEOUT_MS 1000

#define SSL_CERTIFICATE "~/.pkcs11server.crt"

void ssl_link_init(const char *url);
void ssl_link_cleanup(void);
char *send_string(char *str);

#ifdef __cplusplus
} /* end extern C */
#endif

#endif /* _HTTPS_H_ */
