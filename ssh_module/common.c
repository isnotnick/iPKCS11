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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <wordexp.h>

char *expand_path(char *path)
{
    wordexp_t exp_result;
    wordexp(path, &exp_result, 0);
    char *expanded = strdup(exp_result.we_wordv[0]);
    wordfree(&exp_result);

    return expanded;
}

FILE *myopen(char *path, const char *mode)
{
    char *filename = expand_path(path);

    struct stat info;
    FILE *ret;

    if(stat(filename, &info))
    {
        fprintf(stderr, "%s: %s\n", filename, strerror(errno));
        ret = NULL;
    }
    else
        ret = fopen(filename, mode);
    
    free(filename);
    return ret;
}
