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
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>

#include "https.h"
#include "common.h"

#define SERVER_CERT "~/.iPKCS11.server.crt"

char *stack[STACK_SIZE];
unsigned short stack_i=0;
CURL *handle = NULL;

const char *url = NULL;

void ssl_link_init(const char *_url)
{
    url = _url;
    CURLcode res;
    res = curl_global_init(CURL_GLOBAL_ALL);
    /* Check for errors */ 
    if(res != CURLE_OK) {
        fprintf(stderr, "curl_global_init() failed: %s\n",
                curl_easy_strerror(res));
        exit(1);
    }
    /* get a curl handle */ 
    handle = curl_easy_init();
}

void ssl_link_cleanup(void)
{
    curl_easy_cleanup(handle);
    handle = NULL;
    curl_global_cleanup();
}

static int push(char *buf)
{
    //printf("PUSHING %s ONTO STACK\n", buf);
    int count = 1000;
    while(stack_i == STACK_SIZE)
    {
        usleep(1000);
        count--;
        if(count == 0)
            return 1;
    }

    stack[stack_i++] = buf;
    return 0;
}


#ifdef USE_BLOCKING_MODE
static char *pop(void)
{
    while(stack_i==0)
        continue;

    return stack[--stack_i];
}
#else
static char *pop(void)
{
    if(stack_i==0)
        return NULL;
    return stack[--stack_i];
}
#endif

size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
    if(size != sizeof(char))
    {
        fprintf(stderr, "%s:%d: callback function got something not a char\n", __FILE__, __LINE__);
        return 0;
    }

    char *msg = strdup((char *)buffer);
    if(push(msg))
    {
        fprintf(stderr, "timeout: stack full\n");
        return 0;
    }

    return nmemb;
}


static void post_query(char *query)
{
    CURLcode res;

    if(handle && url) {
        /* First set the URL that is about to receive our POST. */ 
        curl_easy_setopt(handle, CURLOPT_URL, url);

        /* define cert to be used */
        char *certfile = expand_path(SERVER_CERT);
        curl_easy_setopt(handle, CURLOPT_CAINFO, certfile);
        free(certfile);

        /* check that the certificate is valid */
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 1);

        /* ignore the host name (which in our case is probably an ip-address) */
        curl_easy_setopt(handle, CURLOPT_SSL_VERIFYHOST, 0);

        /* let curl write back data to our own function */
        curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, write_data);

        /* specify we want to POST data */ 
        curl_easy_setopt(handle, CURLOPT_POST, 1L);

        /* Content-type for POST */
        struct curl_slist *slist=NULL;
        slist = curl_slist_append(slist, "Content-type: application/json");
        curl_easy_setopt(handle, CURLOPT_HTTPHEADER, slist);

        /* pointer to pass to our read function */ 
        /* Set the expected POST size. If you want to POST large amounts of data,
           consider CURLOPT_POSTFIELDSIZE_LARGE */ 
        curl_easy_setopt(handle, CURLOPT_POSTFIELDS, query);

        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(handle);
        /* Check for errors */ 
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        curl_slist_free_all(slist); /* free the list again */ 
    }
}

inline char *send_string(char *str)
{
    post_query(str);
    int count = TIMEOUT_MS;
    while(count--)
    {
        char *ret = pop();
        if(ret)
            return ret;

        usleep(1000);
    }

    fprintf(stderr, "timeout\n");

    return NULL;
}
