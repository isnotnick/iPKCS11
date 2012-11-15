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
