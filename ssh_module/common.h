#ifndef _COMMON_H_
#define _COMMON_H_

#include <wordexp.h>

char *expand_path(char *path);
FILE *myopen(char *path, const char *mode);

#endif /* _COMMON_H_ */
