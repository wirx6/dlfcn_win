#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTLD_NEXT    ((void *)-1)
#define RTLD_DEFAULT ((void *)0)

typedef enum {
  RTLD_LAZY = 1,
  RTLD_NOW = 2,
  RTLD_GLOBAL = 3,
  RTLD_LOCAL = 4,
  RTLD_MAX = 4
} DL_MODE;

typedef enum {
  RTLD_DI_LMID = 1,
  RTLD_DI_LINKMAP = 2,
  RTLD_DI_CONFIGADDR = 3,
  RTLD_DI_SERINFO = 4,
  RTLD_DI_SERINFOSIZE = 5,
  RTLD_DI_ORIGIN = 6,
  RTLD_DI_PROFILENAME = 7,
  RTLD_DI_PROFILEOUT = 8,
  RTLD_DI_TLS_MODID = 9,
  RTLD_DI_TLS_DATA = 10,
  RTLD_DI_MAX = 10
} DL_REQUEST;

typedef enum { RTLD_DL_SYMENT = 1, RTLD_DL_LINKMAP = 2, RTLD_DL_MAX = 2 } DL_FLAGS;

typedef struct {
  const char *dli_fname;
  void *dli_fbase;
  const char *dli_sname;
  void *dli_saddr;
} Dl_info;

typedef struct {
  char *dls_name;
  unsigned int dls_flags;
} Dl_serpath;

typedef struct {
  size_t dls_size;
  unsigned int dls_cnt;
  Dl_serpath dls_serpath[1];
} Dl_serinfo;

extern void *dlopen(const char *file, int mode);
extern void *dlsym(void *handle, const char *name);
extern void *dlvsym(void *handle, const char *name, const char *version);
extern int dlclose(void *handle);
extern int dlinfo(void *handle, int request, void *info);
extern int dladdr(const void *address, Dl_info *info);
extern int dladdr1(const void *address, Dl_info *info, void **extra_info,
                   int flags);
extern char *dlerror(void);

#ifdef __cplusplus
}
#endif
