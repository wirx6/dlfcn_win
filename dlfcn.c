#include "dlfcn.h"

#include <malloc.h>
#include <stdbool.h>
#include <stdio.h>

#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>

// private

__attribute__((visibility("hidden"))) bool dladdr_initialized = 0;
__attribute__((visibility("hidden"))) bool dladdr_modules_changed = 0;

__attribute__((visibility("hidden"))) bool dl_has_error = 0;
__attribute__((visibility("hidden"))) char *dl_error_buffer = NULL;
__attribute__((visibility("hidden"))) HANDLE dl_error_mutex = NULL;

void dl_error(const char *error, ...) {
  if (dl_error_mutex == NULL) {
    dl_error_mutex = CreateMutex(NULL, 0, NULL);
  }

  WaitForSingleObject(dl_error_mutex, INFINITE);

  if (dl_has_error) {
    free(dl_error_buffer);
  } else {
    dl_has_error = true;
  }
  dl_error_buffer = (char *)malloc(1024 * sizeof(char));
  va_list args;
  va_start(args, error);
  snprintf(dl_error_buffer, 1024, error, args);

  ReleaseMutex(dl_error_mutex);
}

// public

void *dlopen(const char *file, int mode __attribute__((unused))) {
  HMODULE handle;

  if (file == NULL) {
    handle = GetModuleHandle(NULL);
  } else {
    char *filename = (char *)file;
    for (size_t i = 0; i < strlen(file); i++) {
      if (filename[i] == '/') filename[i] = '\\';
    }
    handle = LoadLibrary(filename);
  }

  dladdr_modules_changed = true;

  if (handle == NULL) {
    dl_error("could not load %s due to code %ld", file, GetLastError());
  }

  return handle;
}

void *dlsym(void *handle, const char *name) {
  /* TODO RTLD_NEXT */

  void *symbol = NULL;

  if (handle == RTLD_DEFAULT) {
    HMODULE mods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), mods, sizeof(mods),
                           &cbNeeded)) {
      for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        FARPROC candidate = GetProcAddress(mods[i], name);
        if (candidate != NULL) {
          symbol = (void *)candidate;
          break;
        }
      }
    }
  } else {
    symbol = (void *)GetProcAddress((HMODULE)handle, name);
  }

  if (symbol == NULL) {
    if (handle == RTLD_DEFAULT) {
      dl_error("could not find %s", handle);
    } else {
      dl_error("could not find %s in %p", name, handle);
    }
  }

  return symbol;
}

void *dlvsym(void *handle, const char *name,
             const char *version __attribute__((unused))) {
  return dlsym(handle, name);
}

int dlclose(void *handle) {
  int err = !FreeLibrary((HMODULE)handle);

  dladdr_modules_changed = true;

  if (err) {
    dl_error("could not unload %p, code %ld", handle, GetLastError());
  }

  return err;
}

int dlinfo(void *handle, int request, void *info) {
  /* TODO ALL */
  if (request > RTLD_DI_MAX) {
    dl_error("unknown dlinfo operation %d", request);
    return -1;
  } else if (request == RTLD_DI_LMID) {
  } else if (request == RTLD_DI_LINKMAP) {
  } else if (request == RTLD_DI_SERINFO) {
  } else if (request == RTLD_DI_SERINFOSIZE) {
  } else if (request == RTLD_DI_ORIGIN) {
  } else if (request == RTLD_DI_TLS_MODID) {
  } else if (request == RTLD_DI_TLS_DATA) {
  }
  return 0;
}

int dladdr(const void *address, Dl_info *info) {
  HANDLE process = GetCurrentProcess();

  if(!dladdr_initialized){
    dladdr_initialized = SymInitialize(process, NULL, true);
  }else if(dladdr_modules_changed){
    SymRefreshModuleList(process);
  }

  HMODULE mod;

  {
    HMODULE mods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(process, mods, sizeof(mods), &cbNeeded)) {
      for (size_t i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
        MODULEINFO mInfo;
        GetModuleInformation(process, mods[i], &mInfo, sizeof(mInfo));
        if ((address < (mInfo.lpBaseOfDll + mInfo.SizeOfImage)) &&
            (address >= mInfo.lpBaseOfDll)) {
          mod = mods[i];
          info->dli_fbase = mInfo.lpBaseOfDll;
        }
      }
    } else {
      dl_error("could not find module of %p, code %ld", address, GetLastError());
      return 0;
    }
  }

  {
    info->dli_fname = (char *)malloc(MAX_PATH * sizeof(char));
    GetModuleFileNameEx(process, mod, (char *)info->dli_fname, MAX_PATH);
    for (size_t i = 0; i < strlen(info->dli_fname); i++) {
      if (info->dli_fname[i] == '\\') ((char *)info->dli_fname)[i] = '/';
    }
  }

  {
    DWORD64 dwDisplacement = 0;
    char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
    PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;
    pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    pSymbol->MaxNameLen = MAX_SYM_NAME;
    if (SymFromAddr(process, (DWORD64)address, &dwDisplacement, pSymbol)) {
      info->dli_saddr = (void *)pSymbol->Address;
      info->dli_sname = (char *)malloc(pSymbol->NameLen);
      strcpy((char *)info->dli_sname, pSymbol->Name);
    } else {
      dl_error("could not find symbol of %p, code %ld", address, GetLastError());
      return 0;
    }
  }

  return 1;
}

int dladdr1(const void *address, Dl_info *info,
            void **extra_info __attribute__((unused)),
            int flags __attribute__((unused))) {
  return dladdr(address, info);
}

char *dlerror(void) {
  WaitForSingleObject(dl_error_mutex, INFINITE);

  if (dl_has_error == true) {
    char *error = (char *)malloc(strlen(dl_error_buffer) * sizeof(char));
    strcpy(error, dl_error_buffer);

    dl_has_error = false;
    free(dl_error_buffer);

    return error;
  } else {
    return NULL;
  }

  ReleaseMutex(dl_error_mutex);
}
