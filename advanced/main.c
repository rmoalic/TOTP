#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "secret_store.h"

void empty_string(char* str) {
  while (*str) {
    *str = 0;
    str += 1;
  }
}

typedef struct {
    void *original_addr;
    void *locked_addr;
    size_t locked_len;
} LockedRegion;

LockedRegion lock_memory(void *addr, size_t len) {
    LockedRegion region = { .original_addr = addr, .locked_addr = NULL, .locked_len = 0 };
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1) {
        perror("sysconf");
        return region;
    }

    region.locked_addr = (void *)((unsigned long)addr & ~(page_size - 1));
    region.locked_len = ((unsigned long)addr + len + page_size - 1) & ~(page_size - 1);
    region.locked_len -= (unsigned long)region.locked_addr;

    if (mlock(region.locked_addr, region.locked_len) == -1) {
        perror("mlock");
        region.locked_addr = NULL;
    }
    return region;
}

void unlock_memory(LockedRegion region) {
    if (region.locked_addr != NULL) {
        if (munlock(region.locked_addr, region.locked_len) == -1) {
            perror("munlock");
        }
    }
}

int main(void) {
  bool (*plug_load)(void);
  void* handle = dlopen("./libsecret_store_plain.so", RTLD_LAZY | RTLD_GLOBAL);
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(EXIT_FAILURE);
  }
  dlerror();
  
  *(void **) (&plug_load) = dlsym(handle, "plug_load");

  char *error;
  if ((error = dlerror()) != NULL)  {
      fprintf(stderr, "%s\n", error);
      exit(EXIT_FAILURE);
  }

  plug_load();


  SecretStore_Arr list = secret_store_list();
  for (int i = 0; i < list.nb; i++) {
    printf("%d: %s\n", i, list.arr[i].name);
  }

  SecretStore store = list.arr[0];

  puts("init");
  store.init();

  while (store.is_locked()) {
    puts("ask unlock");
    store.unlock("TT");
  }

  store.set_secret("totp_json", "{secret}");

  char* secret = NULL;
  
  if (store.get_secret("totp_json", &secret)) {
    int len = strlen(secret);

    LockedRegion region = lock_memory(secret, len);

    printf("secret: %s\n", secret);
    empty_string(secret);

    unlock_memory(region);
  } else {
    puts("could'nt get secret");
  }
  return EXIT_SUCCESS;
}
