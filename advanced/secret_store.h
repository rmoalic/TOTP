#ifndef SECRET_STORE_H
#define SECRET_STORE_H 1

#include <stdlib.h>
#include <stdbool.h>

#define SECRET_STORE_MAX 5

enum SecretStoreType {
  SECRET_STORE_SYSTEM,
  SECRET_STORE_FILE
};

enum SecretStoreLockType {
  SECRET_STORE_LOCK_SYSTEM,
  SECRET_STORE_LOCK_PASSWORD,
  SECRET_STORE_LOCK_NONE
};

typedef struct {
  void  (*init)(void);
  bool  (*is_locked)(void);
  int   (*unlock)(void* pass);

  bool  (*get_secret)(char* key, char** secret);
  bool  (*set_secret)(char* key, char* secret);
  bool  (*delete_secret)(char* key);

  enum SecretStoreType type;
  enum SecretStoreLockType locktype;
  char* name;
} SecretStore;

typedef struct {
  SecretStore arr[SECRET_STORE_MAX];
  int nb;
} SecretStore_Arr;

bool register_secret_store(SecretStore store);
SecretStore_Arr secret_store_list(void);

#endif
