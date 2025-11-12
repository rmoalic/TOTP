
#include "secret_store.h"

SecretStore_Arr secret_store_arr = {NULL};

bool register_secret_store(SecretStore store) {
  if (SECRET_STORE_MAX < secret_store_arr.nb) {
    return false;
  }

  secret_store_arr.arr[secret_store_arr.nb++] = store;
  return true;
}


SecretStore_Arr secret_store_list(void) {
  return secret_store_arr;
}
