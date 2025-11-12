#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "secret_store.h"

#include <zip.h>

char* default_password;
zip_t* archive = NULL;

bool is_filename_safe(const char* filename) {
  if (filename == NULL) return false;
  if (strlen(filename) == 0) return false;
  if (strstr(filename, "..")) return false;
  if (filename[0] == '/' || filename[0] == '\\') return false;
  return true;
}

void zip_fread_entire_file(zip_t* zip, const char* filename, char** file, int* filesize) {
  zip_stat_t st;

  *file = NULL;
  *filesize = 0;
  
  if (zip_stat(zip, filename, 0, &st) < 0) {
    fprintf(stderr, "Error: Could not get file stat for '%s': %s\n", filename, zip_strerror(zip));
    return;
  }
  
  char* buffer = malloc(st.size + 1);
  if (buffer == NULL) {
    perror("malloc");
    return;
  }

  zip_file_t* file_handle = zip_fopen(zip, filename, ZIP_FL_COMPRESSED);
  if (file_handle == NULL) {
    fprintf(stderr, "Error: Could not open file '%s' in zip archive: %s\n", filename, zip_strerror(zip));
    free(buffer);
    return;
  }

  zip_int64_t total_read = 0;
  while (total_read < st.size) {
    zip_int64_t read_bytes = zip_fread(file_handle, buffer + total_read, st.size - total_read);
    if (read_bytes < 0) {
      fprintf(stderr, "Error: Reading from file '%s' failed\n", filename);
      free(buffer);
      zip_fclose(file_handle);
      return;
    }
    total_read += read_bytes;
  }

  buffer[st.size] = '\0';  
  
  zip_fclose(file_handle);

  *file = buffer;
  *filesize = st.size + 1;
}

bool zip_fwrite_entire_memory(zip_t *zip, const char *zip_entry_name, const void *buffer, size_t buffer_size) {
    zip_source_t* nsource = zip_source_buffer_create(buffer, buffer_size, false, NULL);
    if (nsource == NULL) {
      fprintf(stderr, "error adding file %s (creating buffer): %s\n", zip_entry_name, zip_strerror(zip));
      return false;
    }

    zip_int64_t ret = zip_file_add(zip, zip_entry_name, nsource, ZIP_FL_ENC_UTF_8 | ZIP_FL_OVERWRITE);
    if (ret < 0) {
      zip_source_free(nsource);

      fprintf(stderr, "error adding file %s: %s\n", zip_entry_name, zip_strerror(zip));
      return false;
    }
    if (zip_file_set_encryption(zip, ret, ZIP_EM_AES_256, NULL) != 0) {
      fprintf(stderr, "error adding encryption %s: %s\n", zip_entry_name, zip_strerror(zip));
    }
    return true;
}

void  mzip_open(void) {
  const char* name = "TOTP_SECRET.zip";
  int err;
  archive = zip_open(name, ZIP_CREATE, &err);
  if (archive == NULL) {
    zip_error_t error;
    zip_error_init_with_code(&error, err);
    fprintf(stderr, "cannot open zip archive '%s': %s\n", name, zip_error_strerror(&error));
    zip_error_fini(&error);
    return;
  }

  zip_set_default_password(archive, default_password);
}

void  mzip_close(void) {
  if (archive == NULL) return;
  int err = zip_close(archive);
  if (err != 0) {
    zip_error_t error;
    zip_error_init_with_code(&error, err);
    fprintf(stderr, "cannot close zip archive: %s\n", zip_error_strerror(&error));
    zip_error_fini(&error);
  }
}

void  mzip_reopen(void) {
  mzip_close();
  mzip_open();
}

void  init(void) {
  default_password = strdup("TOTP");
  mzip_open();
}

bool  is_locked(void) {
  zip_int64_t num_entries = zip_get_num_entries(archive, 0);
  if (num_entries == 0) return false;
  
  int index = 0;
  do {
    zip_stat_t stat;
    int err = zip_stat_index(archive, index, 0, &stat);
    if (err != 0) {
      fprintf(stderr, "Error: Could not stat index '%d' in zip archive: %s\n", index, zip_strerror(archive));
      return false;
    }
    if (stat.valid & ZIP_STAT_NAME) {
      if (strchr(stat.name, '/') != NULL) { // is folder
          index++;
          continue;
      }
    }
    if (stat.valid & ZIP_STAT_ENCRYPTION_METHOD) {
      if (stat.encryption_method == ZIP_EM_NONE) {
        return false;
      }
      zip_file_t* file_handle = zip_fopen_index(archive, index, ZIP_FL_COMPRESSED);
      if (file_handle == NULL) {
        zip_error_t* zip_err = zip_get_error(archive);
        switch (zip_error_code_zip(zip_err)) {
        case ZIP_ER_NOPASSWD:
        case ZIP_ER_WRONGPASSWD:
        case ZIP_ER_ENCRNOTSUPP:
          return true;
        default:
          fprintf(stderr, "Error: Could not open file index '%d' in zip archive: %s\n", index, zip_strerror(archive));
        }
      }

      zip_fclose(file_handle);
    }
    index++;
  } while (index < num_entries);
    
  return false;
}

int   unlock(void* pass) {
  char* p = (char*) pass;
  default_password = strdup(pass);
  zip_set_default_password(archive, p); 
  return 0;
}

bool  get_secret(char* key, char** secret) {
  if (! is_filename_safe(key)) {
    fprintf(stderr, "filename (%s) not safe", key);
    return false;
  }
  int secret_len;
  zip_fread_entire_file(archive, key, secret, &secret_len);

  return secret_len > 0;
}

bool  set_secret(char* key, char* secret) {
  if (! is_filename_safe(key)) {
    fprintf(stderr, "filename (%s) not safe", key);
    return false;
  }

  if (! zip_fwrite_entire_memory(archive, key, secret, strlen(secret))) {
    return false;
  } else {
    mzip_reopen();
  }
  
  return true;
}

bool  delete_secret(char* key) {
  return true;
}

SecretStore secret_store = {
  .name = "plain",
  .type = SECRET_STORE_FILE,
  .locktype = SECRET_STORE_LOCK_NONE,
  .init = init,
  .is_locked = is_locked,
  .unlock = unlock,
  .get_secret = get_secret,
  .set_secret = set_secret,
  .delete_secret = delete_secret,
};

bool plug_load(void) {
  register_secret_store(secret_store);
  return true;
}

void plug_unload(void) {
  if (archive != NULL) {
    zip_close(archive);
  }

  free(default_password);
}
