#include <string.h>
#include <assert.h>
#define MAX_MIME_TYPES_NUM 1000

extern char _binary_mime_types_start[];
extern char _binary_mime_types_end[];

char *tg_mime_by_filename (const char *filename) {
  int l = strlen (filename);
  const char *p = filename - 1 + l;
  while (p >= filename && *p != '.') {
    p --;
  }
  p ++;

  static int mime_initialized;
  static int mime_type_number;
  static char *mime_type_names[MAX_MIME_TYPES_NUM];
  static char *mime_type_extensions[MAX_MIME_TYPES_NUM];
  if (!mime_initialized) {
    mime_initialized = 1;
    char *c = _binary_mime_types_start;
    while (c < _binary_mime_types_end) {
      if (*c == '#') {
        while (c < _binary_mime_types_end && *c != '\n') {
          c ++;
        }
        if (c < _binary_mime_types_end) {
          c ++;
        }
      } else {
        while (*c <= ' ' && *c != '\n' && c < _binary_mime_types_end) {
          c ++;
        }
        assert (*c > ' ' && *c != '\n' && c < _binary_mime_types_end);
        char *name = c;
        while (*c > ' ' && *c != '\n' && c < _binary_mime_types_end) {
          c ++;
        }
        assert (*c <= ' ' && *c != '\n' && c < _binary_mime_types_end);
        *c = 0;
        c ++;
        while (1) {
          while (*c <= ' ' && *c != '\n' && c < _binary_mime_types_end) {
            c ++;
          }
          if (*c == '\n' || c == _binary_mime_types_end) { 
            if (*c == '\n') { c ++; }
            break; 
          }
          char *ext = c;
          while (*c > ' ' && *c != '\n' && c < _binary_mime_types_end) {
            c ++;
          }
          assert (c != _binary_mime_types_end);
          *c = 0;
          c ++;
          assert (mime_type_number < MAX_MIME_TYPES_NUM);
          mime_type_names[mime_type_number] = name;
          mime_type_extensions[mime_type_number] = ext;
          mime_type_number ++;
        }
      }
    }
  }

  static char *def = "application/octet-stream";
  int i;
  for (i = 0; i < mime_type_number; i++) {
    if (!strcmp (mime_type_extensions[i], p)) {
      return mime_type_names[i];
    }
  }
  return def;
}
