#include <string.h>
#include <assert.h>
#define MAX_MIME_TYPES_NUM 10000


#ifdef __APPLE__
#include <mach-o/getsect.h>

extern char _section$__DATA_auto_mime_types[];
static char *start = _section$__DATA_auto_mime_types[];
static char *end = _section$__DATA__auto_mime_types + getsectbyname("__DATA", "_auto_mime_types")->size

#elif (defined __WIN32__)  /* mingw */

extern char binary_auto_mime_types_start[];
extern char binary_auto_mime_types_end[];
static char *start = binary_auto_mime_types_start;
static char *end =  binary_auto_mime_types_end;

#else /* gnu ld */

extern char _binary_auto_mime_types_start[];
extern char _binary_auto_mime_types_end[];
static char *start = _binary_auto_mime_types_start;
static char *end =  _binary_auto_mime_types_end;

#endif

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
    char *c = start;
    while (c < end) {
      if (*c == '#') {
        while (c < end && *c != '\n') {
          c ++;
        }
        if (c < end) {
          c ++;
        }
      } else {
        while (*c <= ' ' && *c != '\n' && c < end) {
          c ++;
        }
        assert (*c > ' ' && *c != '\n' && c < end);
        char *name = c;
        while (*c > ' ' && *c != '\n' && c < end) {
          c ++;
        }
        assert (*c <= ' ' && *c != '\n' && c < end);
        *c = 0;
        c ++;
        while (1) {
          while (*c <= ' ' && *c != '\n' && c < end) {
            c ++;
          }
          if (*c == '\n' || c == end) { 
            if (*c == '\n') { c ++; }
            break; 
          }
          char *ext = c;
          while (*c > ' ' && *c != '\n' && c < end) {
            c ++;
          }
          assert (c != end);
          int br = (*c == '\n');
          *c = 0;
          c ++;
          assert (mime_type_number < MAX_MIME_TYPES_NUM);
          mime_type_names[mime_type_number] = name;
          mime_type_extensions[mime_type_number] = ext;
          mime_type_number ++;
          if (br) { break; }
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
