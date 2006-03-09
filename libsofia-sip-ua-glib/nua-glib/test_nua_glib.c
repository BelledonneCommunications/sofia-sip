#include <glib.h>

#include "sofia-sip/nua_glib.h"

int main(int argc, char *argv[]) {
  NuaGlib *self;

  g_type_init();

  self = g_object_new(NUA_GLIB_TYPE, 
		      "address", "sip:foo@localhost",
		      NULL);
  
  g_message ("NuaGlib instance %p created\n", self);

  g_object_unref(self);

  return 0;
}
