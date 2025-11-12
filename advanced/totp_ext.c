#include <tcl.h>
#define TOTP_IMPLEMENTATION
#include "../totp.c"


static int HOTP_Cmd(ClientData cdata, Tcl_Interp *interp, int objc, Tcl_Obj *const objv[])
{
  for (int i = 1; i < objc; i++) {
    int v;
    int ret = Tcl_GetIntFromObj(interp, objv[i], &v);
    printf("%d: ret: %d: %d\n", i, ret, v);
    if (ret) {
      Tcl_SetObjResult(interp, Tcl_NewStringObj("expected number", -1));  
      return TCL_ERROR;
    }
  }
    
    Tcl_SetObjResult(interp, Tcl_NewStringObj("Hello, World!", -1));
  return TCL_OK;
}

int DLLEXPORT Totp_ext_Init(Tcl_Interp *interp)
{
  if (Tcl_InitStubs(interp, TCL_VERSION, 0) == NULL) {
    return TCL_ERROR;
  }

  Tcl_Namespace* nsPtr = Tcl_CreateNamespace(interp, "TOTP", NULL, NULL);
  if (nsPtr == NULL) {
    return TCL_ERROR;
  }
        
  Tcl_CreateObjCommand(interp, "TOTP::HOTP", HOTP_Cmd, NULL, NULL);
  Tcl_PkgProvide(interp, "TOTP", "1.0");
    
  return TCL_OK;
}
