#include <xenctrl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv)
{
#define MAX_CPU_ID 255
  xc_interface *xch;
  int has_hvm, has_hvm_directio;
  xc_physinfo_t info = { 0 };

  xch = xc_interface_open(0, 0, 0);
  if (xch == NULL)
  {
    fprintf(stderr, "xc_interface_open() failed: %s.\n", strerror(errno));
    return 1;
  }

  info.max_cpu_id = MAX_CPU_ID;
  if (xc_physinfo(xch, &info) != 0)
  {
    fprintf(stderr, "xc_physinfo() failed: %s.\n", strerror(errno));
    return 1;
  }

  has_hvm = info.capabilities & XEN_SYSCTL_PHYSCAP_hvm;
  has_hvm_directio = info.capabilities & XEN_SYSCTL_PHYSCAP_hvm_directio;

  printf("hvm is %s\n", has_hvm ? "enabled" : "disabled");
  printf("hvm_directio is %s\n", has_hvm_directio ? "enabled" : "disabled");

  xc_interface_close(xch);
  return 0;
}
