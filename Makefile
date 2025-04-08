# Template makefile

include $(RTEMS_MAKEFILE_PATH)/Makefile.inc

include $(RTEMS_CUSTOM)
include $(RTEMS_ROOT)/make/directory.cfg

SUBDIRS=src

REVISION=$(filter-out $$%,$$Name$$)

tar: tar-recursive
	@$(make-tar)
