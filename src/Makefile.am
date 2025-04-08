AUTOMAKE_OPTIONS=foreign

include $(top_srcdir)/rtems-pre.am

EXEEXT=$(OBJEXEEXT)

bin_PROGRAMS                   =
lib_LIBRARIES                  =

libt9p_a_SOURCES               = t9p.c t9p_rtems.c t9proto.c
EXTRA_libt9p_a_SOURCES         = t9p.modini.c

lib_LIBRARIES                 += libt9p.a

include_HEADERS                = t9p.h t9proto.h t9p_rtems.h

if HAVE_CEXP

bin_PROGRAMS                  += t9p

t9p_SOURCES                     = t9p.modini.c
t9p_LDADD                       = t9p.$(OBJEXT) t9p_rtems.$(OBJEXT) t9proto.$(OBJEXT)
t9p_DEPENDENCIES                = $(t9p_LDADD)
t9p_LINK                        = $(OBJLINK)

#rpcio_SOURCES                  = rpcio.modini.c
#rpcio_LDADD                    = rpcio.$(OBJEXT)
#rpcio_DEPENDENCIES             = $(rpcio_LDADD)
#rpcio_LINK                     = $(OBJLINK)

#nfs_SOURCES                    = rpcio.modini.c
#nfs_LDADD                      = nfs.$(OBJEXT) sock_mbuf.$(OBJEXT)
#nfs_LDADD                     += xdr_mbuf.$(OBJEXT)
#nfs_DEPENDENCIES               = $(nfs_LDADD)
#nfs_LINK                       = $(OBJLINK)

endif # HAVE_CEXP

#AM_CPPFLAGS                   += -I$(srcdir)/../proto
AM_CFLAGS                      += -std=gnu99

include $(top_srcdir)/rtems.am

