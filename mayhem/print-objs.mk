# Included after mk/<program>/Makefile by mayhem/build.sh to read what automake
# links <program> from and with (make PROG=<program>), so the harnesses link exactly the same objects.
# A per-program <program>_CPPFLAGS replaces AM_CPPFLAGS, as automake does.
print-objs:
	@echo $($(PROG)_OBJECTS) $(LIBOBJS)
print-cppflags:
	@echo $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(or $($(PROG)_CPPFLAGS),$(AM_CPPFLAGS)) $(CPPFLAGS)
print-libs:
	@echo $(LIBS)
print-cflags:
	@echo $(or $($(PROG)_CFLAGS),$(AM_CFLAGS))
