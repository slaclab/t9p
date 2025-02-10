
TARGETS=rtems6-pc686-qemu rtems6-beatnik-qemu rtems6-mvme3100

configure:
	cmake . -Bbuild -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
	$(foreach target,$(TARGETS),cmake . -Bbuild-$(target) -GNinja -DCMAKE_BUILD_TYPE=RelWithDbgInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_TOOLCHAIN_FILE=rtems-tools/toolchains/$(target).cmake \
		-DRTEMS_TOP=$(RTEMS_TOP);)

.PHONY: configure