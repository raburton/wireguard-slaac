KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all: kernel tools

kernel:
	@mkdir -p $(PWD)/wireguard-linux/include/uapi/linux
	@cp -f $(PWD)/wireguard-tools/src/uapi/linux/linux/wireguard.h $(PWD)/wireguard-linux/include/uapi/linux/wireguard.h
	$(MAKE) -C $(KDIR) M=$(PWD)/wireguard-linux CONFIG_WIREGUARD=m CC="$(CC) -I$(PWD)/wireguard-linux/include" modules

tools:
	$(MAKE) -C wireguard-tools/src

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/wireguard-linux CONFIG_WIREGUARD=m clean

	@rm -f $(PWD)/wireguard-linux/include/uapi/linux/wireguard.h || true
	@rmdir --ignore-fail-on-non-empty $(PWD)/wireguard-linux/include/uapi/linux 2>/dev/null || true
	@rmdir --ignore-fail-on-non-empty $(PWD)/wireguard-linux/include/uapi 2>/dev/null || true
	$(MAKE) -C wireguard-tools/src clean

.PHONY: all kernel tools clean
