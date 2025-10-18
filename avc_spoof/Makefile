obj-m += avc_spoof.o
ccflags-y += -Wno-declaration-after-statement

ifeq ($(CONFIG_SELINUX_AVC_SPOOF_USE_CFI),y)
ccflags-y += -fsanitize=cfi -fsanitize-cfi-cross-dso \
             -fno-sanitize-cfi-canonical-jump-tables \
             -fno-sanitize-trap=cfi -fno-sanitize-blacklist
endif	
