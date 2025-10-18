obj-m += avc_spoof.o
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -fsanitize=cfi -fsanitize-cfi-cross-dso \
             -fno-sanitize-cfi-canonical-jump-tables \
             -fno-sanitize-trap=cfi
