# kernel directory
KDIR := /lib/modules/$(shell uname -r)/build

# source file
SOURCE := kfetch_mod_312512011.c

# define module name
MODULE_NAME := kfetch_mod

# object
obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := $(SOURCE:.c=.o)
PWD := $(CURDIR)

# 編譯指令
all: $(SOURCE)
	$(MAKE) -C $(KDIR) M=$(PWD) modules
# 清理生成檔案
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
load: all
	sudo insmod $(MODULE_NAME).ko
unload:
	sudo rmmod  $(MODULE_NAME).ko
info:
	modinfo $(MODULE_NAME).ko
.PHONY: all clean load unload info