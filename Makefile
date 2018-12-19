### Standard Makefile template
### Copyright (C) Matthew Peddie <peddie@alum.mit.edu>
###
### This file is hereby placed in the public domain, or, if your legal
### system doesn't recognize this concept, you may consider it
### licensed under the WTFPL version 2.0 or any BSD license you
### choose.
###
### This file should be all you need to configure a basic project;
### obviously for more complex projects, you'll need to edit the other
### files as well.  It supports only one project at a time.  Type
### ``make help'' for usage help.

# What's the executable called?
PROJ = h2o-wrapper

LOCAL_PATH:= $(shell pwd)

####################################################
LOCAL_SRC_FILES := \



LOCAL_C_INCLUDES:= \
		$(LOCAL_PATH)/../ \
		$(LOCAL_PATH)/../include \

LOCAL_CFLAGS += 

LOCAL_LIBNAMES += 
LOCAL_LIBDIRS += 

#######################################################


include $(ROOT_DIR)/build/makefile-$(TARGET_ARCH).mk

