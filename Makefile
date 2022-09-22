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
H2O_HAS_WSLAY ?= false
H2O_HAS_HIREDIS ?= false
H2O_HAS_LIBYRMCDS ?= false

####################################################
h2o_SRC_FILES := \
    h2o/deps/cloexec/cloexec.c \
    h2o/deps/libgkc/gkc.c \
    h2o/deps/picohttpparser/picohttpparser.c \
    h2o/lib/common/cache.c \
    h2o/lib/common/file.c \
    h2o/lib/common/filecache.c \
    h2o/lib/common/hostinfo.c \
    h2o/lib/common/http1client.c \
    h2o/lib/common/http2client.c \
    h2o/lib/common/httpclient.c \
    h2o/lib/common/memory.c \
    h2o/lib/common/multithread.c \
    h2o/lib/common/serverutil.c \
    h2o/lib/common/socket.c \
    h2o/lib/common/socketpool.c \
    h2o/lib/common/string.c \
    h2o/lib/common/time.c \
    h2o/lib/common/timerwheel.c \
    h2o/lib/common/token.c \
    h2o/lib/common/url.c \
    h2o/lib/common/balancer/roundrobin.c \
    h2o/lib/common/balancer/least_conn.c \
    h2o/lib/core/config.c \
    h2o/lib/core/configurator.c \
    h2o/lib/core/context.c \
    h2o/lib/core/headers.c \
    h2o/lib/core/logconf.c \
    h2o/lib/core/proxy.c \
    h2o/lib/core/request.c \
    h2o/lib/core/util.c \
    h2o/lib/handler/access_log.c \
    h2o/lib/handler/compress.c \
    h2o/lib/handler/compress/gzip.c \
    h2o/lib/handler/errordoc.c \
    h2o/lib/handler/expires.c \
    h2o/lib/handler/fastcgi.c \
    h2o/lib/handler/file.c \
    h2o/lib/handler/headers.c \
    h2o/lib/handler/mimemap.c \
    h2o/lib/handler/proxy.c \
    h2o/lib/handler/redirect.c \
    h2o/lib/handler/reproxy.c \
    h2o/lib/handler/throttle_resp.c \
    h2o/lib/handler/server_timing.c \
    h2o/lib/handler/status.c \
    h2o/lib/handler/headers_util.c \
    h2o/lib/handler/status/events.c \
    h2o/lib/handler/status/requests.c \
    h2o/lib/handler/status/ssl.c \
    h2o/lib/handler/http2_debug_state.c \
    h2o/lib/handler/status/durations.c \
    h2o/lib/handler/configurator/access_log.c \
    h2o/lib/handler/configurator/compress.c \
    h2o/lib/handler/configurator/errordoc.c \
    h2o/lib/handler/configurator/expires.c \
    h2o/lib/handler/configurator/fastcgi.c \
    h2o/lib/handler/configurator/file.c \
    h2o/lib/handler/configurator/headers.c \
    h2o/lib/handler/configurator/proxy.c \
    h2o/lib/handler/configurator/redirect.c \
    h2o/lib/handler/configurator/reproxy.c \
    h2o/lib/handler/configurator/throttle_resp.c \
    h2o/lib/handler/configurator/server_timing.c \
    h2o/lib/handler/configurator/status.c \
    h2o/lib/handler/configurator/http2_debug_state.c \
    h2o/lib/handler/configurator/headers_util.c \
    h2o/lib/http1.c \
    h2o/lib/tunnel.c \
    h2o/lib/http2/cache_digests.c \
    h2o/lib/http2/casper.c \
    h2o/lib/http2/connection.c \
    h2o/lib/http2/frame.c \
    h2o/lib/http2/hpack.c \
    h2o/lib/http2/scheduler.c \
    h2o/lib/http2/stream.c \
    h2o/lib/http2/http2_debug_state.c \

h2o_wrapper_SRC_FILES := \
    libh2o_log.c \
    libh2o_cmn.c \
    libh2o_socket_client/libh2o_socket_client.c \
    libh2o_http_client/libh2o_http_client.c \
    libh2o_http_server/libh2o_http_server.c \
    libh2o_socket_server/libh2o_socket_server.c \


wslay_SRC_FILES := \
    wslay/lib/wslay_event.c \
    wslay/lib/wslay_frame.c \
    wslay/lib/wslay_net.c \
    wslay/lib/wslay_queue.c \
    wslay/lib/wslay_stack.c \

ifeq ($(H2O_HAS_WSLAY), true)
h2o_SRC_FILES += \
    h2o/lib/websocket.c \
    h2o/lib/websocketclient.c \
    libh2o_websocket_client/libh2o_websocket_client.c \
    $(wslay_SRC_FILES)
endif

ifeq ($(H2O_HAS_HIREDIS), true)
h2o_SRC_FILES += \
    h2o/deps/hiredis/async.c \
    h2o/deps/hiredis/hiredis.c \
    h2o/deps/hiredis/net.c \
    h2o/deps/hiredis/read.c \
    h2o/deps/hiredis/sds.c \
    h2o/lib/common/redis.c \

endif

ifeq ($(H2O_HAS_LIBYRMCDS), true)
h2o_SRC_FILES += \
    h2o/deps/libyrmcds/close.c \
    h2o/deps/libyrmcds/connect.c \
    h2o/deps/libyrmcds/recv.c \
    h2o/deps/libyrmcds/send.c \
    h2o/deps/libyrmcds/send_text.c \
    h2o/deps/libyrmcds/socket.c \
    h2o/deps/libyrmcds/strerror.c \
    h2o/deps/libyrmcds/text_mode.c \
    h2o/lib/common/memcached.c \

endif

LOCAL_SRC_FILES := \
    $(h2o_SRC_FILES) \
    $(h2o_wrapper_SRC_FILES) \

LOCAL_C_INCLUDES:= \
    $(LOCAL_PATH) \
    $(LOCAL_PATH)/wslay/lib/includes \
    $(LOCAL_PATH)/h2o/include \
    $(LOCAL_PATH)/h2o/deps/klib \
    $(LOCAL_PATH)/h2o/deps/picohttpparser \
    $(LOCAL_PATH)/h2o/deps/libyrmcds \
    $(LOCAL_PATH)/h2o/deps/cloexec \
    $(LOCAL_PATH)/h2o/deps/hiredis \
    $(LOCAL_PATH)/h2o/deps/yoml \
    $(LOCAL_PATH)/h2o/deps/libgkc \
    $(LOCAL_PATH)/h2o/deps/golombset \
    $(ROOT_DIR)/foundation/include \

h2o_cmn_clfags :=  -Wno-error=return-type -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare \
    -DWSLAY_VERSION=\"1.0.1-DEV\" \
    -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H \
    -Dh2o_error_printf=libh2o_error_printf \
    -DH2O_EVLOOP_USE_CLOCK_MONOTONIC \

ifeq ($(H2O_HAS_WSLAY), true)
h2o_cmn_clfags += -DH2O_HAS_WSLAY
endif

ifeq ($(H2O_HAS_HIREDIS), true)
h2o_cmn_clfags += -DH2O_HAS_HIREDIS
endif
ifeq ($(H2O_HAS_LIBYRMCDS), true)
h2o_cmn_clfags += -DH2O_HAS_LIBYRMCDS
endif

LOCAL_CFLAGS := $(h2o_cmn_clfags)

ifeq ($(TARGET_PLATFORM), qnx)
LOCAL_CFLAGS += -DH2O_USE_POLL=1
else
# linux, android
LOCAL_CFLAGS += -DH2O_USE_EPOLL=1
endif

# warning: ‘XXX’ is deprecated: Since OpenSSL 3.0
LOCAL_CFLAGS += -Wno-deprecated-declarations

# for unit test
ifeq ($(SELF_TEST), true)
LOCAL_CFLAGS += -DLIBH2O_UNIT_TEST
endif


LOCAL_LIBNAMES += 
LOCAL_LIBDIRS += 

#######################################################


include $(ROOT_DIR)/build/makefile-$(TARGET_PLATFORM)-$(TARGET_ARCH).mk

