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
    $(LOCAL_PATH)/h2o/deps/cloexec/cloexec.c \
    $(LOCAL_PATH)/h2o/deps/hiredis/async.c \
    $(LOCAL_PATH)/h2o/deps/hiredis/hiredis.c \
    $(LOCAL_PATH)/h2o/deps/hiredis/net.c \
    $(LOCAL_PATH)/h2o/deps/hiredis/read.c \
    $(LOCAL_PATH)/h2o/deps/hiredis/sds.c \
    $(LOCAL_PATH)/h2o/deps/libgkc/gkc.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/close.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/connect.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/recv.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/send.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/send_text.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/socket.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/strerror.c \
    $(LOCAL_PATH)/h2o/deps/libyrmcds/text_mode.c \
    $(LOCAL_PATH)/h2o/deps/picohttpparser/picohttpparser.c \
    $(LOCAL_PATH)/h2o/lib/common/cache.c \
    $(LOCAL_PATH)/h2o/lib/common/file.c \
    $(LOCAL_PATH)/h2o/lib/common/filecache.c \
    $(LOCAL_PATH)/h2o/lib/common/hostinfo.c \
    $(LOCAL_PATH)/h2o/lib/common/http1client.c \
    $(LOCAL_PATH)/h2o/lib/common/http2client.c \
    $(LOCAL_PATH)/h2o/lib/common/httpclient.c \
    $(LOCAL_PATH)/h2o/lib/common/memcached.c \
    $(LOCAL_PATH)/h2o/lib/common/memory.c \
    $(LOCAL_PATH)/h2o/lib/common/multithread.c \
    $(LOCAL_PATH)/h2o/lib/common/redis.c \
    $(LOCAL_PATH)/h2o/lib/common/serverutil.c \
    $(LOCAL_PATH)/h2o/lib/common/socket.c \
    $(LOCAL_PATH)/h2o/lib/common/socketpool.c \
    $(LOCAL_PATH)/h2o/lib/common/string.c \
    $(LOCAL_PATH)/h2o/lib/common/time.c \
    $(LOCAL_PATH)/h2o/lib/common/timerwheel.c \
    $(LOCAL_PATH)/h2o/lib/common/token.c \
    $(LOCAL_PATH)/h2o/lib/common/url.c \
    $(LOCAL_PATH)/h2o/lib/common/balancer/roundrobin.c \
    $(LOCAL_PATH)/h2o/lib/common/balancer/least_conn.c \
    $(LOCAL_PATH)/h2o/lib/core/config.c \
    $(LOCAL_PATH)/h2o/lib/core/configurator.c \
    $(LOCAL_PATH)/h2o/lib/core/context.c \
    $(LOCAL_PATH)/h2o/lib/core/headers.c \
    $(LOCAL_PATH)/h2o/lib/core/logconf.c \
    $(LOCAL_PATH)/h2o/lib/core/proxy.c \
    $(LOCAL_PATH)/h2o/lib/core/request.c \
    $(LOCAL_PATH)/h2o/lib/core/util.c \
    $(LOCAL_PATH)/h2o/lib/handler/access_log.c \
    $(LOCAL_PATH)/h2o/lib/handler/compress.c \
    $(LOCAL_PATH)/h2o/lib/handler/compress/gzip.c \
    $(LOCAL_PATH)/h2o/lib/handler/errordoc.c \
    $(LOCAL_PATH)/h2o/lib/handler/expires.c \
    $(LOCAL_PATH)/h2o/lib/handler/fastcgi.c \
    $(LOCAL_PATH)/h2o/lib/handler/file.c \
    $(LOCAL_PATH)/h2o/lib/handler/headers.c \
    $(LOCAL_PATH)/h2o/lib/handler/mimemap.c \
    $(LOCAL_PATH)/h2o/lib/handler/proxy.c \
    $(LOCAL_PATH)/h2o/lib/handler/redirect.c \
    $(LOCAL_PATH)/h2o/lib/handler/reproxy.c \
    $(LOCAL_PATH)/h2o/lib/handler/throttle_resp.c \
    $(LOCAL_PATH)/h2o/lib/handler/server_timing.c \
    $(LOCAL_PATH)/h2o/lib/handler/status.c \
    $(LOCAL_PATH)/h2o/lib/handler/headers_util.c \
    $(LOCAL_PATH)/h2o/lib/handler/status/events.c \
    $(LOCAL_PATH)/h2o/lib/handler/status/requests.c \
    $(LOCAL_PATH)/h2o/lib/handler/status/ssl.c \
    $(LOCAL_PATH)/h2o/lib/handler/http2_debug_state.c \
    $(LOCAL_PATH)/h2o/lib/handler/status/durations.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/access_log.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/compress.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/errordoc.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/expires.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/fastcgi.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/file.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/headers.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/proxy.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/redirect.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/reproxy.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/throttle_resp.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/server_timing.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/status.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/http2_debug_state.c \
    $(LOCAL_PATH)/h2o/lib/handler/configurator/headers_util.c \
    $(LOCAL_PATH)/h2o/lib/http1.c \
    $(LOCAL_PATH)/h2o/lib/tunnel.c \
    $(LOCAL_PATH)/h2o/lib/http2/cache_digests.c \
    $(LOCAL_PATH)/h2o/lib/http2/casper.c \
    $(LOCAL_PATH)/h2o/lib/http2/connection.c \
    $(LOCAL_PATH)/h2o/lib/http2/frame.c \
    $(LOCAL_PATH)/h2o/lib/http2/hpack.c \
    $(LOCAL_PATH)/h2o/lib/http2/scheduler.c \
    $(LOCAL_PATH)/h2o/lib/http2/stream.c \
    $(LOCAL_PATH)/h2o/lib/http2/http2_debug_state.c \

LOCAL_SRC_FILES += \
    $(LOCAL_PATH)/libh2o_socket_client/libh2o_socket_client.c \
    $(LOCAL_PATH)/libh2o_http_client/libh2o_http_client.c \
    $(LOCAL_PATH)/libh2o_http_server/libh2o_http_server.c \
    $(LOCAL_PATH)/libh2o_websocket_client/libh2o_websocket_client.c \


LOCAL_SRC_FILES += \
    $(LOCAL_PATH)/wslay/lib/wslay_event.c \
    $(LOCAL_PATH)/wslay/lib/wslay_frame.c \
    $(LOCAL_PATH)/wslay/lib/wslay_net.c \
    $(LOCAL_PATH)/wslay/lib/wslay_queue.c \
    $(LOCAL_PATH)/wslay/lib/wslay_stack.c \

LOCAL_C_INCLUDES:= \
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

# ignore warnigs
LOCAL_CFLAGS := -Wno-error=return-type -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare
LOCAL_CFLAGS += -DH2O_USE_EPOLL=1 -DWSLAY_VERSION=\"1.0.1-DEV\"

# for pipe2
LOCAL_CFLAGS += -D_GNU_SOURCE

# for wslay
LOCAL_CFLAGS += -DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H

LOCAL_LIBNAMES += 
LOCAL_LIBDIRS += 

#######################################################


include $(ROOT_DIR)/build/makefile-$(TARGET_ARCH).mk

