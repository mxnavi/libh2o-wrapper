cmake_minimum_required(VERSION 3.20)
project(h2o-wrapper)

set(H2O_DIR ${CMAKE_CURRENT_SOURCE_DIR}/h2o)
set(CMAKE_C_FLAGS "-Wno-error=return-type -Wno-unused-parameter -Wno-missing-field-initializers -Wno-sign-compare -fPIC")

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/includes
    ${H2O_DIR}/include
    ${H2O_DIR}/deps/klib
    ${H2O_DIR}/deps/picohttpparser
    ${H2O_DIR}/deps/libyrmcds
    ${H2O_DIR}/deps/cloexec
    ${H2O_DIR}/deps/hiredis
    ${H2O_DIR}/deps/yoml
    ${H2O_DIR}/deps/libgkc
    ${H2O_DIR}/deps/golombset
)

file(GLOB H2O_SRC_FILES
    ${H2O_DIR}/deps/cloexec/cloexec.c
    ${H2O_DIR}/deps/hiredis/async.c
    ${H2O_DIR}/deps/hiredis/hiredis.c
    ${H2O_DIR}/deps/hiredis/net.c
    ${H2O_DIR}/deps/hiredis/read.c
    ${H2O_DIR}/deps/hiredis/sds.c
    ${H2O_DIR}/deps/libgkc/gkc.c
    ${H2O_DIR}/deps/libyrmcds/close.c
    ${H2O_DIR}/deps/libyrmcds/connect.c
    ${H2O_DIR}/deps/libyrmcds/recv.c
    ${H2O_DIR}/deps/libyrmcds/send.c
    ${H2O_DIR}/deps/libyrmcds/send_text.c
    ${H2O_DIR}/deps/libyrmcds/socket.c
    ${H2O_DIR}/deps/libyrmcds/strerror.c
    ${H2O_DIR}/deps/libyrmcds/text_mode.c
    ${H2O_DIR}/deps/picohttpparser/picohttpparser.c
    ${H2O_DIR}/lib/common/cache.c
    ${H2O_DIR}/lib/common/file.c
    ${H2O_DIR}/lib/common/filecache.c
    ${H2O_DIR}/lib/common/hostinfo.c
    ${H2O_DIR}/lib/common/http1client.c
    ${H2O_DIR}/lib/common/http2client.c
    ${H2O_DIR}/lib/common/httpclient.c
    ${H2O_DIR}/lib/common/memcached.c
    ${H2O_DIR}/lib/common/memory.c
    ${H2O_DIR}/lib/common/multithread.c
    ${H2O_DIR}/lib/common/redis.c
    ${H2O_DIR}/lib/common/serverutil.c
    ${H2O_DIR}/lib/common/socket.c
    ${H2O_DIR}/lib/common/socketpool.c
    ${H2O_DIR}/lib/common/string.c
    ${H2O_DIR}/lib/common/time.c
    ${H2O_DIR}/lib/common/timerwheel.c
    ${H2O_DIR}/lib/common/token.c
    ${H2O_DIR}/lib/common/url.c
    ${H2O_DIR}/lib/common/balancer/roundrobin.c
    ${H2O_DIR}/lib/common/balancer/least_conn.c
    ${H2O_DIR}/lib/core/config.c 
    ${H2O_DIR}/lib/core/configurator.c
    ${H2O_DIR}/lib/core/context.c
    ${H2O_DIR}/lib/core/headers.c
    ${H2O_DIR}/lib/core/logconf.c
    ${H2O_DIR}/lib/core/proxy.c
    ${H2O_DIR}/lib/core/request.c
    ${H2O_DIR}/lib/core/util.c
    ${H2O_DIR}/lib/handler/access_log.c
    ${H2O_DIR}/lib/handler/compress.c
    ${H2O_DIR}/lib/handler/compress/gzip.c
    ${H2O_DIR}/lib/handler/errordoc.c
    ${H2O_DIR}/lib/handler/expires.c
    ${H2O_DIR}/lib/handler/fastcgi.c
    ${H2O_DIR}/lib/handler/file.c
    ${H2O_DIR}/lib/handler/headers.c
    ${H2O_DIR}/lib/handler/mimemap.c
    ${H2O_DIR}/lib/handler/proxy.c
    ${H2O_DIR}/lib/handler/redirect.c
    ${H2O_DIR}/lib/handler/reproxy.c
    ${H2O_DIR}/lib/handler/throttle_resp.c
    ${H2O_DIR}/lib/handler/server_timing.c
    ${H2O_DIR}/lib/handler/status.c
    ${H2O_DIR}/lib/handler/headers_util.c
    ${H2O_DIR}/lib/handler/status/events.c
    ${H2O_DIR}/lib/handler/status/requests.c
    ${H2O_DIR}/lib/handler/status/ssl.c
    ${H2O_DIR}/lib/handler/http2_debug_state.c
    ${H2O_DIR}/lib/handler/status/durations.c
    ${H2O_DIR}/lib/handler/configurator/access_log.c
    ${H2O_DIR}/lib/handler/configurator/compress.c
    ${H2O_DIR}/lib/handler/configurator/errordoc.c
    ${H2O_DIR}/lib/handler/configurator/expires.c
    ${H2O_DIR}/lib/handler/configurator/fastcgi.c
    ${H2O_DIR}/lib/handler/configurator/file.c
    ${H2O_DIR}/lib/handler/configurator/headers.c
    ${H2O_DIR}/lib/handler/configurator/proxy.c
    ${H2O_DIR}/lib/handler/configurator/redirect.c 
    ${H2O_DIR}/lib/handler/configurator/reproxy.c
    ${H2O_DIR}/lib/handler/configurator/throttle_resp.c
    ${H2O_DIR}/lib/handler/configurator/server_timing.c
    ${H2O_DIR}/lib/handler/configurator/status.c
    ${H2O_DIR}/lib/handler/configurator/http2_debug_state.c
    ${H2O_DIR}/lib/handler/configurator/headers_util.c
    ${H2O_DIR}/lib/http1.c
    ${H2O_DIR}/lib/tunnel.c
    # ${H2O_DIR}/lib/websocket.c
    # ${H2O_DIR}/lib/websocketclient.c
    ${H2O_DIR}/lib/http2/cache_digests.c
    ${H2O_DIR}/lib/http2/casper.c
    ${H2O_DIR}/lib/http2/connection.c
    ${H2O_DIR}/lib/http2/frame.c
    ${H2O_DIR}/lib/http2/hpack.c
    ${H2O_DIR}/lib/http2/scheduler.c
    ${H2O_DIR}/lib/http2/stream.c
    ${H2O_DIR}/lib/http2/http2_debug_state.c
)

file(GLOB H2O_WRAPPER_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_cmn.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_socket_client/libh2o_socket_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_http_client/libh2o_http_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_http_server/libh2o_http_server.c
    # ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_websocket_client/libh2o_websocket_client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/libh2o_socket_server/libh2o_socket_server.c
)

file(GLOB WSLAY_SRC_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/wslay_event.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/wslay_frame.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/wslay_net.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/wslay_queue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wslay/lib/wslay_stack.c
)

#add_subdirectory(wslay)

add_library(${PROJECT_NAME} STATIC
    ${H2O_SRC_FILES}
    ${H2O_WRAPPER_SRC_FILES}
    ${WSLAY_SRC_FILES}
)
target_compile_definitions(
    ${PROJECT_NAME} PUBLIC
    H2O_USE_EPOLL=1
    WSLAY_VERSION=\"1.0.1-DEV\"
    HAVE_ARPA_INET_H
    HAVE_NETINET_IN_H
    h2o_error_printf=libh2o_error_printf
    H2O_EVLOOP_USE_CLOCK_MONOTONIC
    LIBH2O_MISSING_CUTILS_LOG)

target_link_libraries(${PROJECT_NAME} LINK_PUBLIC crypto ssl)

