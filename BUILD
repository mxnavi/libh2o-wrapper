load("@rules_cc//cc:defs.bzl", "cc_library")
load("//modules/map/hdmap_static:build/build.bzl", "COPTS")

package(default_visibility = ["//visibility:public"])

config_setting(
    name = "H2O_HAS_WSLAY",
    values = {
        "define" : "H2O_HAS_WSLAY=1",
    },
)

config_setting(
    name = "H2O_HAS_HIREDIS",
    values = {
        "define" : "H2O_HAS_HIREDIS=1",
    },
)

config_setting(
    name = "H2O_HAS_LIBYRMCDS",
    values = {
        "define" : "H2O_HAS_LIBYRMCDS=1",
    },
)

config_setting(
    name = "qnx",
    values = {
        "define" : "platform=qnx",
    },
    # constraint_values = ["@bazel_tools//platforms:qnx"],  # not work
)

h2o_SRC_FILES = [
    "h2o/deps/cloexec/cloexec.c",
    "h2o/deps/libgkc/gkc.c",
    "h2o/deps/picohttpparser/picohttpparser.c",
    "h2o/lib/common/cache.c",
    "h2o/lib/common/file.c",
    "h2o/lib/common/filecache.c",
    "h2o/lib/common/hostinfo.c",
    "h2o/lib/common/http1client.c",
    "h2o/lib/common/http2client.c",
    "h2o/lib/common/httpclient.c",
    "h2o/lib/common/memory.c",
    "h2o/lib/common/multithread.c",
    "h2o/lib/common/serverutil.c",
    "h2o/lib/common/socket.c",
    "h2o/lib/common/socketpool.c",
    "h2o/lib/common/string.c",
    "h2o/lib/common/time.c",
    "h2o/lib/common/timerwheel.c",
    "h2o/lib/common/token.c",
    "h2o/lib/common/url.c",
    "h2o/lib/common/balancer/roundrobin.c",
    "h2o/lib/common/balancer/least_conn.c",
    "h2o/lib/core/config.c",
    "h2o/lib/core/configurator.c",
    "h2o/lib/core/context.c",
    "h2o/lib/core/headers.c",
    "h2o/lib/core/logconf.c",
    "h2o/lib/core/proxy.c",
    "h2o/lib/core/request.c",
    "h2o/lib/core/util.c",
    "h2o/lib/handler/access_log.c",
    "h2o/lib/handler/compress.c",
    "h2o/lib/handler/compress/gzip.c",
    "h2o/lib/handler/errordoc.c",
    "h2o/lib/handler/expires.c",
    "h2o/lib/handler/fastcgi.c",
    "h2o/lib/handler/file.c",
    "h2o/lib/handler/headers.c",
    "h2o/lib/handler/mimemap.c",
    "h2o/lib/handler/proxy.c",
    "h2o/lib/handler/redirect.c",
    "h2o/lib/handler/reproxy.c",
    "h2o/lib/handler/throttle_resp.c",
    "h2o/lib/handler/server_timing.c",
    "h2o/lib/handler/status.c",
    "h2o/lib/handler/headers_util.c",
    "h2o/lib/handler/status/events.c",
    "h2o/lib/handler/status/requests.c",
    "h2o/lib/handler/status/ssl.c",
    "h2o/lib/handler/http2_debug_state.c",
    "h2o/lib/handler/status/durations.c",
    "h2o/lib/handler/configurator/access_log.c",
    "h2o/lib/handler/configurator/compress.c",
    "h2o/lib/handler/configurator/errordoc.c",
    "h2o/lib/handler/configurator/expires.c",
    "h2o/lib/handler/configurator/fastcgi.c",
    "h2o/lib/handler/configurator/file.c",
    "h2o/lib/handler/configurator/headers.c",
    "h2o/lib/handler/configurator/proxy.c",
    "h2o/lib/handler/configurator/redirect.c",
    "h2o/lib/handler/configurator/reproxy.c",
    "h2o/lib/handler/configurator/throttle_resp.c",
    "h2o/lib/handler/configurator/server_timing.c",
    "h2o/lib/handler/configurator/status.c",
    "h2o/lib/handler/configurator/http2_debug_state.c",
    "h2o/lib/handler/configurator/headers_util.c",
    "h2o/lib/http1.c",
    "h2o/lib/tunnel.c",
    "h2o/lib/http2/cache_digests.c",
    "h2o/lib/http2/casper.c",
    "h2o/lib/http2/connection.c",
    "h2o/lib/http2/frame.c",
    "h2o/lib/http2/hpack.c",
    "h2o/lib/http2/scheduler.c",
    "h2o/lib/http2/stream.c",
    "h2o/lib/http2/http2_debug_state.c",
    "h2o/deps/ssl-conservatory/openssl/openssl_hostname_validation.c",
] + select({
    ":H2O_HAS_WSLAY" : [
        "h2o/lib/websocket.c",
        "h2o/lib/websocketclient.c",
        "libh2o_websocket_client/libh2o_websocket_client.c",
        "wslay/lib/wslay_event.c",
        "wslay/lib/wslay_frame.c",
        "wslay/lib/wslay_net.c",
        "wslay/lib/wslay_queue.c",
        "wslay/lib/wslay_stack.c",
    ],
    "//conditions:default": [],}
) + select({
    ":H2O_HAS_HIREDIS" : [
        "h2o/deps/hiredis/async.c",
        "h2o/deps/hiredis/hiredis.c",
        "h2o/deps/hiredis/net.c",
        "h2o/deps/hiredis/read.c",
        "h2o/deps/hiredis/sds.c",
        "h2o/lib/common/redis.c",
    ],
    "//conditions:default": [],}
) + select ({
    ":H2O_HAS_LIBYRMCDS" : [
        "h2o/deps/libyrmcds/close.c",
        "h2o/deps/libyrmcds/connect.c",
        "h2o/deps/libyrmcds/recv.c",
        "h2o/deps/libyrmcds/send.c",
        "h2o/deps/libyrmcds/send_text.c",
        "h2o/deps/libyrmcds/socket.c",
        "h2o/deps/libyrmcds/strerror.c",
        "h2o/deps/libyrmcds/text_mode.c",
        "h2o/lib/common/memcached.c",
    ],
    "//conditions:default": [],}
)

h2o_wrapper_SRC_FILES = [
    "libh2o_log.c",
    "libh2o_cmn.c",
    "libh2o_socket_client/libh2o_socket_client.c",
    "libh2o_http_client/libh2o_http_client.c",
    "libh2o_http_server/libh2o_http_server.c",
    "libh2o_socket_server/libh2o_socket_server.c",
]

local_copts = [
    "-isystem modules/map/hdmap_static/foundation/include",
    "-isystem modules/map/hdmap_static/libh2o-wrapper",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/wslay/lib/includes",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/include",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/klib",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/picohttpparser",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/libyrmcds",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/cloexec",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/hiredis",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/yoml",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/libgkc",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/golombset",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/lib/common",
    "-isystem modules/map/hdmap_static/libh2o-wrapper/h2o/deps/ssl-conservatory/openssl/",
    "-Wno-deprecated-declarations",
    "-Wno-error=return-type",
    "-Wno-unused-paramete",
    "-Wno-missing-field-initializer",
    "-Wno-sign-compare",
    "-DHAVE_ARPA_INET_H -DHAVE_NETINET_IN_H",
    "-Dh2o_error_printf=libh2o_error_printf",
    "-DH2O_EVLOOP_USE_CLOCK_MONOTONIC",
] + select({
    ":H2O_HAS_WSLAY" : [
        "-DH2O_HAS_WSLAY",
    ],
    "//conditions:default": [],}
) + select({
    ":H2O_HAS_HIREDIS" : [
        "-DH2O_HAS_HIREDIS",
    ],
    "//conditions:default": [],}
) + select ({
    ":H2O_HAS_LIBYRMCDS" : [
        "-DH2O_HAS_LIBYRMCDS",
    ],
    "//conditions:default": [],}
) + select ({
    ":qnx" : [
        "-DH2O_USE_POLL=1",
    ],
    "//conditions:default": [ # linux android
        "-DH2O_USE_EPOLL=1",
    ],}
)

cc_library(
    name = "h2o-wrapper",
    srcs = h2o_SRC_FILES + h2o_wrapper_SRC_FILES,
    visibility = ["//visibility:public"],
    alwayslink = True,
    copts = COPTS + local_copts,
    deps = [
        "//modules/map/hdmap_static",
    ],
)
