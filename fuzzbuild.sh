#!/bin/bash

SANITIZER="address,fuzzer-no-link" \
CC=`which clang` \
CXX=`which clang++` \
CFLAGS="-g -fsanitize=$SANITIZER -fno-omit-frame-pointer" \
CXXFLAGS="-g -fsanitize=$SANITIZER" \
LDFLAGS="-g -fsanitize=$SANITIZER" make

clang -g -O0 \
    -I.  -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
    -fno-strict-aliasing -Wextra -Wno-unused-parameter -Wno-missing-field-initializers \
    -DUWSGI_HAS_IFADDRS -DUWSGI_ZLIB -DUWSGI_LOCK_USE_MUTEX -DUWSGI_EVENT_USE_EPOLL \
    -DUWSGI_EVENT_TIMER_USE_TIMERFD -DUWSGI_EVENT_FILEMONITOR_USE_INOTIFY -fPIC \
    -DUWSGI_AS_SHARED_LIBRARY  -DUWSGI_PCRE -DUWSGI_ROUTING -DUWSGI_CAP \
    -DUWSGI_UUID -DUWSGI_VERSION="\"2.1-dev-8c68860e\"" -DUWSGI_VERSION_BASE="2" \
    -DUWSGI_VERSION_MAJOR="1" -DUWSGI_VERSION_MINOR="0" -DUWSGI_VERSION_REVISION="0" \
    -DUWSGI_VERSION_CUSTOM="\"dev-8c68860e\"" -DUWSGI_YAML -I/usr/include/ -DUWSGI_JSON \
    -DUWSGI_JSON_YAJL -DUWSGI_SSL -I/usr/include/libxml2 -DUWSGI_XML -DUWSGI_XML_LIBXML2 \
    -DUWSGI_PLUGIN_DIR="\".\"" \
    -DUWSGI_DECLARE_EMBEDDED_PLUGINS="UDEP(python);UDEP(ping);UDEP(cache);UDEP(nagios);UDEP(rrdtool);UDEP(carbon);UDEP(rpc);UDEP(corerouter);UDEP(fastrouter);UDEP(http);UDEP(ugreen);UDEP(signal);UDEP(syslog);UDEP(rsyslog);UDEP(logsocket);UDEP(router_uwsgi);UDEP(router_redirect);UDEP(router_basicauth);UDEP(zergpool);UDEP(redislog);UDEP(mongodblog);UDEP(router_rewrite);UDEP(router_http);UDEP(logfile);UDEP(router_cache);UDEP(rawrouter);UDEP(router_static);UDEP(sslrouter);UDEP(spooler);UDEP(cheaper_busyness);UDEP(symcall);UDEP(transformation_tofile);UDEP(transformation_gzip);UDEP(transformation_chunked);UDEP(transformation_offload);UDEP(router_memcached);UDEP(router_redis);UDEP(router_hash);UDEP(router_expires);UDEP(router_metrics);UDEP(transformation_template);UDEP(stats_pusher_socket);UDEP(router_fcgi);" \
    -DUWSGI_LOAD_EMBEDDED_PLUGINS="ULEP(python);ULEP(ping);ULEP(cache);ULEP(nagios);ULEP(rrdtool);ULEP(carbon);ULEP(rpc);ULEP(corerouter);ULEP(fastrouter);ULEP(http);ULEP(ugreen);ULEP(signal);ULEP(syslog);ULEP(rsyslog);ULEP(logsocket);ULEP(router_uwsgi);ULEP(router_redirect);ULEP(router_basicauth);ULEP(zergpool);ULEP(redislog);ULEP(mongodblog);ULEP(router_rewrite);ULEP(router_http);ULEP(logfile);ULEP(router_cache);ULEP(rawrouter);ULEP(router_static);ULEP(sslrouter);ULEP(spooler);ULEP(cheaper_busyness);ULEP(symcall);ULEP(transformation_tofile);ULEP(transformation_gzip);ULEP(transformation_chunked);ULEP(transformation_offload);ULEP(router_memcached);ULEP(router_redis);ULEP(router_hash);ULEP(router_expires);ULEP(router_metrics);ULEP(transformation_template);ULEP(stats_pusher_socket);ULEP(router_fcgi);" \
    -DUWSGI_CFLAGS=\"2d492e202d57616c6c202d576572726f72202d445f4c4152474546494c455f534f55524345202d445f46494c455f4f46465345545f424954533d3634202d67202d6673616e6974697a653d616464726573732c66757a7a65722d6e6f2d6c696e6b202d666e6f2d6f6d69742d6672616d652d706f696e746572202d666e6f2d7374726963742d616c696173696e67202d576578747261202d576e6f2d756e757365642d706172616d65746572202d576e6f2d6d697373696e672d6669656c642d696e697469616c697a657273202d4455575347495f4841535f49464144445253202d4455575347495f5a4c4942202d4455575347495f4c4f434b5f5553455f4d55544558202d4455575347495f4556454e545f5553455f45504f4c4c202d4455575347495f4556454e545f54494d45525f5553455f54494d45524644202d4455575347495f4556454e545f46494c454d4f4e49544f525f5553455f494e4f54494659202d66504943202d4455575347495f41535f5348415245445f4c49425241525920202d4455575347495f50435245202d4455575347495f524f5554494e47202d4455575347495f434150202d4455575347495f55554944202d4455575347495f56455253494f4e3d225c22322e312d6465762d38633638383630655c2222202d4455575347495f56455253494f4e5f424153453d223222202d4455575347495f56455253494f4e5f4d414a4f523d223122202d4455575347495f56455253494f4e5f4d494e4f523d223022202d4455575347495f56455253494f4e5f5245564953494f4e3d223022202d4455575347495f56455253494f4e5f435553544f4d3d225c226465762d38633638383630655c2222202d4455575347495f59414d4c202d492f7573722f696e636c7564652f202d4455575347495f4a534f4e202d4455575347495f4a534f4e5f59414a4c202d4455575347495f53534c202d492f7573722f696e636c7564652f6c6962786d6c32202d4455575347495f584d4c202d4455575347495f584d4c5f4c4942584d4c32202d4455575347495f504c5547494e5f4449523d225c222e5c2222202d4455575347495f4445434c4152455f454d4245444445445f504c5547494e533d225544455028707974686f6e293b554445502870696e67293b55444550286361636865293b55444550286e6167696f73293b5544455028727264746f6f6c293b5544455028636172626f6e293b5544455028727063293b5544455028636f7265726f75746572293b554445502866617374726f75746572293b554445502868747470293b554445502875677265656e293b55444550287369676e616c293b55444550287379736c6f67293b5544455028727379736c6f67293b55444550286c6f67736f636b6574293b5544455028726f757465725f7577736769293b5544455028726f757465725f7265646972656374293b5544455028726f757465725f626173696361757468293b55444550287a657267706f6f6c293b554445502872656469736c6f67293b55444550286d6f6e676f64626c6f67293b5544455028726f757465725f72657772697465293b5544455028726f757465725f68747470293b55444550286c6f6766696c65293b5544455028726f757465725f6361636865293b5544455028726177726f75746572293b5544455028726f757465725f737461746963293b554445502873736c726f75746572293b554445502873706f6f6c6572293b5544455028636865617065725f627573796e657373293b554445502873796d63616c6c293b55444550287472616e73666f726d6174696f6e5f746f66696c65293b55444550287472616e73666f726d6174696f6e5f677a6970293b55444550287472616e73666f726d6174696f6e5f6368756e6b6564293b55444550287472616e73666f726d6174696f6e5f6f66666c6f6164293b5544455028726f757465725f6d656d636163686564293b5544455028726f757465725f7265646973293b5544455028726f757465725f68617368293b5544455028726f757465725f65787069726573293b5544455028726f757465725f6d657472696373293b55444550287472616e73666f726d6174696f6e5f74656d706c617465293b554445502873746174735f7075736865725f736f636b6574293b5544455028726f757465725f66636769293b22202d4455575347495f4c4f41445f454d4245444445445f504c5547494e533d22554c455028707974686f6e293b554c45502870696e67293b554c4550286361636865293b554c4550286e6167696f73293b554c455028727264746f6f6c293b554c455028636172626f6e293b554c455028727063293b554c455028636f7265726f75746572293b554c45502866617374726f75746572293b554c45502868747470293b554c45502875677265656e293b554c4550287369676e616c293b554c4550287379736c6f67293b554c455028727379736c6f67293b554c4550286c6f67736f636b6574293b554c455028726f757465725f7577736769293b554c455028726f757465725f7265646972656374293b554c455028726f757465725f626173696361757468293b554c4550287a657267706f6f6c293b554c45502872656469736c6f67293b554c4550286d6f6e676f64626c6f67293b554c455028726f757465725f72657772697465293b554c455028726f757465725f68747470293b554c4550286c6f6766696c65293b554c455028726f757465725f6361636865293b554c455028726177726f75746572293b554c455028726f757465725f737461746963293b554c45502873736c726f75746572293b554c45502873706f6f6c6572293b554c455028636865617065725f627573796e657373293b554c45502873796d63616c6c293b554c4550287472616e73666f726d6174696f6e5f746f66696c65293b554c4550287472616e73666f726d6174696f6e5f677a6970293b554c4550287472616e73666f726d6174696f6e5f6368756e6b6564293b554c4550287472616e73666f726d6174696f6e5f6f66666c6f6164293b554c455028726f757465725f6d656d636163686564293b554c455028726f757465725f7265646973293b554c455028726f757465725f68617368293b554c455028726f757465725f65787069726573293b554c455028726f757465725f6d657472696373293b554c4550287472616e73666f726d6174696f6e5f74656d706c617465293b554c45502873746174735f7075736865725f736f636b6574293b554c455028726f757465725f66636769293b22\" \
    -fno-omit-frame-pointer -fsanitize=address,fuzzer harness.c uwsgi -o fuzz \
    -lpthread -lm -rdynamic -ldl -lz -lpcre -lcap -luuid -lyajl -lssl -lcrypto -lxml2 -lpthread -ldl -lutil -lm -lpython2.7 -lcrypt