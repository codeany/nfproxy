#LOCAL_PATH is used to locate source files in the development tree.
#the macro my-dir provided by the build system, indicates the path of the current directory
LOCAL_PATH:=$(call my-dir)
 
#####################################################################
#                          build libnflink                          #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=nflink
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include
LOCAL_SRC_FILES:=\
    libnfnetlink/src/iftable.c \
    libnfnetlink/src/rtnl.c \
    libnfnetlink/src/libnfnetlink.c
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#                      build libnetfilter_queue                     #
#####################################################################
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
    $(LOCAL_PATH)/libnetfilter_queue/include
LOCAL_MODULE:=netfilter_queue
LOCAL_SRC_FILES:=libnetfilter_queue/src/libnetfilter_queue.c
LOCAL_STATIC_LIBRARIES:=libnflink
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)

#####################################################################
#                    build libnetfilter_conntrack                   #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODILE:=netfilter_conntrack
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
    $(LOCAL_PATH)/libnetfilter_conntrack/include
LOCAL_MODULE:=netfilter_conntrack
LOCAL_SRC_FILES:=\
    libnetfilter_conntrack/src/main.c \
    libnetfilter_conntrack/src/conntrack/api.c \
    libnetfilter_conntrack/src/conntrack/setter.c \
    libnetfilter_conntrack/src/conntrack/build.c \
    libnetfilter_conntrack/src/conntrack/objopt.c \
    libnetfilter_conntrack/src/conntrack/filter_dump.c

LOCAL_STATIC_LIBRARIES:=libnflink
include $(BUILD_STATIC_LIBRARY)
#include $(BUILD_SHARED_LIBRARY)
 
#####################################################################
#                          build nfproxy                            #
#####################################################################
include $(CLEAR_VARS)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libnfnetlink/include \
    $(LOCAL_PATH)/libnetfilter_queue/include \
    $(LOCAL_PATH)/libnetfilter_conntrack/include
LOCAL_MODULE:=nfproxy
LOCAL_SRC_FILES:=\
    nfproxy.c \
    nfqueue.c \
    nfconntrack.c
LOCAL_STATIC_LIBRARIES:=libnetfilter_queue libnetfilter_conntrack
LOCAL_LDLIBS:=-llog -lm
#include $(BUILD_SHARED_LIBRARY)
include $(BUILD_EXECUTABLE)

#####################################################################
#                          build client                             #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=client
LOCAL_SRC_FILES:=client.c
LOCAL_LDLIBS:=-llog -lm
include $(BUILD_EXECUTABLE)

#####################################################################
#                          build server                             #
#####################################################################
include $(CLEAR_VARS)
LOCAL_MODULE:=server
LOCAL_SRC_FILES:=server.c
LOCAL_LDLIBS:=-llog -lm
include $(BUILD_EXECUTABLE)
