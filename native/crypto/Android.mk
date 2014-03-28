NDK_PROJECT_PATH = .
LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := conceal
LOCAL_CFLAGS    := -Werror
LOCAL_SRC_FILES := aes.c aes_util.c init.c util.c
LOCAL_LDLIBS    := -llog

$(call import-add-path, $(LOCAL_PATH)/../)
LOCAL_SHARED_LIBRARIES += libcryptox
include $(BUILD_SHARED_LIBRARY)

$(call import-module,third-party/cryptox)
