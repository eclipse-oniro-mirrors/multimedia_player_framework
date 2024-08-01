/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_MEDIA_LOG_H
#define OHOS_MEDIA_LOG_H

#include <hilog/log.h>
#include <cinttypes>

#ifdef OHOS_MEDIA_LOG_DFX
#include "dfx_log_dump.h"
#endif

namespace OHOS {

#undef LOG_DOMAIN_PLAYER
#define LOG_DOMAIN_PLAYER        0xD002B2B
#undef LOG_DOMAIN_RECORDER
#define LOG_DOMAIN_RECORDER      0xD002B2C
#undef LOG_DOMAIN_METADATA
#define LOG_DOMAIN_METADATA      0xD002B2D
#undef LOG_DOMAIN_SCREENCAPTURE
#define LOG_DOMAIN_SCREENCAPTURE 0xD002B2E
#undef LOG_DOMAIN_SOUNDPOOL
#define LOG_DOMAIN_SOUNDPOOL     0xD002B3B
#undef LOG_DOMAIN_AUDIO_NAPI
#define LOG_DOMAIN_AUDIO_NAPI    0xD002B20

#undef LOG_TAG
#define LOG_TAG LABEL.tag
#undef LOG_DOMAIN
#define LOG_DOMAIN LABEL.domain
#undef LOG_TYPE
#define LOG_TYPE LABEL.type

#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)

#define MEDIA_LOG(func, fmt, args...)                                   \
    do {                                                                \
        if (LABEL.tag != nullptr) {                                     \
            (void)func(LOG_TYPE, "#%{public}d " fmt, __LINE__, ##args); \
        }                                                               \
    } while (0)

#ifdef OHOS_MEDIA_LOG_DFX
#define DUMP_LOG(level, fmt, args...)                                                                                \
    do {                                                                                                             \
        (void)OHOS::Media::DfxLogDump::GetInstance().SaveLog(level, LABEL, "{%s():%d} " fmt, __FUNCTION__, __LINE__, \
                                                             ##args);                                                \
    } while (0);
#define MEDIA_LOGD(fmt, ...)             \
    DUMP_LOG("LOGD", fmt, ##__VA_ARGS__) \
    MEDIA_LOG(HILOG_DEBUG, fmt, ##__VA_ARGS__)
#define MEDIA_LOGI(fmt, ...)             \
    DUMP_LOG("LOGI", fmt, ##__VA_ARGS__) \
    MEDIA_LOG(HILOG_INFO, fmt, ##__VA_ARGS__)
#define MEDIA_LOGW(fmt, ...)             \
    DUMP_LOG("LOGW", fmt, ##__VA_ARGS__) \
    MEDIA_LOG(HILOG_WARN, fmt, ##__VA_ARGS__)
#define MEDIA_LOGE(fmt, ...)             \
    DUMP_LOG("LOGE", fmt, ##__VA_ARGS__) \
    MEDIA_LOG(HILOG_ERROR, fmt, ##__VA_ARGS__)
#define MEDIA_LOGF(fmt, ...)             \
    DUMP_LOG("LOGF", fmt, ##__VA_ARGS__) \
    MEDIA_LOG(HILOG_FATAL, fmt, ##__VA_ARGS__)
#else
#define MEDIA_LOGD(fmt, ...) MEDIA_LOG(HILOG_DEBUG, fmt, ##__VA_ARGS__)
#define MEDIA_LOGI(fmt, ...) MEDIA_LOG(HILOG_INFO, fmt, ##__VA_ARGS__)
#define MEDIA_LOGW(fmt, ...) MEDIA_LOG(HILOG_WARN, fmt, ##__VA_ARGS__)
#define MEDIA_LOGE(fmt, ...) MEDIA_LOG(HILOG_ERROR, fmt, ##__VA_ARGS__)
#define MEDIA_LOGF(fmt, ...) MEDIA_LOG(HILOG_FATAL, fmt, ##__VA_ARGS__)
#endif

#define MEDIA_LOG_PRERELEASE(op, fmt, args...)                         \
    do {                                                               \
        op(LOG_ONLY_PRERELEASE, "#%{public}d " fmt, __LINE__, ##args); \
    } while (0)

#define MEDIA_LOGI_NO_RELEASE(fmt, ...) MEDIA_LOG_PRERELEASE(HILOG_INFO, fmt, ##__VA_ARGS__)
#define MEDIA_LOGW_NO_RELEASE(fmt, ...) MEDIA_LOG_PRERELEASE(HILOG_WARN, fmt, ##__VA_ARGS__)
#define MEDIA_LOGE_NO_RELEASE(fmt, ...) MEDIA_LOG_PRERELEASE(HILOG_ERROR, fmt, ##__VA_ARGS__)
#define MEDIA_LOGF_NO_RELEASE(fmt, ...) MEDIA_LOG_PRERELEASE(HILOG_FATAL, fmt, ##__VA_ARGS__)

#define CHECK_AND_RETURN(cond)                                         \
    do {                                                               \
        if (!(cond)) {                                                 \
            MEDIA_LOGE_NO_RELEASE("%{public}s, check failed!", #cond); \
            return;                                                    \
        }                                                              \
    } while (0)

#define CHECK_AND_RETURN_RET(cond, ret)                                                       \
    do {                                                                                      \
        if (!(cond)) {                                                                        \
            MEDIA_LOGE_NO_RELEASE("%{public}s, check failed! ret = %{public}s", #cond, #ret); \
            return ret;                                                                       \
        }                                                                                     \
    } while (0)

#define CHECK_AND_RETURN_RET_LOG(cond, ret, fmt, ...) \
    do {                                              \
        if (!(cond)) {                                \
            MEDIA_LOGE(fmt, ##__VA_ARGS__);           \
            return ret;                               \
        }                                             \
    } while (0)

#define CHECK_AND_RETURN_LOG(cond, fmt, ...) \
    do {                                     \
        if (!(cond)) {                       \
            MEDIA_LOGE(fmt, ##__VA_ARGS__);  \
            return;                          \
        }                                    \
    } while (0)

#define CHECK_AND_BREAK_LOG(cond, fmt, ...) \
    if (1) {                                \
        if (!(cond)) {                      \
            MEDIA_LOGE(fmt, ##__VA_ARGS__); \
            break;                          \
        }                                   \
    } else                                  \
        void(0)

#define CHECK_AND_BREAK(cond)                                          \
    if (1) {                                                           \
        if (!(cond)) {                                                 \
            MEDIA_LOGE_NO_RELEASE("%{public}s, check failed!", #cond); \
            break;                                                     \
        }                                                              \
    } else                                                             \
        void(0)

#define CHECK_AND_CONTINUE(cond)                                       \
    if (1) {                                                           \
        if (!(cond)) {                                                 \
            MEDIA_LOGE_NO_RELEASE("%{public}s, check failed!", #cond); \
            continue;                                                  \
        }                                                              \
    } else                                                             \
        void(0)

#define CHECK_AND_CONTINUE_LOG(cond, fmt, ...) \
    if (1) {                                   \
        if (!(cond)) {                         \
            MEDIA_LOGE(fmt, ##__VA_ARGS__);    \
            continue;                          \
        }                                      \
    } else                                     \
        void(0)

#define TRUE_LOG(cond, func, fmt, ...)         \
    if (1) {                                   \
        if ((cond)) {                          \
            func(fmt, ##__VA_ARGS__);          \
        }                                      \
    } else                                     \
        void(0)

#define POINTER_MASK 0x00FFFFFF
#define FAKE_POINTER(addr) (POINTER_MASK & reinterpret_cast<uintptr_t>(addr))
}  // namespace OHOS
#endif  // OHOS_MEDIA_LOG_H
