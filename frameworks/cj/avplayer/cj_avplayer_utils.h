/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_AVPLAYER_UTILS_H
#define CJ_AVPLAYER_UTILS_H

#include <cstdint>
#include <memory>
#include <refbase.h>
#include <string>
#include "cj_common_ffi.h"
#include "player.h"

#define INVALID_ID (-1)
#define MAX_SIZE_OF_MEDIADESCRIPTIONKEY (14)

namespace OHOS {
namespace Media {
struct CSubtitleInfo {
    char *text;
    int32_t startTime;
    int32_t duration;
};

struct CValueType {
    int32_t number;
    double dou;
    char *str;
};

struct CMediaDescription {
    char **key;
    CValueType *value;
    int64_t size;
};

struct CArrCMediaDescription {
    CMediaDescription *head;
    int64_t size;
};

struct CArrFloat {
    float *head;
    int64_t size;
};

struct CMediaKeySystemInfo {
    char *uuid;
    CArrUI8 pssh;
};

struct CArrCMediaKeySystemInfo {
    CMediaKeySystemInfo *head;
    int64_t size;
};

struct CAVFileDescriptor {
    int32_t fd;
    int64_t offset;
    int64_t length;
};

struct CAVDataSrcDescriptor {
    int64_t fileSize;
    int64_t callback;
};

struct CPlaybackInfo {
    int32_t key;
    void *value;
};

struct CArrCPlaybackInfo {
    CPlaybackInfo *infos;
    int64_t size;
};

struct CPlayStrategy {
    uint32_t preferredWidth;
    uint32_t preferredHeight;
    uint32_t preferredBufferDuration;
    bool preferredHdr;
    int32_t mutedMediaType;
    char *preferredAudioLanguage;
    char *preferredSubtitleLanguage;
};

char *MallocCString(const std::string &origin);
CArrI32 Convert2CArrI32(const std::vector<int32_t> &arr);
CArrFloat Convert2CArrFloat(const std::vector<float> &arr);
CSubtitleInfo Convert2CSubtitleInfo(std::string text, int32_t pts, int32_t duration);
CMediaDescription Convert2CMediaDescription(const Format trackInfo);
CArrCMediaDescription Convert2CArrCMediaDescription(const std::vector<Format> trackInfo);
} // namespace Media
} // namespace OHOS

#endif