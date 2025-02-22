/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef METADATAHELPER_UTIL_H
#define METADATAHELPER_UTIL_H

#include <cstdint>
#include <vector>
#include <securec.h>
#include "meta/meta.h"

typedef struct  {
    int32_t width;
    int32_t height;
} CPixelMapParams;

typedef struct {
    int32_t fd;
    int64_t offset;
    int64_t length;
} CAVFileDescriptor;

typedef struct {
    int64_t fileSize;
    int64_t callback;
} CAVDataSrcDescriptor;

typedef struct {
    float latitude;
    float longitude;
} CLocation;

typedef struct {
    char** key;
    char** value;
    int64_t size;
} CCustomInfo;

typedef struct {
    char* album;
    char* albumArtist;
    char* artist;
    char* author;
    char* dateTime;
    char* dateTimeFormat;
    char* composer;
    char* duration;
    char* genre;
    char* hasAudio;
    char* hasVideo;
    char* mimeType;
    char* trackCount;
    char* sampleRate;
    char* title;
    char* videoHeight;
    char* videoWidth;
    char* videoOrientation;
    int32_t hdrType;
    CLocation location;
    CCustomInfo customInfo;
} CAVMetadata;

#endif // METADATAHELPER_UTIL_H
