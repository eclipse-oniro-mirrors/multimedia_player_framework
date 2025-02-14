/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef AV_RECORDER_COMMON_H
#define AV_RECORDER_COMMON_H

#include <cstdint>
#include <string>
#include <vector>
#include "recorder.h"
#include "cj_common_ffi.h"

constexpr int32_t INVALID_RECORDER_VALUE = -1;

struct CAVRecorderProfile {
    char *fileFormat;
    int32_t audioBitrate;
    int32_t audioChannels;
    char *audioCodec;
    int32_t audioSampleRate;
    int32_t videoBitrate;
    char *videoCodec;
    int32_t videoFrameWidth;
    int32_t videoFrameHeight;
    int32_t videoFrameRate;
    bool isHdr;
    bool enableTemporalScale;
};

struct CLocation {
    double latitude;
    double longitude;
    bool isValid;
};

struct CHashStrStrPair {
    char *key;
    char *value;
};

struct CHashStrStrArr {
    CHashStrStrPair *headers;
    int64_t size;
};

struct CAVMetadata {
    char *album;
    char *albumArtist;
    char *artist;
    char *author;
    char *dateTime;
    char *dateTimeFormat;
    char *composer;
    char *duration;
    char *genre;
    char *hasAudio;
    char *hasVideo;
    char *mimeType;
    char *trackCount;
    char *sampleRate;
    char *title;
    char *videoHeight;
    char *videoWeight;
    char *videoOrientation;
    int32_t hdrType;
    CLocation location;
    CHashStrStrArr customInfo;
    bool isValid;
};

struct CAVRecorderConfig {
    CAVRecorderProfile profile;
    char *url;
    int32_t audioSourceType;
    int32_t videoSourceType;
    int32_t fileGenerationMode;
    CAVMetadata metadata;
    int32_t maxDuration; // INT32_MAX by default
};

struct CRange {
    int32_t minVal;
    int32_t maxVal;
};

struct CEncoderInfo {
    char* mimeType;
    char& type;
    CRange bitRate;
    CRange frameRate;
    CRange width;
    CRange height;
    CRange channels;
    CArrI32 sampleRates;
};

struct CArrEncoderInfo {
    CEncoderInfo* head;
    int64_t size;
};

struct CErrorInfo {
    int32_t code;
    char* msg;
};

struct CStateChangeHandler {
    char* state;
    int32_t reason;
};

struct CAudioCapturerInfo {
    int32_t capturerFlags;
    int32_t source;
};

struct COptionArr {
    CArrI32 arr;
    bool hasValue;
};

struct CDeviceDescriptor {
    char* address;
    CArrI32 channelCounts;
    CArrI32 channelMasks;
    int32_t deviceRole;
    int32_t deviceType;
    char* displayName;
    COptionArr encodingTypes;
    int32_t id;
    char* name;
    CArrI32 sampleRates;
};

struct CArrDeviceDescriptor {
    CDeviceDescriptor* head;
    int64_t size;
};

struct CAudioCapturerChangeInfo {
    CAudioCapturerInfo audioCapturerInfo;
    CArrDeviceDescriptor deviceDescriptors;
    int32_t streamId;
    bool muted;
};
#endif /* AV_RECORDER_COMMON_H */
