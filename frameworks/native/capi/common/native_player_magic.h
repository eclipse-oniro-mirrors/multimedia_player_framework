/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef NATIVE_SCREEN_CAPTURE_MAGIC_H
#define NATIVE_SCREEN_CAPTURE_MAGIC_H

#include <refbase.h>
#include "screen_capture.h"
#include "player.h"
#include "recorder.h"
#include "avmetadatahelper.h"
#include "lpp_audio_streamer.h"
#include "lpp_video_streamer.h"

struct OH_AVScreenCapture : public OHOS::RefBase {
    OH_AVScreenCapture() = default;
    virtual ~OH_AVScreenCapture() = default;
};

struct OH_AVScreenCapture_ContentFilter : public OHOS::RefBase {
    OH_AVScreenCapture_ContentFilter() = default;
    virtual ~OH_AVScreenCapture_ContentFilter() = default;
};

struct OH_AVScreenCapture_CaptureStrategy : public OHOS::RefBase {
    OH_AVScreenCapture_CaptureStrategy() = default;
    virtual ~OH_AVScreenCapture_CaptureStrategy() = default;
};

struct OH_AVScreenCapture_UserSelectionInfo : public OHOS::RefBase {
    OH_AVScreenCapture_UserSelectionInfo() = default;
    virtual ~OH_AVScreenCapture_UserSelectionInfo() = default;
};

struct OH_AVPlayer : public OHOS::RefBase {
    OH_AVPlayer() = default;
    virtual ~OH_AVPlayer() = default;
    OHOS::Media::PlayerStates state_ = OHOS::Media::PLAYER_IDLE;
};

struct OH_AVRecorder : public OHOS::RefBase {
    OH_AVRecorder() = default;
    virtual ~OH_AVRecorder() = default;
};

struct OH_AVHttpHeader : public OHOS::RefBase {
    std::map<std::string, std::string> records = {};
    std::mutex recordsMutex;
};

struct OH_AVMediaSource : public OHOS::RefBase {
    OH_AVMediaSource() = default;
    virtual ~OH_AVMediaSource() = default;
};

struct OH_AVMediaSourceLoadingRequest : public OHOS::RefBase {
    OH_AVMediaSourceLoadingRequest() = default;
    virtual ~OH_AVMediaSourceLoadingRequest() = default;
};

struct OH_AVImageGenerator : public OHOS::RefBase {
    OH_AVImageGenerator() = default;
    virtual ~OH_AVImageGenerator() = default;
};

struct OH_AVMetadataExtractor : public OHOS::RefBase {
    OH_AVMetadataExtractor() = default;
    virtual ~OH_AVMetadataExtractor() = default;
};

struct OH_AVTranscoder : public OHOS::RefBase {
    OH_AVTranscoder() = default;
    virtual ~OH_AVTranscoder() = default;
};

struct OH_AVTranscoder_Config : public OHOS::RefBase {
    OH_AVTranscoder_Config() = default;
    virtual ~OH_AVTranscoder_Config() = default;
};

struct OH_LowPowerAudioSink : public OHOS::RefBase {
    OH_LowPowerAudioSink() = default;
    virtual ~OH_LowPowerAudioSink() = default;
};

struct OH_LowPowerVideoSink : public OHOS::RefBase {
    OH_LowPowerVideoSink() = default;
    virtual ~OH_LowPowerVideoSink() = default;
};

struct OH_AVSamplesBuffer : public OHOS::RefBase {
    OH_AVSamplesBuffer() = default;
    virtual ~OH_AVSamplesBuffer() = default;
};

struct OH_AVSeiMessageArray : public OHOS::RefBase {
    OH_AVSeiMessageArray() = default;
    virtual ~OH_AVSeiMessageArray() = default;
};

struct OH_LowPowerAVSink_Capability : public OHOS::RefBase {
    OH_LowPowerAVSink_Capability() = default;
    virtual ~OH_LowPowerAVSink_Capability() = default;
};

struct OH_AVMediaSourceLoader : public OHOS::RefBase {
    OH_AVMediaSourceLoader() = default;
    virtual ~OH_AVMediaSourceLoader() = default;
};
#endif // NATIVE_SCREEN_CAPTURE_MAGIC_H