/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_SERVICE_SERVER_BASE_H
#define SCREEN_CAPTURE_SERVICE_SERVER_BASE_H

#include <string>

namespace OHOS {
namespace Media {
enum VideoPermissionState : int32_t {
    START_VIDEO = 0,
    STOP_VIDEO = 1
};

enum AVScreenCaptureState : int32_t {
    CREATED = 0,
    POPUP_WINDOW = 1,
    STARTING = 2,
    STARTED = 3,
    PAUSED = 4,
    RESUMED = 5,
    STOPPED = 6
};

enum AVScreenCaptureAvType : int8_t {
    INVALID_TYPE = -1,
    AUDIO_TYPE = 0,
    VIDEO_TYPE = 1,
    AV_TYPE = 2
};

enum AVScreenCaptureDataMode : int8_t {
    BUFFER_MODE = 0,
    SUFFACE_MODE = 1,
    FILE_MODE = 2
};

enum StopReason: int8_t {
    NORMAL_STOPPED = 0,
    RECEIVE_USER_PRIVACY_AUTHORITY_FAILED = 1,
    POST_START_SCREENCAPTURE_HANDLE_FAILURE = 2,
    REQUEST_USER_PRIVACY_AUTHORITY_FAILED = 3,
    STOP_REASON_INVALID = 4
};

enum Capability : uint32_t {
    CAP_NONE = 0,
    CAP_INIT = 1 << 0,
    CAP_CONFIG = 1 << 1,
    CAP_ALIVE = 1 << 2,
    CAP_POPUP = 1 << 4,
    CAP_RUNNING = 1 << 5,
    CAP_PAUSED = 1 << 6,
    CAP_ACTIVE = 1 << 7,
};

enum AudioStateFlag : uint32_t {
    AUDIO_STATE_HEADSET = 1 << 0,
    AUDIO_STATE_VOIP = 1 << 1,
    AUDIO_STATE_TEL = 1 << 2,
};

struct StatisticalEventInfo {
    int32_t errCode = 0;
    std::string errMsg;
    int32_t captureDuration = -1;
    bool userAgree = false;
    bool requireMic = false;
    bool enableMic = false;
    std::string videoResolution;
    StopReason stopReason = StopReason::STOP_REASON_INVALID;
    int32_t startLatency = -1;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_SERVER_BASE_H
