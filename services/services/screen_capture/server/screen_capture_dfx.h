/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_DFX_H
#define SCREEN_CAPTURE_DFX_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

namespace OHOS {
namespace Media {

class ICaptureDfx;

struct AVScreenCaptureConfig;

struct ScDfxIdentity {
    uint64_t instanceId{0};
    int32_t uid{-1};
    int32_t pid{-1};
    std::string bundleName;
};

enum CaptureEndReason : int8_t {
    NORMAL_STOPPED = 0,
    RECEIVE_USER_PRIVACY_AUTHORITY_FAILED = 1,
    POST_START_SCREENCAPTURE_HANDLE_FAILURE = 2,
    REQUEST_USER_PRIVACY_AUTHORITY_FAILED = 3,
    STOP_REASON_INVALID = 4,
    START_PREPARE_FAILED = 5,
    START_INVALID_STATE = 6,
    START_NOTIFICATION_FAILED = 7,
};

struct StatisticalEventInfo {
    int32_t errCode = 0;
    std::string errMsg;
    int32_t captureDuration = -1;
    bool userAgree = false;
    bool requireMic = false;
    bool enableMic = false;
    std::string videoResolution;
    CaptureEndReason stopReason = CaptureEndReason::STOP_REASON_INVALID;
    int32_t startLatency = -1;
};

struct ScDfxHeader {
    ScDfxIdentity identity;
    int8_t avType{-1};
    int8_t dataMode{0};
};

enum class ScFault : uint8_t {
    INVALID_FILE_FORMAT,
    INVALID_OUTPUT_FD,
    GET_FILE_STATUS_FLAGS_FAILED,
    OUTPUT_FD_NOT_WRITABLE,
    VIDEO_CAP_INVALID,
    INNER_OR_VIDEO_CAP_INVALID,
    INNER_OR_VIDEO_CAP_IGNORED,
    CAP_PARAMS_INVALID,
    MIC_CAP_INVALID,
    INNER_MIC_PARAM_MISMATCH,
    START_IN_CALL,
    GET_SCREEN_FAILED,
    NO_VALID_DISPLAY,
    ACQUIRE_AUDIO_SOURCE_UNSUPPORTED,
    RELEASE_AUDIO_SOURCE_UNSUPPORTED,
    EXCLUDE_CONTENT_FAILED,
};

class ICaptureDfx {
public:
    virtual ~ICaptureDfx() = default;
    virtual void BindAppInfo(int32_t uid, int32_t pid, const std::string &bundleName) = 0;
    virtual void BindConfig(const AVScreenCaptureConfig &config, uint32_t maxRefreshRate, bool hasRecorder) = 0;
    virtual int32_t Fault(ScFault fault, int32_t result) = 0;
    virtual void StartResult(int32_t result, CaptureEndReason reason) = 0;
    virtual void CaptureStarted() = 0;
    virtual void CaptureStopped() = 0;
    virtual void Finish(bool userAgree, bool micEnabled) = 0;
};

class ScreenCaptureDfx final : public ICaptureDfx {
public:
    explicit ScreenCaptureDfx(ScDfxIdentity identity);
    ~ScreenCaptureDfx() override = default;

    void BindAppInfo(int32_t uid, int32_t pid, const std::string &bundleName) override;
    void BindConfig(const AVScreenCaptureConfig &config, uint32_t maxRefreshRate, bool hasRecorder) override;
    int32_t Fault(ScFault fault, int32_t result) override;
    void StartResult(int32_t result, CaptureEndReason reason) override;
    void CaptureStarted() override;
    void CaptureStopped() override;
    void Finish(bool userAgree, bool micEnabled) override;

private:
    ScDfxHeader Snapshot() const;

    mutable std::mutex mutex_;
    ScDfxHeader header_;
    std::string mediaKitEvents_;
    StatisticalEventInfo statistic_;
    int64_t startTimeMs_{0};
    int64_t startedTimeMs_{-1};
    int64_t stoppedTimeMs_{-1};
    int32_t startRet_{0};
    CaptureEndReason startReason_{CaptureEndReason::NORMAL_STOPPED};
    bool finished_{false};
};

std::unique_ptr<ICaptureDfx> CreateScreenCaptureDfx(ScDfxIdentity identity);

} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_DFX_H
