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

#ifndef CJ_AVRECORDER_CALLBACK_H
#define CJ_AVRECORDER_CALLBACK_H

#include "cj_avrecorder.h"
#include "avrecorder_common.h"

namespace OHOS {
namespace Media {
void InitDeviceRates(CDeviceDescriptor* device, const DeviceInfo& deviceInfo);
void InitDeviceChannels(CDeviceDescriptor* device, const DeviceInfo& deviceInfo);
void ConvertToCDeviceInfo(CDeviceDescriptor* device, const DeviceInfo& deviceInfo);
void ConvertToCArrDeviceDescriptor(CArrDeviceDescriptor& devices, const DeviceInfo& deviceInfo);
void ConvertToCAudioCapturerChangeInfo(CAudioCapturerChangeInfo& cInfo, const AudioRecorderChangeInfo& changeInfo);
void ConvertToCEncoderInfo(CEncoderInfo& cInfo, EncoderCapabilityData& encoderInfo);
void ConvertToCArrEncoderInfo(CArrEncoderInfo& cInfo, std::vector<EncoderCapabilityData>& encoderInfo);

namespace CJAVRecorderEvent {
const int32_t EVENT_STATE_CHANGE = 1;
const int32_t EVENT_ERROR = 2;
const int32_t EVENT_AUDIO_CAPTURE_CHANGE = 3;
const int32_t EVENT_PHOTO_ASSET_AVAILABLE = 4;
}

class CJAVRecorderCallback : public RecorderCallback {
public:
    CJAVRecorderCallback() = default;
    virtual ~CJAVRecorderCallback() = default;

    void Register(const int32_t type, int64_t id);
    void UnRegister(const int32_t type);
    std::string GetState();
    void ExecuteStateCallback(CStateChangeHandler &handler);

protected:
    void OnError(RecorderErrorType errorType, int32_t errCode) override;
    void OnInfo(int32_t type, int32_t extra) override;
    void OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo) override;
    void OnPhotoAssertAvailable(const std::string &uri) override;

private:
    std::function<void(CErrorInfo)> onError = nullptr;
    std::function<void(CAudioCapturerChangeInfo)> onAudioCapturerChange = nullptr;
    std::function<void(CStateChangeHandler)> onStateChange = nullptr;
    std::function<void(int64_t)> onPhotoAssertAvailable = nullptr;

    void InitError(int64_t id);
    void InitStateChange(int64_t id);
    void InitAudioRecorderChange(int64_t id);
    void InitPhotoAssertAvailable(int64_t id);

    std::mutex mutex_;
    std::string currentState_ = CjAVRecorderState::STATE_IDLE;
};
} // namespace Media
} // namespace OHOS
#endif // AVRECORDER_CALLBACK_H