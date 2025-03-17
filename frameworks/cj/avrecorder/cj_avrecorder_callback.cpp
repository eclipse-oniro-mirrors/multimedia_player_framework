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

#include "cj_avrecorder_callback.h"
#include "cj_lambda.h"
#include "media_log.h"
#ifdef SUPPORT_RECORDER_CREATE_FILE
#include "photo_asset_helper.h"
#endif

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "CJAVRecorderCallback"};
}

namespace OHOS {
namespace Media {

#ifdef SUPPORT_RECORDER_CREATE_FILE
const int32_t CAMERA_SHOT_TYPE = 1; // CameraShotType VIDEO
#endif

std::string CJAVRecorderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void CJAVRecorderCallback::Register(const int32_t type, int64_t id)
{
    std::lock_guard<std::mutex> lock(mutex_);
    switch (type) {
        case CJAVRecorderEvent::EVENT_STATE_CHANGE:
            InitStateChange(id);
            break;
        case CJAVRecorderEvent::EVENT_ERROR:
            InitError(id);
            break;
        case CJAVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE:
            InitAudioRecorderChange(id);
            break;
        case CJAVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE:
            InitPhotoAssertAvailable(id);
            break;
        default:
            MEDIA_LOGE("invalid type");
            return;
    }
}

void CJAVRecorderCallback::UnRegister(const int32_t type)
{
    std::lock_guard<std::mutex> lock(mutex_);
    switch (type) {
        case CJAVRecorderEvent::EVENT_STATE_CHANGE:
            onStateChange = nullptr;
            break;
        case CJAVRecorderEvent::EVENT_ERROR:
            onError = nullptr;
            break;
        case CJAVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE:
            onAudioCapturerChange = nullptr;
            break;
        case CJAVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE:
            onPhotoAssertAvailable = nullptr;
            break;
        default:
            MEDIA_LOGE("invalid type");
            return;
    }
}

void CJAVRecorderCallback::ExecuteStateCallback(CStateChangeHandler &handler)
{
    currentState_ = handler.state;
    if (!onStateChange) {
        MEDIA_LOGE("onStateChange is null");
        return;
    }
    onStateChange(handler);
    free(handler.state);
    handler.state = nullptr;
}

void CJAVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
    if (!onError) {
        MEDIA_LOGE("onError is null");
        return;
    }
    CErrorInfo errorInfo {};
    if (errCode == MSERR_DATA_SOURCE_IO_ERROR) {
        errorInfo.code = MSERR_EXT_API9_TIMEOUT;
        errorInfo.msg = MallocCString(
            "The video input stream timed out. Please confirm that the input stream is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_OBTAIN_MEM_ERROR) {
        errorInfo.code = MSERR_EXT_API9_TIMEOUT;
        errorInfo.msg = MallocCString(
            "Read data from audio timeout, please confirm whether the audio module is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_ERROR_UNKNOWN) {
        errorInfo.code = MSERR_EXT_API9_IO;
        errorInfo.msg = MallocCString(
            "Please confirm that the pts, width, height, size and other data are normal.");
    } else if (errCode == MSERR_AUD_INTERRUPT) {
        errorInfo.code = MSERR_EXT_API9_AUDIO_INTERRUPTED;
        errorInfo.msg = MallocCString("Record failed by audio interrupt.");
    } else {
        errorInfo.code = MSERR_EXT_API9_IO;
        errorInfo.msg = MallocCString("IO error happened.");
    }
    onError(errorInfo);
    free(errorInfo.msg);
    errorInfo.msg = nullptr;
    CStateChangeHandler handler {};
    handler.state = MallocCString(CjAVRecorderState::STATE_ERROR);
    handler.reason = static_cast<int32_t>(StateChangeReason::BACKGROUND);
    ExecuteStateCallback(handler);
}

void CJAVRecorderCallback::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGI("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
    if (type == RecorderInfoType::RECORDER_INFO_MAX_DURATION_REACHED) {
        MEDIA_LOGI("OnInfo() type = MAX_DURATION_REACHED, type: %{public}d, extra: %{public}d", type, extra);
        CStateChangeHandler handler {};
        handler.state = MallocCString(CjAVRecorderState::STATE_STOPPED);
        handler.reason = static_cast<int32_t>(StateChangeReason::BACKGROUND);
        ExecuteStateCallback(handler);
    }
}

void CJAVRecorderCallback::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    if (!onAudioCapturerChange) {
        MEDIA_LOGE("onAudioCapturerChange is null");
        return;
    }
    CAudioCapturerChangeInfo cInfo {};
    if (!ConvertToCAudioCapturerChangeInfo(cInfo, audioRecorderChangeInfo)) {
        FreeCArrDeviceDescriptor(cInfo.deviceDescriptors);
        return;
    }
    onAudioCapturerChange(cInfo);
    FreeCArrDeviceDescriptor(cInfo.deviceDescriptors);
}

void CJAVRecorderCallback::OnPhotoAssertAvailable(const std::string &uri)
{
    if (!onPhotoAssertAvailable) {
        MEDIA_LOGE("onPhotoAssertAvailable is null");
        return;
    }

    if (uri.empty()) {
        MEDIA_LOGE("uri is empty");
        return;
    }
#ifdef SUPPORT_RECORDER_CREATE_FILE
    auto id = CreatePhotoAssetImpl(uri, CAMERA_SHOT_TYPE);
    onPhotoAssertAvailable(id);
#endif
}

void CJAVRecorderCallback::InitError(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(CErrorInfo)>(id);
    onError = [lambda = CJLambda::Create(callback)](CErrorInfo value) -> void {
        lambda(value);
    };
}

void CJAVRecorderCallback::InitStateChange(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(CStateChangeHandler)>(id);
    onStateChange = [lambda = CJLambda::Create(callback)](CStateChangeHandler value) -> void {
        lambda(value);
    };
}

void CJAVRecorderCallback::InitAudioRecorderChange(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(CAudioCapturerChangeInfo)>(id);
    onAudioCapturerChange = [lambda = CJLambda::Create(callback)](CAudioCapturerChangeInfo value) -> void {
        lambda(value);
    };
}

void CJAVRecorderCallback::InitPhotoAssertAvailable(int64_t id)
{
    auto callback = reinterpret_cast<void(*)(const int64_t)>(id);
    onPhotoAssertAvailable = [lambda = CJLambda::Create(callback)](int64_t value) -> void {
        lambda(value);
    };
}

bool InitDeviceRates(CDeviceDescriptor* device, const DeviceInfo& deviceInfo)
{
    int32_t rateSize = static_cast<int32_t>(deviceInfo.audioStreamInfo.samplingRate.size());
    if (rateSize <= 0) {
        MEDIA_LOGE("rateSize is illeagle");
        return false;
    }

    int32_t mallocSize = static_cast<int32_t>(sizeof(int32_t) * rateSize);

    auto rates = static_cast<int32_t*>(malloc(mallocSize));
    if (!rates) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(rates, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(rates);
        return false;
    }

    device->sampleRates.size = static_cast<int64_t>(rateSize);
    device->sampleRates.head = rates;

    int32_t iter = 0;
    for (auto rate: deviceInfo.audioStreamInfo.samplingRate) {
        rates[iter] = rate;
        iter++;
    }
    return true;
}

bool InitDeviceChannels(CDeviceDescriptor* device, const DeviceInfo& deviceInfo)
{
    int32_t channelSize = static_cast<int32_t>(deviceInfo.audioStreamInfo.channels.size());
    if (channelSize <= 0) {
        MEDIA_LOGE("channelSize is illeagle");
        return false;
    }

    int32_t mallocSize = static_cast<int32_t>(sizeof(int32_t) * channelSize);

    auto channels = static_cast<int32_t*>(malloc(mallocSize));
    if (!channels) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(channels, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(channels);
        return false;
    }

    device->channelCounts.size = static_cast<int64_t>(channelSize);
    device->channelCounts.head = channels;

    int32_t iter = 0;
    for (auto channel: deviceInfo.audioStreamInfo.channels) {
        channels[iter] = channel;
        iter++;
    }
    return true;
}

bool InitDeviceMasks(CDeviceDescriptor* device, const DeviceInfo& deviceInfo)
{
    int32_t deviceSize = 1;
    int32_t mallocSize = static_cast<int32_t>(sizeof(int32_t) * deviceSize);
    if (mallocSize <= 0) {
        MEDIA_LOGE("Masks size is illeagle");
        return false;
    }

    auto masks = static_cast<int32_t*>(malloc(mallocSize));
    if (!masks) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(masks, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(masks);
        return false;
    }

    device->channelMasks.size = deviceSize;
    device->channelMasks.head = masks;
    masks[0] = deviceInfo.channelMasks;
    return true;
}

bool InitDeviceEncodingTypes(CDeviceDescriptor* device, const DeviceInfo& deviceInfo)
{
    int32_t deviceSize = 1;
    int32_t mallocSize = static_cast<int32_t>(sizeof(int32_t) * deviceSize);
    if (mallocSize <= 0) {
        MEDIA_LOGE("EncodingTypes size is illeagle");
        return false;
    }

    auto encodings = static_cast<int32_t*>(malloc(mallocSize));
    if (!encodings) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(encodings, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(encodings);
        return false;
    }

    device->encodingTypes.hasValue = true;
    device->encodingTypes.arr.size = deviceSize;
    device->encodingTypes.arr.head = encodings;
    encodings[0] = deviceInfo.audioStreamInfo.encoding;
    return true;
}

bool ConvertToCDeviceInfo(CDeviceDescriptor* device, const DeviceInfo& deviceInfo)
{
    device->deviceRole = deviceInfo.deviceRole;
    device->deviceType = deviceInfo.deviceType;
    device->id = deviceInfo.deviceId;
    device->displayName = MallocCString(deviceInfo.displayName);
    device->address = MallocCString(deviceInfo.macAddress);
    device->name = MallocCString(deviceInfo.deviceName);

    if (!InitDeviceRates(device, deviceInfo)) {
        return false;
    }

    if (!InitDeviceChannels(device, deviceInfo)) {
        return false;
    }
    
    if (!InitDeviceMasks(device, deviceInfo)) {
        return false;
    }

    if (!InitDeviceEncodingTypes(device, deviceInfo)) {
        return false;
    }

    return true;
}

bool ConvertToCArrDeviceDescriptor(CArrDeviceDescriptor& devices, const DeviceInfo& deviceInfo)
{
    int32_t deviceSize = 1;
    int32_t mallocSize = static_cast<int32_t>(sizeof(CDeviceDescriptor) * deviceSize);

    CDeviceDescriptor* device = static_cast<CDeviceDescriptor*>(malloc(mallocSize));
    if (!device) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(device, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(device);
        return false;
    }

    devices.head = device;
    devices.size = static_cast<int64_t>(deviceSize);

    return ConvertToCDeviceInfo(&(device[0]), deviceInfo);
}

bool ConvertToCAudioCapturerChangeInfo(CAudioCapturerChangeInfo& cInfo, const AudioRecorderChangeInfo& changeInfo)
{
    cInfo.muted = changeInfo.muted;
    cInfo.streamId = changeInfo.sessionId;
    cInfo.audioCapturerInfo.capturerFlags = changeInfo.capturerInfo.capturerFlags;
    cInfo.audioCapturerInfo.source = changeInfo.capturerInfo.sourceType;
    return ConvertToCArrDeviceDescriptor(cInfo.deviceDescriptors, changeInfo.inputDeviceInfo);
}

bool ConvertToCEncoderInfo(CEncoderInfo* cInfo, EncoderCapabilityData& encoderInfo)
{
    cInfo->mimeType = MallocCString(encoderInfo.mimeType);
    cInfo->type = MallocCString(encoderInfo.type);
    cInfo->bitRate.minVal = encoderInfo.bitrate.minVal;
    cInfo->bitRate.maxVal = encoderInfo.bitrate.maxVal;
    cInfo->frameRate.minVal = encoderInfo.frameRate.minVal;
    cInfo->frameRate.maxVal = encoderInfo.frameRate.maxVal;
    cInfo->width.minVal = encoderInfo.width.minVal;
    cInfo->width.maxVal = encoderInfo.width.maxVal;
    cInfo->height.minVal = encoderInfo.height.minVal;
    cInfo->height.maxVal = encoderInfo.height.maxVal;
    cInfo->channels.minVal = encoderInfo.channels.minVal;
    cInfo->channels.maxVal = encoderInfo.channels.maxVal;

    int32_t rateSize = static_cast<int32_t>(encoderInfo.sampleRate.size());
    if (rateSize <= 0) {
        MEDIA_LOGE("rateSize is illeagle");
        return false;
    }

    int32_t mallocSize = static_cast<int32_t>(sizeof(int32_t) * rateSize);

    auto rates = static_cast<int32_t*>(malloc(mallocSize));
    if (!rates) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(rates, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(rates);
        return false;
    }

    cInfo->sampleRates.size = static_cast<int64_t>(rateSize);
    cInfo->sampleRates.head = rates;

    int32_t iter = 0;
    for (auto rate: encoderInfo.sampleRate) {
        rates[iter] = rate;
        iter++;
    }
    return true;
}

bool ConvertToCArrEncoderInfo(CArrEncoderInfo& cInfo, std::vector<EncoderCapabilityData>& encoderInfo)
{
    int32_t encoderSize = static_cast<int32_t>(encoderInfo.size());
    if (encoderSize <= 0) {
        MEDIA_LOGE("encoderSize is illeagle");
        return false;
    }

    int32_t mallocSize = static_cast<int32_t>(sizeof(CEncoderInfo) * encoderSize);

    CEncoderInfo* encoders = static_cast<CEncoderInfo*>(malloc(mallocSize));
    if (!encoders) {
        MEDIA_LOGE("malloc is failed");
        return false;
    }

    if (memset_s(encoders, mallocSize, 0, mallocSize) != EOK) {
        MEDIA_LOGE("initial memory space failed");
        free(encoders);
        return false;
    }
    cInfo.head = encoders;
    cInfo.size = static_cast<int64_t>(encoderSize);

    for (int32_t i = 0; i < encoderSize; i++) {
        if (!ConvertToCEncoderInfo(&(encoders[i]), encoderInfo[i])) {
            return false;
        }
    }
    return true;
}

void FreeDescriptor(CDeviceDescriptor& device)
{
    free(device.address);
    device.address = nullptr;
    free(device.displayName);
    device.displayName = nullptr;
    free(device.name);
    device.name = nullptr;
    free(device.channelMasks.head);
    device.channelMasks.head = nullptr;
    device.channelMasks.size = 0;
    free(device.channelCounts.head);
    device.channelCounts.head = nullptr;
    device.channelCounts.size = 0;
    free(device.sampleRates.head);
    device.sampleRates.head = nullptr;
    device.sampleRates.size = 0;
    if (device.encodingTypes.hasValue) {
        free(device.encodingTypes.arr.head);
        device.encodingTypes.hasValue = false;
        device.encodingTypes.arr.head = nullptr;
        device.encodingTypes.arr.size = 0;
    }
}
void FreeCArrDeviceDescriptor(CArrDeviceDescriptor& devices)
{
    if (!devices.head) {
        return;
    }
    for (int64_t i = 0; i < devices.size; i++) {
        FreeDescriptor((devices.head)[i]);
    }
    free(devices.head);
    devices.head = nullptr;
    devices.size = 0;
}

void FreeEncoderInfo(CEncoderInfo& info)
{
    free(info.mimeType);
    info.mimeType = nullptr;
    free(info.type);
    info.type = nullptr;
    free(info.sampleRates.head);
    info.sampleRates.head = nullptr;
    info.sampleRates.size = 0;
}
void FreeCArrEncoderInfo(CArrEncoderInfo& cInfo)
{
    if (!cInfo.head) {
        return;
    }
    for (int64_t i = 0; i < cInfo.size; i++) {
        FreeEncoderInfo((cInfo.head)[i]);
    }
    free(cInfo.head);
    cInfo.head = nullptr;
    cInfo.size = 0;
}
} // namespace Media
} // namespace OHOS