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

#include "media_errors.h"
#include "scope_guard.h"
#include "media_log.h"
#include "avrecorder_callback_taihe.h"
#include "media_taihe_utils.h"
#ifdef SUPPORT_RECORDER_CREATE_FILE
#include "media_library_comm_ani.h"
#endif

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderCallback"};
}

using namespace OHOS::Media;

namespace ANI {
namespace Media {
#ifdef SUPPORT_RECORDER_CREATE_FILE
const int32_t CAMERA_SHOT_TYPE = 1; // CameraShotType VIDEO
#endif
AVRecorderCallback::AVRecorderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

AVRecorderCallback::~AVRecorderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void AVRecorderCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_ERROR);
    cb->callbackName = AVRecorderEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    OnTaiheErrorCallBack(cb);
}

void AVRecorderCallback::OnTaiheErrorCallBack(AVRecordTaiheCallback *taiheCb) const
{
    auto task = [event = taiheCb]() {
        std::string request = event->callbackName;
        do {
            MEDIA_LOGD("OnTaiheErrorCallBack is called");
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            auto func = ref->callbackRef_;
            CHECK_AND_BREAK_LOG(func != nullptr, "failed to get callback");
            auto err = MediaTaiheUtils::ToBusinessError(taihe::get_env(), 0, "OnErrorCallback is OK");
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            (*cacheCallback)(reinterpret_cast<uintptr_t>(err));
        } while (0);
        delete event;
    };
    bool ret = mainHandler_->PostTask(task, "OnError", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete taiheCb;
    }
}

void AVRecorderCallback::SendStateCallback(const std::string &state, const OHOS::Media::StateChangeReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_ = state;
    if (refMap_.find(AVRecorderEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find statechange callback!");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_STATE_CHANGE);
    cb->callbackName = AVRecorderEvent::EVENT_STATE_CHANGE;
    cb->reason = reason;
    cb->state = state;

    OnTaiheStateCallBack(cb);
}

void AVRecorderCallback::OnTaiheStateCallBack(AVRecordTaiheCallback *taiheCb) const
{
    auto task = [event = taiheCb]() {
        std::string request = event->callbackName;
        do {
            MEDIA_LOGD("OnTaiheStateCallBack is called");
            std::shared_ptr<AutoRef> stateChangeRef = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(stateChangeRef != nullptr, "%{public}s AutoRef is nullptr", request.c_str());
            std::shared_ptr<taihe::callback<StateChangeCallback>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<StateChangeCallback>>(stateChangeRef->callbackRef_);
            ohos::multimedia::media::StateChangeReason::key_t key;
            MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::media::StateChangeReason>(event->reason, key);
            (*cacheCallback)(taihe::string_view(event->state), ohos::multimedia::media::StateChangeReason(key));
        } while (0);
        delete event;
    };
    bool ret = mainHandler_->PostTask(task, "OnStatechange", 0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete taiheCb;
    }
}

#ifdef SUPPORT_RECORDER_CREATE_FILE
void AVRecorderCallback::OnTaihePhotoAssertAvailableCallback(AVRecordTaiheCallback *taiheCb) const
{
    auto task = [event = taiheCb]() {
        do {
            std::string request = event->callbackName;
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "ref is nullptr");
            auto func = ref->callbackRef_;
            std::shared_ptr<taihe::callback<void(uintptr_t)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(uintptr_t)>>(func);
            ani_object aniObject = MediaLibraryCommAni::CreatePhotoAssetAni(
                taihe::get_env(), event->uri, CAMERA_SHOT_TYPE);
            uintptr_t photoAssetPtr = reinterpret_cast<uintptr_t>(aniObject);
            (*cacheCallback)(photoAssetPtr);
        } while (0);
        delete event;
    };
    bool ret = mainHandler_->PostTask(task, "OnPhotoAssetAvailable",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete taiheCb;
    }
}
#endif

void AVRecorderCallback::OnTaiheAudioCaptureChangeCallback(AVRecordTaiheCallback *taiheCb) const
{
    MEDIA_LOGI("AVRecorderCallback OnTaiheAudioCaptureChangeCallback is start");
    auto task = [this, event = taiheCb]() {
        std::string request = event->callbackName;
        do {
            MEDIA_LOGD("OnTaiheAudioCaptureChangeCallback is called");
            std::shared_ptr<AutoRef> errorRef = event->autoRef.lock();
            CHECK_AND_RETURN_LOG(errorRef != nullptr, "ref is nullptr");
            auto func = errorRef->callbackRef_;

            std::shared_ptr<taihe::callback<void(
                ::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>> cacheCallback =
                std::reinterpret_pointer_cast<taihe::callback<void(
                    ::ohos::multimedia::audio::AudioCapturerChangeInfo const&)>>(func);
            (*cacheCallback)(this->GetAudioCapturerChangeInfo(event));
        } while (0);
        delete event;
    };
    bool ret = mainHandler_->PostTask(task, "OnAudioCapturerChange",
        0, OHOS::AppExecFwk::EventQueue::Priority::IMMEDIATE, {});
    if (!ret) {
        MEDIA_LOGE("Failed to PostTask!");
        delete taiheCb;
    }
}

void AVRecorderCallback::SendAudioCaptureChangeCallback(const OHOS::Media::AudioRecorderChangeInfo
    &audioRecorderChangeInfo)
{
    MEDIA_LOGI("AVRecorderCallback SendAudioCaptureChangeCallback is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find audioCaptureChange callback");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE);
    cb->callbackName = AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE;
    cb->audioRecorderChangeInfo = audioRecorderChangeInfo;
    OnTaiheAudioCaptureChangeCallback(cb);
}

void AVRecorderCallback::SendPhotoAssertAvailableCallback(const std::string &uri)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE) == refMap_.end()) {
        MEDIA_LOGW("can not find PhotoAssertAvailable callback");
        return;
    }

    AVRecordTaiheCallback *cb = new(std::nothrow) AVRecordTaiheCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE);
    cb->callbackName = AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE;
    cb->uri = uri;
#ifdef SUPPORT_RECORDER_CREATE_FILE
    OnTaihePhotoAssertAvailableCallback(cb);
#endif
}

void AVRecorderCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
    if (mainHandler_ == nullptr) {
        std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner = OHOS::AppExecFwk::EventRunner::GetMainEventRunner();
        mainHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
}

void AVRecorderCallback::CancelCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto iter = refMap_.find(name);
    if (iter != refMap_.end()) {
        refMap_.erase(iter);
    }
    MEDIA_LOGI("Cancel callback type: %{public}s", name.c_str());
}

void AVRecorderCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
    MEDIA_LOGI("ClearCallback!");
}

std::string AVRecorderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void AVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
    SendStateCallback(AVRecorderState::STATE_ERROR, OHOS::Media::StateChangeReason::BACKGROUND);
    if (errCode == MSERR_DATA_SOURCE_IO_ERROR) {
        SendErrorCallback(MSERR_EXT_API9_TIMEOUT,
            "The video input stream timed out. Please confirm that the input stream is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_OBTAIN_MEM_ERROR) {
        SendErrorCallback(MSERR_EXT_API9_TIMEOUT,
            "Read data from audio timeout, please confirm whether the audio module is normal.");
    } else if (errCode == MSERR_DATA_SOURCE_ERROR_UNKNOWN) {
        SendErrorCallback(MSERR_EXT_API9_IO, "Video input data is abnormal."
            " Please confirm that the pts, width, height, size and other data are normal.");
    } else if (errCode == MSERR_AUD_INTERRUPT) {
        SendErrorCallback(MSERR_EXT_API9_AUDIO_INTERRUPTED,
            "Record failed by audio interrupt.");
    } else {
        SendErrorCallback(MSERR_EXT_API9_IO, "IO error happened.");
    }
}

void AVRecorderCallback::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGI("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
    if (type == RecorderInfoType::RECORDER_INFO_MAX_DURATION_REACHED) {
        MEDIA_LOGI("OnInfo() type = MAX_DURATION_REACHED, type: %{public}d, extra: %{public}d", type, extra);
        SendStateCallback(AVRecorderState::STATE_STOPPED, OHOS::Media::StateChangeReason::BACKGROUND);
    }
}

void AVRecorderCallback::OnAudioCaptureChange(const OHOS::Media::AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    MEDIA_LOGI("OnAudioCaptureChange() is called");
    MEDIA_LOGI("AVRecorderCallback OnAudioCaptureChange is start");
    SendAudioCaptureChangeCallback(audioRecorderChangeInfo);
}

void AVRecorderCallback::OnPhotoAssertAvailable(const std::string &uri)
{
    MEDIA_LOGI("OnPhotoAssertAvailable() is called");
    SendPhotoAssertAvailableCallback(uri);
}

::ohos::multimedia::audio::AudioCapturerChangeInfo AVRecorderCallback::GetAudioCapturerChangeInfo(
    AVRecordTaiheCallback *taiheCb) const
{
    ohos::multimedia::audio::AudioState::key_t audioStateKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioState>(
        taiheCb->audioRecorderChangeInfo.capturerState, audioStateKey);
    ohos::multimedia::audio::SourceType::key_t sourceTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::SourceType>(
        taiheCb->audioRecorderChangeInfo.capturerInfo.sourceType, sourceTypeKey);

    ::ohos::multimedia::audio::AudioCapturerInfo audioCapturerInfo {
        std::move(::ohos::multimedia::audio::SourceType(sourceTypeKey)),
        taiheCb->audioRecorderChangeInfo.capturerInfo.capturerFlags
    };

    std::vector<::ohos::multimedia::audio::AudioDeviceDescriptor> audioDeviceDescriptor;
    audioDeviceDescriptor.push_back(GetDeviceInfo(taiheCb));
    ::ohos::multimedia::audio::AudioCapturerChangeInfo audioCapturerChangeInfo {
        std::move(taiheCb->audioRecorderChangeInfo.sessionId), std::move(taiheCb->audioRecorderChangeInfo.clientUID),
        std::move(audioCapturerInfo),
        std::move(::ohos::multimedia::audio::AudioState(audioStateKey)),
        array<::ohos::multimedia::audio::AudioDeviceDescriptor>(audioDeviceDescriptor),
        optional<bool>(std::in_place_t{}, taiheCb->audioRecorderChangeInfo.muted)
    };
    return audioCapturerChangeInfo;
}

::ohos::multimedia::audio::AudioDeviceDescriptor AVRecorderCallback::GetDeviceInfo(
    AVRecordTaiheCallback *taiheCb) const
{
    ohos::multimedia::audio::DeviceRole::key_t deviceRoleKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceRole>(
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.deviceRole, deviceRoleKey);
    ohos::multimedia::audio::DeviceType::key_t deviceTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::DeviceType>(
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.deviceType, deviceTypeKey);
    taihe::string name = MediaTaiheUtils::ToTaiheString(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.deviceName);
    taihe::string address =
        MediaTaiheUtils::ToTaiheString(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.macAddress);
    std::vector<int32_t> samplingRateVec(
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.samplingRate.begin(),
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.samplingRate.end());
    std::vector<int32_t> channelsVec(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.channels.begin(),
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.channels.end());
    taihe::string networkId =
        MediaTaiheUtils::ToTaiheString(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.networkId);
    taihe::string displayName = MediaTaiheUtils::ToTaiheString(
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.displayName);
    ohos::multimedia::audio::AudioEncodingType::key_t audioEncodingTypeKey;
    MediaTaiheUtils::GetEnumKeyByValue<ohos::multimedia::audio::AudioEncodingType>(
        taiheCb->audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.encoding, audioEncodingTypeKey);
    std::vector<int32_t> channelMasks;
    channelMasks.push_back(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.channelMasks);
    std::vector<::ohos::multimedia::audio::AudioEncodingType> audioEncodingType;
    audioEncodingType.push_back(audioEncodingTypeKey);

    ::ohos::multimedia::audio::AudioDeviceDescriptor descriptor {
        std::move(::ohos::multimedia::audio::DeviceRole(deviceRoleKey)),
        std::move(::ohos::multimedia::audio::DeviceType(deviceTypeKey)),
        std::move(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.deviceId),
        std::move(name),
        std::move(address),
        array<int32_t>(samplingRateVec),
        array<int32_t>(channelsVec),
        array<int32_t>(channelMasks),
        std::move(networkId),
        std::move(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.interruptGroupId),
        std::move(taiheCb->audioRecorderChangeInfo.inputDeviceInfo.volumeGroupId),
        std::move(displayName),
        optional<::taihe::array<::ohos::multimedia::audio::AudioEncodingType>>(
            std::in_place_t{}, array<::ohos::multimedia::audio::AudioEncodingType>(audioEncodingType)),
        optional<bool>(std::nullopt),
        optional<int32_t>(std::nullopt),
    };
    return descriptor;
}
}
}