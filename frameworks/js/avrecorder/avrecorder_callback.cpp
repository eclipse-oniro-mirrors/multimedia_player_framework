/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "avrecorder_callback.h"
#include <uv.h>
#include "media_errors.h"
#include "scope_guard.h"
#include "media_log.h"
#ifdef SUPPORT_RECORDER_CREATE_FILE
#include "media_library_comm_napi.h"
#endif

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "AVRecorderCallback"};
}

namespace OHOS {
namespace Media {
#ifdef SUPPORT_RECORDER_CREATE_FILE
const int32_t CAMERA_SHOT_TYPE = 1; // CameraShotType VIDEO
#endif
AVRecorderCallback::AVRecorderCallback(napi_env env) : env_(env)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
}

AVRecorderCallback::~AVRecorderCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

void AVRecorderCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
    MEDIA_LOGI("Set callback type: %{public}s", name.c_str());
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

void AVRecorderCallback::SendErrorCallback(int32_t errCode, const std::string &msg)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("can not find error callback!");
        return;
    }

    AVRecordJsCallback *cb = new(std::nothrow) AVRecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_ERROR);
    cb->callbackName = AVRecorderEvent::EVENT_ERROR;
    cb->errorCode = errCode;
    cb->errorMsg = msg;
    return OnJsErrorCallBack(cb);
}

void AVRecorderCallback::SendStateCallback(const std::string &state, const StateChangeReason &reason)
{
    std::lock_guard<std::mutex> lock(mutex_);
    currentState_ = state;
    if (refMap_.find(AVRecorderEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find statechange callback!");
        return;
    }

    AVRecordJsCallback *cb = new(std::nothrow) AVRecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_STATE_CHANGE);
    cb->callbackName = AVRecorderEvent::EVENT_STATE_CHANGE;
    cb->reason = reason;
    cb->state = state;
    return OnJsStateCallBack(cb);
}

void AVRecorderCallback::SendAudioCaptureChangeCallback(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    MEDIA_LOGI("AVRecorderCallback SendAudioCaptureChangeCallback is start");
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find audioCaptureChange callback");
        return;
    }

    AVRecordJsCallback *cb = new(std::nothrow) AVRecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE);
    cb->callbackName = AVRecorderEvent::EVENT_AUDIO_CAPTURE_CHANGE;
    cb->audioRecorderChangeInfo = audioRecorderChangeInfo;
    return OnJsAudioCaptureChangeCallback(cb);
}

void AVRecorderCallback::SendPhotoAssertAvailableCallback(const std::string &uri)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE) == refMap_.end()) {
        MEDIA_LOGW("can not find PhotoAssertAvailable callback");
        return;
    }

    AVRecordJsCallback *cb = new(std::nothrow) AVRecordJsCallback();
    CHECK_AND_RETURN_LOG(cb != nullptr, "cb is nullptr");
    cb->autoRef = refMap_.at(AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE);
    cb->callbackName = AVRecorderEvent::EVENT_PHOTO_ASSET_AVAILABLE;
    cb->uri = uri;
#ifdef SUPPORT_RECORDER_CREATE_FILE
    return OnJsPhotoAssertAvailableCallback(cb);
#endif
}

std::string AVRecorderCallback::GetState()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return currentState_;
}

void AVRecorderCallback::OnError(RecorderErrorType errorType, int32_t errCode)
{
    MEDIA_LOGI("OnError is called, name: %{public}d, error message: %{public}d", errorType, errCode);
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
    SendStateCallback(AVRecorderState::STATE_ERROR, StateChangeReason::BACKGROUND);
}

void AVRecorderCallback::OnInfo(int32_t type, int32_t extra)
{
    MEDIA_LOGI("OnInfo() is called, type: %{public}d, extra: %{public}d", type, extra);
    if (type == RecorderInfoType::RECORDER_INFO_MAX_DURATION_REACHED) {
        MEDIA_LOGI("OnInfo() type = MAX_DURATION_REACHED, type: %{public}d, extra: %{public}d", type, extra);
        SendStateCallback(AVRecorderState::STATE_STOPPED, StateChangeReason::BACKGROUND);
    }
}

void AVRecorderCallback::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
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

void AVRecorderCallback::OnJsStateCallBack(AVRecordJsCallback *jsCb) const
{
    ON_SCOPE_EXIT(0) {
        delete jsCb;
    };

    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) { napi_close_handle_scope(ref->env_, scope); };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            napi_value args[2] = { nullptr };
            nstatus = napi_create_string_utf8(ref->env_, event->state.c_str(), NAPI_AUTO_LENGTH, &args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr,
                "%{public}s failed to create callback", request.c_str());

            nstatus = napi_create_int32(ref->env_, event->reason, &args[1]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[1] != nullptr,
                "%{public}s failed to create callback", request.c_str());

            const size_t argCount = 2;
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate);
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");

    CANCEL_SCOPE_EXIT_GUARD(0);
}

#ifdef SUPPORT_RECORDER_CREATE_FILE
void AVRecorderCallback::OnJsPhotoAssertAvailableCallback(AVRecordJsCallback *jsCb) const
{
    ON_SCOPE_EXIT(0) {
        delete jsCb;
    };

    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            const size_t argCount = 1;
            napi_value args[argCount] = { nullptr };

            args[0] = Media::MediaLibraryCommNapi::CreatePhotoAssetNapi(ref->env_, event->uri, CAMERA_SHOT_TYPE);
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate);
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");

    CANCEL_SCOPE_EXIT_GUARD(0);
}
#endif

void AVRecorderCallback::OnJsAudioCaptureChangeCallback(AVRecordJsCallback *jsCb) const
{
    MEDIA_LOGI("AVRecorderCallback OnJsAudioCaptureChangeCallback is start");
    ON_SCOPE_EXIT(0) {
        delete jsCb;
    };

    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) { napi_close_handle_scope(ref->env_, scope); };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            const size_t argCount = 1;
            napi_value args[argCount] = { nullptr };
            std::shared_ptr<AudioCaptureChangeInfoJsCallback> ChangeInfoJsCallback =
                std::make_shared<AudioCaptureChangeInfoJsCallback>(event->audioRecorderChangeInfo);
            nstatus = ChangeInfoJsCallback->GetJsResult(ref->env_, args[0]);
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate);
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");

    CANCEL_SCOPE_EXIT_GUARD(0);
}

void AVRecorderCallback::OnJsErrorCallBack(AVRecordJsCallback *jsCb) const
{
    ON_SCOPE_EXIT(0) {
        delete jsCb;
    };

    auto task = [event = jsCb]() {
        std::string request = event->callbackName;
        do {
            std::shared_ptr<AutoRef> ref = event->autoRef.lock();
            CHECK_AND_BREAK_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", request.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_BREAK_LOG(scope != nullptr, "%{public}s scope is nullptr", request.c_str());
            ON_SCOPE_EXIT(0) { napi_close_handle_scope(ref->env_, scope); };

            napi_value jsCallback = nullptr;
            napi_status nstatus = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && jsCallback != nullptr, "%{public}s get reference value failed",
                request.c_str());

            napi_value msgValStr = nullptr;
            nstatus = napi_create_string_utf8(ref->env_, event->errorMsg.c_str(), NAPI_AUTO_LENGTH, &msgValStr);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && msgValStr != nullptr, "create error message str failed");

            napi_value args[1] = { nullptr };
            nstatus = napi_create_error(ref->env_, nullptr, msgValStr, &args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok && args[0] != nullptr, "create error callback failed");

            nstatus = CommonNapi::FillErrorArgs(ref->env_, event->errorCode, args[0]);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "create error callback failed");

            // Call back function
            napi_value result = nullptr;
            nstatus = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_BREAK_LOG(nstatus == napi_ok, "%{public}s failed to napi call function", request.c_str());
        } while (0);
        delete event;
    };
    auto ret = napi_send_event(env_, task, napi_eprio_immediate);
    CHECK_AND_RETURN_LOG(ret == napi_status::napi_ok, "failed to napi_send_event task");

    CANCEL_SCOPE_EXIT_GUARD(0);
}

napi_status AudioCaptureChangeInfoJsCallback::GetJsResult(napi_env env, napi_value &result)
{
    napi_status ret = napi_ok;
    bool setRet = true;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &result)) == napi_ok, ret);

    setRet = CommonNapi::SetPropertyInt32(env, result, "streamId", value_.sessionId);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "clientUid", value_.clientUID);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, result, "capturerState", value_.capturerState);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyBool(env, result, "muted", value_.muted);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);

    napi_value captureInfo;
    napi_value deviceDescriptors;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &captureInfo)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = napi_create_array_with_length(env, 1, &deviceDescriptors)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = SetAudioCapturerInfo(env, captureInfo, result)) == napi_ok, ret);
    CHECK_AND_RETURN_RET((ret = SetDeviceInfo(env, deviceDescriptors, result)) == napi_ok, ret);
    return ret;
}

napi_status AudioCaptureChangeInfoJsCallback::SetAudioCapturerInfo(napi_env env,
    napi_value &captureInfo, napi_value &result)
{
    bool setRet = true;
    setRet = CommonNapi::SetPropertyInt32(env, captureInfo, "source",
        static_cast<int32_t>(value_.capturerInfo.sourceType));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, captureInfo, "capturerFlags", value_.capturerInfo.capturerFlags);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, result, "capturerInfo", captureInfo);
    return napi_ok;
}

napi_status AudioCaptureChangeInfoJsCallback::SetDeviceProperty(napi_env env, napi_value &element)
{
    bool setRet = true;
    setRet = CommonNapi::SetPropertyInt32(env, element, "deviceRole",
        static_cast<int32_t>(value_.inputDeviceInfo.deviceRole));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, element, "deviceType",
        static_cast<int32_t>(value_.inputDeviceInfo.deviceType));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, element, "id", value_.inputDeviceInfo.deviceId);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, element, "name", value_.inputDeviceInfo.deviceName);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, element, "address", value_.inputDeviceInfo.macAddress);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, element, "networkId", value_.inputDeviceInfo.networkId);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyString(env, element, "displayName", value_.inputDeviceInfo.displayName);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, element, "interruptGroupId",
        value_.inputDeviceInfo.interruptGroupId);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    setRet = CommonNapi::SetPropertyInt32(env, element, "volumeGroupId",
        value_.inputDeviceInfo.volumeGroupId);
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    return napi_ok;
}

napi_status AudioCaptureChangeInfoJsCallback::SetDeviceInfo(napi_env env,
    napi_value &deviceDescriptors, napi_value &result)
{
    napi_value element;
    napi_status ret = napi_ok;
    CHECK_AND_RETURN_RET((ret = napi_create_object(env, &element)) == napi_ok, ret);
    CHECK_AND_RETURN_RET(SetDeviceProperty(env, element) == napi_ok, napi_generic_failure);

    bool setRet = true;
    napi_value sampleRates;
    setRet = CommonNapi::AddArrayInt(env, sampleRates,
        std::vector<int32_t>(value_.inputDeviceInfo.audioStreamInfo.samplingRate.begin(),
        value_.inputDeviceInfo.audioStreamInfo.samplingRate.end()));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, element, "sampleRates", sampleRates);

    napi_value channelCounts;
    setRet = CommonNapi::AddArrayInt(env, channelCounts,
        std::vector<int32_t>(value_.inputDeviceInfo.audioStreamInfo.channels.begin(),
        value_.inputDeviceInfo.audioStreamInfo.channels.end()));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, element, "channelCounts", channelCounts);

    napi_value channelMasks;
    setRet = CommonNapi::AddArrayInt(env, channelMasks, std::vector<int32_t>({value_.inputDeviceInfo.channelMasks}));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, element, "channelMasks", channelMasks);

    napi_value channelIndexMasks;
    setRet = CommonNapi::AddArrayInt(env, channelIndexMasks,
        std::vector<int32_t>({value_.inputDeviceInfo.channelIndexMasks}));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, element, "channelIndexMasks", channelIndexMasks);

    napi_value encodingTypes;
    setRet = CommonNapi::AddArrayInt(env, encodingTypes,
        std::vector<int32_t>({value_.inputDeviceInfo.audioStreamInfo.encoding}));
    CHECK_AND_RETURN_RET(setRet == true, napi_generic_failure);
    napi_set_named_property(env, element, "encodingTypes", encodingTypes);

    napi_set_element(env, deviceDescriptors, 0, element);
    napi_set_named_property(env, result, "deviceDescriptors", deviceDescriptors);
    return napi_ok;
}
} // namespace Media
} // namespace OHOS