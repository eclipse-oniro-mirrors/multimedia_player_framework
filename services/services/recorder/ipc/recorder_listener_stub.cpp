/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "recorder_listener_stub.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_RECORDER, "RecorderListenerStub"};
}

namespace OHOS {
namespace Media {
RecorderListenerStub::RecorderListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

RecorderListenerStub::~RecorderListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int RecorderListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (RecorderListenerStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }

    switch (code) {
        case RecorderListenerMsg::ON_ERROR: {
            int errorType = data.ReadInt32();
            int errorCode = data.ReadInt32();
            OnError(static_cast<RecorderErrorType>(errorType), errorCode);
            return MSERR_OK;
        }
        case RecorderListenerMsg::ON_INFO: {
            int type = data.ReadInt32();
            int extra = data.ReadInt32();
            OnInfo(type, extra);
            return MSERR_OK;
        }
        case RecorderListenerMsg::ON_AUDIO_CAPTURE_CHANGE: {
            AudioRecorderChangeInfo audioRecorderChangeInfo;
            audioRecorderChangeInfo.Unmarshalling(data);
            OnAudioCaptureChange(audioRecorderChangeInfo);
            return MSERR_OK;
        }
        case RecorderListenerMsg::ON_PHOTO_ASSET_AVAILABLE: {
            std::string uri = data.ReadString();
            OnPhotoAssetAvailable(uri);
            return MSERR_OK;
        }
        default: {
            MEDIA_LOGE("default case, need check RecorderListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

void RecorderListenerStub::OnError(int32_t errorType, int32_t errorCode)
{
    std::shared_ptr<RecorderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        cb = callback_;
    }
    if (cb != nullptr) {
        cb->OnError(static_cast<RecorderErrorType>(errorType), errorCode);
    }

    std::weak_ptr<MonitorClientObject> monitorCopy;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        monitorCopy = monitor_;
    }
    std::shared_ptr<MonitorClientObject> monitor = monitorCopy.lock();
    CHECK_AND_RETURN(monitor != nullptr);
    (void)monitor->DisableMonitor();
}

void RecorderListenerStub::OnInfo(int32_t type, int32_t extra)
{
    std::shared_ptr<RecorderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        cb = callback_;
    }
    CHECK_AND_RETURN(cb != nullptr);
    cb->OnInfo(type, extra);
}

void RecorderListenerStub::OnAudioCaptureChange(const AudioRecorderChangeInfo &audioRecorderChangeInfo)
{
    std::shared_ptr<RecorderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        cb = callback_;
    }
    CHECK_AND_RETURN(cb != nullptr);
    cb->OnAudioCaptureChange(audioRecorderChangeInfo);
}

void RecorderListenerStub::OnPhotoAssetAvailable(const std::string &uri)
{
    std::shared_ptr<RecorderCallback> cb;
    {
        std::lock_guard<std::mutex> lock(callbackMutex_);
        cb = callback_;
    }
    CHECK_AND_RETURN(cb != nullptr);
    cb->OnPhotoAssetAvailable(uri);
}

void RecorderListenerStub::SetRecorderCallback(const std::shared_ptr<RecorderCallback> &callback)
{
    std::lock_guard<std::mutex> lock(callbackMutex_);
    callback_ = callback;
}

void RecorderListenerStub::SetMonitor(const std::weak_ptr<MonitorClientObject> &monitor)
{
    MEDIA_LOGI("SetMonitor");
    std::lock_guard<std::mutex> lock(callbackMutex_);
    monitor_ = monitor;
}
} // namespace Media
} // namespace OHOS
