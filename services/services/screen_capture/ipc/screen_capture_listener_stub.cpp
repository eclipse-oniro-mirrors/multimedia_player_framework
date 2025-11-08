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

#include "screen_capture_listener_stub.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureListenerStub"};
}

namespace OHOS {
namespace Media {
ScreenCaptureListenerStub::ScreenCaptureListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

ScreenCaptureListenerStub::~ScreenCaptureListenerStub()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t ScreenCaptureListenerStub::OnCaptureContentChangedStub(MessageParcel &data, MessageParcel &reply)
{
    (void) reply;
    AVScreenCaptureContentChangedEvent event =
        static_cast<AVScreenCaptureContentChangedEvent>(data.ReadInt32());
    CHECK_AND_RETURN_RET_LOG(event >= AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE
        && event <= AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE, MSERR_INVALID_VAL,
        "CaptureContentChanged event invalid");
    bool isAreaExist = data.ReadBool();
    if (isAreaExist) {
        ScreenCaptureRect area = { 0, 0, 0, 0 };
        MEDIA_LOGD("ScreenCaptureListenerStub::OnCaptureContentChangedStub area exist");
        area.x = data.ReadInt32();
        area.y = data.ReadInt32();
        area.width = data.ReadInt32();
        area.height = data.ReadInt32();
        OnCaptureContentChanged(event, &area);
    } else {
        MEDIA_LOGD("ScreenCaptureListenerStub::OnCaptureContentChangedStub area not exist");
        OnCaptureContentChanged(event, nullptr);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureListenerStub::OnUserSelectedStub(MessageParcel &data, MessageParcel &reply)
{
    (void) reply;
    MEDIA_LOGI("ScreenCaptureListenerStub::OnUserSelectedStub start");
    ScreenCaptureUserSelectionInfo selectionInfo = {0, static_cast<uint64_t>(0)};
    selectionInfo.selectType = data.ReadInt32();
    selectionInfo.displayId = data.ReadUint64();
    CHECK_AND_RETURN_RET_LOG(selectionInfo.selectType == 0 || selectionInfo.selectType == 1, MSERR_INVALID_VAL,
        "OnUserSelected selectType invalid");
    OnUserSelected(selectionInfo);
    return MSERR_OK;
}

int ScreenCaptureListenerStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances OnRemoteRequest code:%{public}u", FAKE_POINTER(this), code);
    auto remoteDescriptor = data.ReadInterfaceToken();
    if (ScreenCaptureListenerStub::GetDescriptor() != remoteDescriptor) {
        MEDIA_LOGE("Invalid descriptor");
        return MSERR_INVALID_OPERATION;
    }
    switch (code) {
        case ScreenCaptureListenerMsg::ON_ERROR: {
            int errorType = data.ReadInt32();
            int errorCode = data.ReadInt32();
            OnError(static_cast<ScreenCaptureErrorType>(errorType), errorCode);
            return MSERR_OK;
        }
        case ScreenCaptureListenerMsg::ON_AUDIO_AVAILABLE: {
            bool isReady = data.ReadBool();
            AudioCaptureSourceType type = static_cast<AudioCaptureSourceType>(data.ReadInt32());
            OnAudioBufferAvailable(isReady, type);
            return MSERR_OK;
        }
        case ScreenCaptureListenerMsg::ON_VIDEO_AVAILABLE: {
            bool isReady = data.ReadBool();
            OnVideoBufferAvailable(isReady);
            return MSERR_OK;
        }
        case ScreenCaptureListenerMsg::ON_STAGE_CHANGE: {
            AVScreenCaptureStateCode stateCode = static_cast<AVScreenCaptureStateCode>(data.ReadInt32());
            OnStateChange(stateCode);
            return MSERR_OK;
        }
        case ScreenCaptureListenerMsg::ON_DISPLAY_SELECTED: {
            uint64_t displayId = data.ReadUint64();
            OnDisplaySelected(displayId);
            return MSERR_OK;
        }
        case ScreenCaptureListenerMsg::ON_CONTENT_CHANGED: {
            MEDIA_LOGD("ScreenCaptureListenerMsg::ON_CONTENT_CHANGED");
            return OnCaptureContentChangedStub(data, reply);
        }
        case ScreenCaptureListenerMsg::ON_USER_SELECTED: {
            return OnUserSelectedStub(data, reply);
        }
        default: {
            MEDIA_LOGE("default case, need check ScreenCaptureListenerStub");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

void ScreenCaptureListenerStub::OnError(ScreenCaptureErrorType errorType, int32_t errorCode)
{
    if (callback_ != nullptr) {
        callback_->OnError(errorType, errorCode);
    }
}

void ScreenCaptureListenerStub::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    callback_ = callback;
}

void ScreenCaptureListenerStub::OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type)
{
    if (callback_ != nullptr) {
        callback_->OnAudioBufferAvailable(isReady, type);
    }
}

void ScreenCaptureListenerStub::OnVideoBufferAvailable(bool isReady)
{
    if (callback_ != nullptr) {
        callback_->OnVideoBufferAvailable(isReady);
    }
}

void ScreenCaptureListenerStub::OnStateChange(AVScreenCaptureStateCode stateCode)
{
    if (callback_ != nullptr) {
        callback_->OnStateChange(stateCode);
    }
}

void ScreenCaptureListenerStub::OnDisplaySelected(uint64_t displayId)
{
    if (callback_ != nullptr) {
        callback_->OnDisplaySelected(displayId);
    }
}

void ScreenCaptureListenerStub::OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect* area)
{
    if (callback_ != nullptr) {
        callback_->OnCaptureContentChanged(event, area);
    }
}

void ScreenCaptureListenerStub::OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    if (callback_ != nullptr) {
        callback_->OnUserSelected(selectionInfo);
    }
}
} // namespace Media
} // namespace OHOS