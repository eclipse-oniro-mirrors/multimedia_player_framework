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

#include <memory>
#include <mutex>
#include <securec.h>

#include "media_log.h"
#include "media_errors.h"
#include "native_mfmagic.h"
#include "native_player_magic.h"
#include "lpp_audio_streamer.h"
#include "native_averrors.h"
#include "lowpower_audio_sink.h"
#include "native_avbuffer.h"
#include "lpp_video_streamer.h"
#include "lpp_common.h"
#include "native_lpp_common.h"
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NativeLPPAudioStreamer"};
}

using namespace OHOS::Media;
using namespace OHOS::DrmStandard;

class NativeLowPowerAudioSinkPositionUpdatedCallback {
public:
    NativeLowPowerAudioSinkPositionUpdatedCallback(OH_LowPowerAudioSink_OnPositionUpdated callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkPositionUpdatedCallback() = default;

    void OnPositionUpdated(OH_LowPowerAudioSink *lppAudioStreamer, long currentPosition)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, currentPosition, userData_);
    }
private:
    OH_LowPowerAudioSink_OnPositionUpdated callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerAudioSinkDataNeeededCallback {
public:
    NativeLowPowerAudioSinkDataNeeededCallback(OH_LowPowerAudioSink_OnDataNeeded callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkDataNeeededCallback() = default;

    void OnDataNeeded(OH_LowPowerAudioSink *lppAudioStreamer, OH_AVSamplesBuffer *framePacket)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, framePacket, userData_);
    }
private:
    OH_LowPowerAudioSink_OnDataNeeded callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerAudioSinkErrorCallback {
public:
    NativeLowPowerAudioSinkErrorCallback(OH_LowPowerAudioSink_OnError callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkErrorCallback() = default;

    void OnError(OH_LowPowerAudioSink *lppAudioStreamer, OH_AVErrCode errorCode, const std::string &errorMsg)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, errorCode, errorMsg.c_str(), userData_);
    }
private:
    OH_LowPowerAudioSink_OnError callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerAudioSinkInterruptCallback {
public:
    NativeLowPowerAudioSinkInterruptCallback(OH_LowPowerAudioSink_OnInterrupted callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkInterruptCallback() = default;

    void OnInterrupted(
        OH_LowPowerAudioSink *lppAudioStreamer, OH_AudioInterrupt_ForceType type, OH_AudioInterrupt_Hint hint)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, type, hint, userData_);
    }

private:
    OH_LowPowerAudioSink_OnInterrupted callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerAudioSinkDeviceChangeCallback {
public:
    NativeLowPowerAudioSinkDeviceChangeCallback(OH_LowPowerAudioSink_OnDeviceChanged callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkDeviceChangeCallback() = default;

    void OnDeviceChanged(OH_LowPowerAudioSink *lppAudioStreamer, OH_AudioStream_DeviceChangeReason reason)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, reason, userData_);
    }
private:
    OH_LowPowerAudioSink_OnDeviceChanged callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerAudioSinkEosCallback {
public:
    NativeLowPowerAudioSinkEosCallback(OH_LowPowerAudioSink_OnEos callback, void *userData)
        : callback_(callback), userData_(userData) {}
    virtual ~NativeLowPowerAudioSinkEosCallback() = default;

    void OnEos(OH_LowPowerAudioSink *lppAudioStreamer)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppAudioStreamer, userData_);
    }
private:
    OH_LowPowerAudioSink_OnEos callback_ = nullptr;
    void *userData_ = nullptr;
};

struct OH_LowPowerAudioSinkCallback : public AudioStreamerCallback {
public:
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody) override;

public:
    int32_t SetErrorListener(OH_LowPowerAudioSink_OnError onError, void *userData);
    int32_t SetDataNeededListener(OH_LowPowerAudioSink_OnDataNeeded onDataNeeded, void *userData);
    int32_t SetPositionUpdateListener(OH_LowPowerAudioSink_OnPositionUpdated onPositionUpdatedback, void *userData);
    int32_t SetInterruptListener(OH_LowPowerAudioSink_OnInterrupted onInterrupted, void *userData);
    int32_t SetDeviceChangeListener(OH_LowPowerAudioSink_OnDeviceChanged onDeviceChanged, void *userData);
    int32_t SetEosListener(OH_LowPowerAudioSink_OnEos onEos, void *userData);
    int32_t SetLowPowerAudioSink(struct OH_LowPowerAudioSink *lppAudioStreamer);
    
private:
    struct OH_LowPowerAudioSink *lppAudioStreamer_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkDataNeeededCallback> dataNeeededCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkPositionUpdatedCallback> positionUpdatedCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkInterruptCallback> interruptCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkDeviceChangeCallback> deviceChangeCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerAudioSinkEosCallback> eosCallback_ = nullptr;
};

int32_t OH_LowPowerAudioSinkCallback::SetLowPowerAudioSink(struct OH_LowPowerAudioSink *lppAudioStreamer)
{
    CHECK_AND_RETURN_RET_LOG(lppAudioStreamer != nullptr, AV_ERR_INVALID_VAL, "lppAudioStreamer is nullptr");
    lppAudioStreamer_ = lppAudioStreamer;
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetErrorListener(OH_LowPowerAudioSink_OnError onError, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onError != nullptr, AV_ERR_INVALID_VAL, "onError is nullptr");
    errorCallback_ = std::make_shared<NativeLowPowerAudioSinkErrorCallback>(onError, userData);
    CHECK_AND_RETURN_RET_LOG(errorCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "errorCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetDataNeededListener(OH_LowPowerAudioSink_OnDataNeeded onDataNeeded,
    void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onDataNeeded != nullptr, AV_ERR_INVALID_VAL, "onDataNeeded is nullptr");
    dataNeeededCallback_ = std::make_shared<NativeLowPowerAudioSinkDataNeeededCallback>(onDataNeeded, userData);
    CHECK_AND_RETURN_RET_LOG(
        dataNeeededCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "dataNeeededCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetPositionUpdateListener(
    OH_LowPowerAudioSink_OnPositionUpdated onPositionUpdated, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onPositionUpdated != nullptr, AV_ERR_INVALID_VAL, "onPositionUpdated is nullptr");
    positionUpdatedCallback_
        = std::make_shared<NativeLowPowerAudioSinkPositionUpdatedCallback>(onPositionUpdated, userData);
    CHECK_AND_RETURN_RET_LOG(positionUpdatedCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT,
        "positionUpdatedCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetInterruptListener(OH_LowPowerAudioSink_OnInterrupted onInterrupted,
    void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onInterrupted != nullptr, AV_ERR_INVALID_VAL, "onInterrupted is nullptr");
    interruptCallback_ = std::make_shared<NativeLowPowerAudioSinkInterruptCallback>(onInterrupted, userData);
    CHECK_AND_RETURN_RET_LOG(
        interruptCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "interruptCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetEosListener(OH_LowPowerAudioSink_OnEos onEos, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onEos != nullptr, AV_ERR_INVALID_VAL, "onEos is nullptr");
    eosCallback_ = std::make_shared<NativeLowPowerAudioSinkEosCallback>(onEos, userData);
    CHECK_AND_RETURN_RET_LOG(eosCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "eosCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerAudioSinkCallback::SetDeviceChangeListener(OH_LowPowerAudioSink_OnDeviceChanged onDeviceChanged,
    void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onDeviceChanged != nullptr, AV_ERR_INVALID_VAL, "onDeviceChanged is nullptr");
    deviceChangeCallback_ = std::make_shared<NativeLowPowerAudioSinkDeviceChangeCallback>(onDeviceChanged, userData);
    CHECK_AND_RETURN_RET_LOG(
        deviceChangeCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "deviceChangeCallback_ is nullptr!");
    return AV_ERR_OK;
}

void OH_LowPowerAudioSinkCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN_LOG(lppAudioStreamer_ != nullptr, "lppAudioStreamer_ is nullptr");
    CHECK_AND_RETURN_LOG(errorCallback_ != nullptr, "errorCallback_ is nullptr");

    OH_AVErrCode avErrorCode = LppMsErrToOHAvErr(errorCode);
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    std::string errorMsgExt = MSExtAVErrorToString(errorCodeApi9) + errorMsg;
    MEDIA_LOGE("LowPowerAudioSink errorCode: %{public}d, errorMsg: %{public}s", static_cast<int32_t>(avErrorCode),
        errorMsgExt.c_str());
    errorCallback_->OnError(lppAudioStreamer_, avErrorCode, errorMsgExt.c_str());
}

void OH_LowPowerAudioSinkCallback::OnInfo(AudioStreamerOnInfoType type, int32_t extra, const Format &infoBody)
{
    MEDIA_LOGD("OnInfo() is called, AudioStreamerOnInfoType: %{public}d, extra: %{public}d", type, extra);
    CHECK_AND_RETURN_LOG(lppAudioStreamer_ != nullptr, "lppAudioStreamer_ is nullptr");
    LowPowerAudioSinkObject *streamerObj = nullptr;
    switch (type) {
        case INFO_TYPE_LPP_AUDIO_DATA_NEEDED:
            CHECK_AND_RETURN_LOG(dataNeeededCallback_ != nullptr, "dataNeeededCallback_ is nullptr");
            streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(lppAudioStreamer_);
            CHECK_AND_RETURN_LOG(streamerObj != nullptr, "streamerObj is nullptr");
            CHECK_AND_RETURN_LOG(streamerObj->framePacket_ != nullptr &&
                streamerObj->framePacket_->lppDataPacket_ != nullptr, "framePacket_ is nullptr");
            streamerObj->framePacket_->lppDataPacket_->Enable();
            dataNeeededCallback_->OnDataNeeded(lppAudioStreamer_, streamerObj->framePacket_);
            break;
        case INFO_TYPE_LPP_AUDIO_EOS:
            CHECK_AND_RETURN_LOG(eosCallback_ != nullptr, "eosCallback_ is nullptr");
            eosCallback_->OnEos(lppAudioStreamer_);
            break;
        case INFO_TYPE_LPP_AUDIO_INTERRUPT:
            CHECK_AND_RETURN_LOG(interruptCallback_ != nullptr, "interruptCallback_ is nullptr");
            int32_t forceType;
            infoBody.GetIntValue(AudioStreamerKeys::LPP_AUDIO_INTERRUPT_FORCE_TYPE, forceType);
            int32_t hint;
            infoBody.GetIntValue(AudioStreamerKeys::LPP_AUDIO_INTERRUPT_HINT, hint);
            interruptCallback_->OnInterrupted(lppAudioStreamer_,
                static_cast<OH_AudioInterrupt_ForceType>(hint),
                static_cast<OH_AudioInterrupt_Hint>(hint));
            break;
        case INFO_TYPE_LPP_AUDIO_DEVICE_CHANGE:
            CHECK_AND_RETURN_LOG(deviceChangeCallback_ != nullptr, "deviceChangeCallback_ is nullptr");
            int32_t reason;
            infoBody.GetIntValue(AudioStreamerKeys::LPP_AUDIO_DEVICE_CHANGE_REASON, reason);
            deviceChangeCallback_->OnDeviceChanged(lppAudioStreamer_,
                static_cast<OH_AudioStream_DeviceChangeReason>(reason));
            break;
        case INFO_TYPE_LPP_AUDIO_POSITION_UPDATE:
            CHECK_AND_RETURN_LOG(positionUpdatedCallback_ != nullptr, "positionUpdatedCallback_ is nullptr");
            long position;
            infoBody.GetLongValue(AudioStreamerKeys::LPP_CURRENT_POSITION, position);
            positionUpdatedCallback_->OnPositionUpdated(lppAudioStreamer_, position);
            break;
        default:
            break;
    }
}


OH_LowPowerAudioSink *OH_LowPowerAudioSink_CreateByMime(const char * mime)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_CreateByMime");
    CHECK_AND_RETURN_RET_LOG(mime != nullptr, nullptr, "mime is nullptr");
    std::shared_ptr<AudioStreamer> player = AudioStreamerFactory::CreateByMime(mime);
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "create player failed!");
    std::string streamId = player->GetStreamerId();

    OHOS::sptr<LppDataPacket> lppDataPacket =  OHOS::sptr<LppDataPacket>::MakeSptr();
    CHECK_AND_RETURN_RET_LOG(lppDataPacket != nullptr, nullptr, "create lppDataPacket failed!");
    lppDataPacket->Init(streamId);

    AVSamplesBufferObject* framePacket = new(std::nothrow) AVSamplesBufferObject(lppDataPacket);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, nullptr, "create framePacket failed!");
    LowPowerAudioSinkObject *object = new(std::nothrow) LowPowerAudioSinkObject(player, framePacket);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "create object failed!");
    return object;
}

OH_AVErrCode OH_LowPowerAudioSink_Configure(OH_LowPowerAudioSink *streamer, const OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Configure");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "format is nullptr");

    struct LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");

    Format format_ = static_cast<Format>(format->format_);
    int32_t res = streamerObj->audioStreamer_->Configure(format_);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_SetParameter(OH_LowPowerAudioSink *streamer, const OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_SetParameter");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "format is nullptr");

    struct LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");

    Format format_ = static_cast<Format>(format->format_);
    int32_t res = streamerObj->audioStreamer_->SetParameter(format_);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_GetParameter(OH_LowPowerAudioSink *sink, OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_GetParameter");
    (void)sink;
    (void)format;
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerAudioSink_Prepare(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Prepare");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Prepare();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Start(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Start");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Start();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Pause(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Pause");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Pause();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Resume(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Resume");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Resume();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Flush(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Flush");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Flush();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Stop(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Stop");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Stop();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Reset(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Reset");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Reset();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_Destroy(OH_LowPowerAudioSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_Destroy");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->Release();
    MEDIA_LOGI("videostreamer release result is %{public}d", res);
    delete streamerObj->framePacket_;
    delete streamerObj;
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerAudioSink_SetPlaybackSpeed(OH_LowPowerAudioSink *streamer, const float speed)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_SetPlaybackSpeed");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->SetPlaybackSpeed(speed);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_SetVolume(OH_LowPowerAudioSink *streamer, const float volume)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_SetVolume");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->SetVolume(volume);
    return LppMsErrToOHAvErr(res);
}


OH_AVErrCode OH_LowPowerAudioSink_SetLoudnessGain(OH_LowPowerAudioSink* streamer, float loudnessGain)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_SetLoudnessGain");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->audioStreamer_->SetLoudnessGain(loudnessGain);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSink_ReturnSamples(OH_LowPowerAudioSink *streamer, OH_AVSamplesBuffer *frames)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_ReturnSamples");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    AVSamplesBufferObject *framePacket = reinterpret_cast<AVSamplesBufferObject *>(frames);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, AV_ERR_INVALID_VAL, "framePacket is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_ != nullptr, AV_ERR_INVALID_VAL, "lppDataPacket is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_->IsEnable(), AV_ERR_INVALID_VAL, "data packet is not in user");
    framePacket->lppDataPacket_->Disable();
    int32_t res = streamerObj->audioStreamer_->ReturnFrames(framePacket->lppDataPacket_);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, LppMsErrToOHAvErr(res), "ReturnFrames failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerAudioSink_RegisterCallback(
    OH_LowPowerAudioSink *streamer, OH_LowPowerAudioSinkCallback *callback)
{
    MEDIA_LOGD("OH_LowPowerAudioSink_RegisterCallback");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    LowPowerAudioSinkObject *streamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    callback->SetLowPowerAudioSink(streamer);
    std::shared_ptr<AudioStreamerCallback> callbackPtr(callback);
    int32_t res = streamerObj->audioStreamer_->SetLppAudioStreamerCallback(callbackPtr);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, LppMsErrToOHAvErr(res), "setcallback failed");
    res = streamerObj->audioStreamer_->RegisterCallback();
    return LppMsErrToOHAvErr(res);
}

OH_LowPowerAudioSinkCallback *OH_LowPowerAudioSinkCallback_Create()
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_Create");
    OH_LowPowerAudioSinkCallback *callback = new(std::nothrow) OH_LowPowerAudioSinkCallback();
    return callback;
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_Destroy(OH_LowPowerAudioSinkCallback *callback)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_Destroy");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetPositionUpdateListener(OH_LowPowerAudioSinkCallback * callback,
    OH_LowPowerAudioSink_OnPositionUpdated onPositionUpdated, void *userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetPositionUpdateListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onPositionUpdated != nullptr, AV_ERR_INVALID_VAL, "onPositionUpdated is nullptr!");
    int32_t res = callback->SetPositionUpdateListener(onPositionUpdated, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetDataNeededListener(OH_LowPowerAudioSinkCallback * callback,
    OH_LowPowerAudioSink_OnDataNeeded onDataNeeded, void *userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetDataNeededListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onDataNeeded != nullptr, AV_ERR_INVALID_VAL, "onDataNeeded is nullptr!");
    int32_t res = callback->SetDataNeededListener(onDataNeeded, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetErrorListener(OH_LowPowerAudioSinkCallback *callback,
    OH_LowPowerAudioSink_OnError onError, void * userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetErrorListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onError != nullptr, AV_ERR_INVALID_VAL, "onError is nullptr!");
    int32_t res = callback->SetErrorListener(onError, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetInterruptListener(OH_LowPowerAudioSinkCallback * callback,
    OH_LowPowerAudioSink_OnInterrupted onInterrupted, void *userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetInterruptListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onInterrupted != nullptr, AV_ERR_INVALID_VAL, "onInterrupted is nullptr!");
    int32_t res = callback->SetInterruptListener(onInterrupted, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetDeviceChangeListener(OH_LowPowerAudioSinkCallback * callback,
    OH_LowPowerAudioSink_OnDeviceChanged onDeviceChanged, void *userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetDeviceChangeListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onDeviceChanged != nullptr, AV_ERR_INVALID_VAL, "onDeviceChanged is nullptr!");
    int32_t res = callback->SetDeviceChangeListener(onDeviceChanged, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerAudioSinkCallback_SetEosListener(OH_LowPowerAudioSinkCallback * callback,
    OH_LowPowerAudioSink_OnEos onEos, void *userData)
{
    MEDIA_LOGD("OH_LowPowerAudioSinkCallback_SetEosListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onEos != nullptr, AV_ERR_INVALID_VAL, "onEos is nullptr!");
    int32_t res = callback->SetEosListener(onEos, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_AVSamplesBuffer_AppendOneBuffer(OH_AVSamplesBuffer *frames, OH_AVBuffer *encodedBuffer)
{
    MEDIA_LOGD("OH_AVSamplesBuffer_AppendOneBuffer");
    CHECK_AND_RETURN_RET_LOG(frames != nullptr, AV_ERR_INVALID_VAL, "frames is nullptr!");
    CHECK_AND_RETURN_RET_LOG(encodedBuffer != nullptr, AV_ERR_INVALID_VAL, "encodedBuffer is nullptr!");
    AVSamplesBufferObject *framePacket = reinterpret_cast<AVSamplesBufferObject *>(frames);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, AV_ERR_INVALID_VAL, "framePacket is nullptr!");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_ != nullptr, AV_ERR_INVALID_VAL, "lppDataPacket is nullptr!");
    bool res = framePacket->lppDataPacket_->AppendOneBuffer(encodedBuffer->buffer_);
    return res ? AV_ERR_OK : AV_ERR_INVALID_VAL;
}

int32_t OH_AVSamplesBuffer_GetRemainedCapacity(OH_AVSamplesBuffer *frames)
{
    MEDIA_LOGD("OH_AVSamplesBuffer_AppendOneBuffer");
    CHECK_AND_RETURN_RET_LOG(frames != nullptr, AV_ERR_INVALID_VAL, "frames is nullptr!");
    AVSamplesBufferObject *framePacket = reinterpret_cast<AVSamplesBufferObject *>(frames);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, AV_ERR_INVALID_VAL, "framePacket is nullptr!");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_ != nullptr, AV_ERR_INVALID_VAL, "lppDataPacket is nullptr!");
    return framePacket->lppDataPacket_->GetRemainedCapacity();
}
