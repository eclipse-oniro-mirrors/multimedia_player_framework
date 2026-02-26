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
#include <refbase.h>

#include <securec.h>
#include "media_log.h"
#include "media_errors.h"
#include "native_lpp_common.h"
#include "native_mfmagic.h"
#include "native_player_magic.h"
#include "native_window.h"
#include "lpp_video_streamer.h"
#include "lowpower_video_sink.h"
#include "native_averrors.h"
#include "lpp_common.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "NativeLPPVideoStreamer"};
}

using namespace OHOS::Media;

class NativeLowPowerVideoSinkDataNeeededCallback {
public:
    NativeLowPowerVideoSinkDataNeeededCallback(OH_LowPowerVideoSink_OnDataNeeded callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkDataNeeededCallback() = default;

    void OnDataNeeded(OH_LowPowerVideoSink *lppVideoStreamer_, OH_AVSamplesBuffer *framePacket)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, framePacket, userData_);
    }

private:
    OH_LowPowerVideoSink_OnDataNeeded callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkErrorCallback {
public:
    NativeLowPowerVideoSinkErrorCallback(OH_LowPowerVideoSink_OnError callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkErrorCallback() = default;

    void OnError(OH_LowPowerVideoSink *lppVideoStreamer_, OH_AVErrCode errCode, const char *errMsg)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, errCode, errMsg, userData_);
    }

private:
    OH_LowPowerVideoSink_OnError callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkTargetArrivedCallback {
public:
    NativeLowPowerVideoSinkTargetArrivedCallback(OH_LowPowerVideoSink_OnTargetArrived callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkTargetArrivedCallback() = default;

    void OnTargetArrived(OH_LowPowerVideoSink *lppVideoStreamer_, long targetPts, bool isTimeout)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, targetPts, isTimeout, userData_);
    }

private:
    OH_LowPowerVideoSink_OnTargetArrived callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkRenderStartedCallback {
public:
    NativeLowPowerVideoSinkRenderStartedCallback(OH_LowPowerVideoSink_OnRenderStarted callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkRenderStartedCallback() = default;

    void OnRenderStarted(OH_LowPowerVideoSink *lppVideoStreamer_)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, userData_);
    }

private:
    OH_LowPowerVideoSink_OnRenderStarted callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkEosCallback {
public:
    NativeLowPowerVideoSinkEosCallback(OH_LowPowerVideoSink_OnEos callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkEosCallback() = default;

    void OnEos(OH_LowPowerVideoSink *lppVideoStreamer_)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, userData_);
    }

private:
    OH_LowPowerVideoSink_OnEos callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkStreamChangedCallback {
public:
    NativeLowPowerVideoSinkStreamChangedCallback(OH_LowPowerVideoSink_OnStreamChanged callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkStreamChangedCallback() = default;

    void OnStreamChanged(OH_LowPowerVideoSink *lppVideoStreamer_, OH_AVFormat *format)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, format, userData_);
    }

private:
    OH_LowPowerVideoSink_OnStreamChanged callback_ = nullptr;
    void *userData_ = nullptr;
};

class NativeLowPowerVideoSinkFirstFrameReadyCallback {
public:
    NativeLowPowerVideoSinkFirstFrameReadyCallback(OH_LowPowerVideoSink_OnFirstFrameDecoded callback, void *userData)
        : callback_(callback), userData_(userData)
    {}
    virtual ~NativeLowPowerVideoSinkFirstFrameReadyCallback() = default;

    void OnFirstFrameReady(OH_LowPowerVideoSink *lppVideoStreamer_)
    {
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "callback_ is nullptr");
        callback_(lppVideoStreamer_, userData_);
    }

private:
    OH_LowPowerVideoSink_OnFirstFrameDecoded callback_ = nullptr;
    void *userData_ = nullptr;
};

struct OH_LowPowerVideoSinkCallback : public VideoStreamerCallback {
public:
    void OnError(int32_t errorCode, const std::string &errorMsg) override;
    void OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody) override;

public:
    int32_t SetDataNeededListener(OH_LowPowerVideoSink_OnDataNeeded onDataNeeded, void *userData);
    int32_t SetErrorListener(OH_LowPowerVideoSink_OnError onError, void *userData);
    int32_t SetTargetArrivedListener(OH_LowPowerVideoSink_OnTargetArrived onTargetArrived, void *userData);
    int32_t SetRenderStartListener(OH_LowPowerVideoSink_OnRenderStarted onRenderStarted, void *userData);
    int32_t SetEosListener(OH_LowPowerVideoSink_OnEos onEos, void *userData);
    int32_t SetStreamChangedListener(OH_LowPowerVideoSink_OnStreamChanged onStreamChanged, void *userData);
    int32_t SetFirstFrameReadyListener(OH_LowPowerVideoSink_OnFirstFrameDecoded onFirstFrameReady, void *userData);
    int32_t SetLowPowerVideoSink(struct OH_LowPowerVideoSink *lppVideoStreamer);

private:
    struct OH_LowPowerVideoSink *lppVideoStreamer_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkDataNeeededCallback> dataNeeededCallback_ = nullptr;
    // std::shared_ptr<NativeLowPowerVideoSinkAnchorUpdatedCallback> anchorUpdatedCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkErrorCallback> errorCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkTargetArrivedCallback> targetArrivedCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkRenderStartedCallback> renderStartedCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkEosCallback> eosCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkStreamChangedCallback> streamChangedCallback_ = nullptr;
    std::shared_ptr<NativeLowPowerVideoSinkFirstFrameReadyCallback> firstFrameReadyCallback_ = nullptr;
};

int32_t OH_LowPowerVideoSinkCallback::SetLowPowerVideoSink(struct OH_LowPowerVideoSink *lppVideoStreamer)
{
    CHECK_AND_RETURN_RET_LOG(lppVideoStreamer != nullptr, AV_ERR_INVALID_VAL, "lppVideoStreamer is nullptr");
    lppVideoStreamer_ = lppVideoStreamer;
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetDataNeededListener(
    OH_LowPowerVideoSink_OnDataNeeded onDataNeeded, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onDataNeeded != nullptr, AV_ERR_INVALID_VAL, "onDataNeeded is nullptr");
    dataNeeededCallback_ = std::make_shared<NativeLowPowerVideoSinkDataNeeededCallback>(onDataNeeded, userData);
    CHECK_AND_RETURN_RET_LOG(
        dataNeeededCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "dataNeeededCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetErrorListener(OH_LowPowerVideoSink_OnError onError, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onError != nullptr, AV_ERR_INVALID_VAL, "onError is nullptr");
    errorCallback_ = std::make_shared<NativeLowPowerVideoSinkErrorCallback>(onError, userData);
    CHECK_AND_RETURN_RET_LOG(errorCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "errorCallback is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetTargetArrivedListener(
    OH_LowPowerVideoSink_OnTargetArrived onTargetArrived, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onTargetArrived != nullptr, AV_ERR_INVALID_VAL, "onTargetArrived is nullptr");
    targetArrivedCallback_ = std::make_shared<NativeLowPowerVideoSinkTargetArrivedCallback>(onTargetArrived, userData);
    CHECK_AND_RETURN_RET_LOG(
        targetArrivedCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "targetArrivedCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetRenderStartListener(
    OH_LowPowerVideoSink_OnRenderStarted onRenderStarted, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onRenderStarted != nullptr, AV_ERR_INVALID_VAL, "onRenderStarted is nullptr");
    renderStartedCallback_ = std::make_shared<NativeLowPowerVideoSinkRenderStartedCallback>(onRenderStarted, userData);
    CHECK_AND_RETURN_RET_LOG(
        renderStartedCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "renderStartedCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetEosListener(OH_LowPowerVideoSink_OnEos onEos, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onEos != nullptr, AV_ERR_INVALID_VAL, "onEos is nullptr");
    eosCallback_ = std::make_shared<NativeLowPowerVideoSinkEosCallback>(onEos, userData);
    CHECK_AND_RETURN_RET_LOG(eosCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "eosCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetStreamChangedListener(
    OH_LowPowerVideoSink_OnStreamChanged onStreamChanged, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onStreamChanged != nullptr, AV_ERR_INVALID_VAL, "onStreamChanged is nullptr");
    streamChangedCallback_ = std::make_shared<NativeLowPowerVideoSinkStreamChangedCallback>(onStreamChanged, userData);
    CHECK_AND_RETURN_RET_LOG(
        streamChangedCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "streamChangedCallback_ is nullptr!");
    return AV_ERR_OK;
}

int32_t OH_LowPowerVideoSinkCallback::SetFirstFrameReadyListener(
    OH_LowPowerVideoSink_OnFirstFrameDecoded onFirstFrameReady, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(onFirstFrameReady != nullptr, AV_ERR_INVALID_VAL, "onFirstFrameReady is nullptr");
    firstFrameReadyCallback_ =
        std::make_shared<NativeLowPowerVideoSinkFirstFrameReadyCallback>(onFirstFrameReady, userData);
    CHECK_AND_RETURN_RET_LOG(
        firstFrameReadyCallback_ != nullptr, AV_ERR_OPERATE_NOT_PERMIT, "firstFrameReadyCallback_ is nullptr!");
    return AV_ERR_OK;
}

void OH_LowPowerVideoSinkCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    CHECK_AND_RETURN_LOG(lppVideoStreamer_ != nullptr, "lppVideoStreamer_ is nullptr");
    CHECK_AND_RETURN_LOG(errorCallback_ != nullptr, "errorCallback_ is nullptr");

    OH_AVErrCode avErrorCode = LppMsErrToOHAvErr(errorCode);
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    std::string errorMsgExt = MSExtAVErrorToString(errorCodeApi9) + errorMsg;
    MEDIA_LOGE("LowPowerVideoSink errorCode: %{public}d, errorMsg: %{public}s", static_cast<int32_t>(avErrorCode),
        errorMsgExt.c_str());
    errorCallback_->OnError(lppVideoStreamer_, avErrorCode, errorMsgExt.c_str());
}

void OH_LowPowerVideoSinkCallback::OnInfo(VideoStreamerOnInfoType type, int32_t extra, const Format &infoBody)
{
    MEDIA_LOGD("OnInfo() is called, VideoStreamerOnInfoType: %{public}d, extra: %{public}d", type, extra);
    CHECK_AND_RETURN_LOG(lppVideoStreamer_ != nullptr, "lppVideoStreamer_ is nullptr");
    LowPowerVideoSinkObject *streamerObj = nullptr;
    switch (type) {
        case VIDEO_INFO_TYPE_LPP_DATA_NEEDED:
            CHECK_AND_RETURN_LOG(dataNeeededCallback_ != nullptr, "dataNeeededCallback_ is nullptr");
            streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(lppVideoStreamer_);
            CHECK_AND_RETURN_LOG(streamerObj != nullptr, "streamerObj is nullptr");
            CHECK_AND_RETURN_LOG(streamerObj->framePacket_ != nullptr &&
                streamerObj->framePacket_->lppDataPacket_ != nullptr, "framePacket_ is nullptr");
            streamerObj->framePacket_->lppDataPacket_->Enable();
            dataNeeededCallback_->OnDataNeeded(lppVideoStreamer_, streamerObj->framePacket_);
            break;
        case VIDEO_INFO_TYPE_LPP_FIRST_FRAME_READY:
            CHECK_AND_RETURN_LOG(firstFrameReadyCallback_ != nullptr, "firstFrameReadyCallback_ is nullptr");
            firstFrameReadyCallback_->OnFirstFrameReady(lppVideoStreamer_);
            break;
        case VIDEO_INFO_TYPE_LPP_TARGET_ARRIVED:
            {
                CHECK_AND_RETURN_LOG(targetArrivedCallback_ != nullptr, "targetArrivedCallback_ is nullptr");
                int64_t targetPts = 0;
                (void)infoBody.GetLongValue(VideoStreamerKeys::LPP_VIDEO_TARGET_PTS, targetPts);
                int32_t isTimeout = 0;
                (void)infoBody.GetIntValue(VideoStreamerKeys::LPP_VIDEO_IS_TIMEOUT, isTimeout);
                targetArrivedCallback_->OnTargetArrived(lppVideoStreamer_, targetPts, static_cast<bool>(isTimeout));
            }
            break;
        case VIDEO_INFO_TYPE_LPP_RENDER_STARTED:
            CHECK_AND_RETURN_LOG(renderStartedCallback_ != nullptr, "renderStartedCallback_ is nullptr");
            renderStartedCallback_->OnRenderStarted(lppVideoStreamer_);
            break;
        case VIDEO_INFO_TYPE_LPP_EOS:
            CHECK_AND_RETURN_LOG(eosCallback_ != nullptr, "eosCallback_ is nullptr");
            eosCallback_->OnEos(lppVideoStreamer_);
            break;
        case VIDEO_INFO_TYPE_LPP_STREAM_CHANGED:
            {
                CHECK_AND_RETURN_LOG(streamChangedCallback_ != nullptr, "streamChangedCallback_ is nullptr");
                OHOS::sptr<OH_AVFormat> object = OHOS::sptr<OH_AVFormat>::MakeSptr(infoBody);
                streamChangedCallback_->OnStreamChanged(lppVideoStreamer_,
                    reinterpret_cast<OH_AVFormat *>(object.GetRefPtr()));
            }
            break;
        default:
            break;
    }
}

OH_LowPowerVideoSink *OH_LowPowerVideoSink_CreateByMime(const char *mime)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_CreateByMime");
    CHECK_AND_RETURN_RET_LOG(mime != nullptr, nullptr, "mime is nullptr");
    std::shared_ptr<VideoStreamer> player = VideoStreamerFactory::CreateByMime(std::string(mime));
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "create player failed!");
    std::string streamerId = player->GetStreamerId();

    OHOS::sptr<LppDataPacket> lppDataPacket = OHOS::sptr<LppDataPacket>::MakeSptr();
    CHECK_AND_RETURN_RET_LOG(lppDataPacket != nullptr, nullptr, "create lppDataPacket failed!");
    lppDataPacket->Init(streamerId);

    AVSamplesBufferObject* framePacket = new(std::nothrow) AVSamplesBufferObject(lppDataPacket);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, nullptr, "create framePacket failed!");
    LowPowerVideoSinkObject *object = new (std::nothrow) LowPowerVideoSinkObject(player, framePacket);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "create object failed!");
    return object;
}

OH_AVErrCode OH_LowPowerVideoSink_Configure(OH_LowPowerVideoSink *streamer, const OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_Configure");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "format is nullptr");
    LowPowerVideoSinkObject *streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);

    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    Format format_ = static_cast<Format>(format->format_);
    int32_t res = streamerObj->videoStreamer_->Configure(format_);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_SetParameter(OH_LowPowerVideoSink *streamer, const OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_SetParameter");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "format is nullptr");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    auto format_ = static_cast<Format>(format->format_);
    int32_t res = streamerObj->videoStreamer_->SetParameter(format_);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_GetParameter(OH_LowPowerVideoSink *sink, OH_AVFormat *format)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_GetParameter");
    CHECK_AND_RETURN_RET_LOG(sink != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr");
    CHECK_AND_RETURN_RET_LOG(format != nullptr, AV_ERR_INVALID_VAL, "format is nullptr");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(sink);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    Format format_ {};
    int32_t res = streamerObj->videoStreamer_->GetParameter(format_);
    format->format_= format_;
    CHECK_AND_RETURN_RET_LOG(res == AV_ERR_OK, AV_ERR_OPERATE_NOT_PERMIT, "OH_LowPowerVideoSink_GetParameter failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerVideoSink_SetVideoSurface(OH_LowPowerVideoSink *streamer, const OHNativeWindow *window)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_SetVideoSurface");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window != nullptr, AV_ERR_INVALID_VAL, "Window is nullptr!");
    CHECK_AND_RETURN_RET_LOG(window->surface != nullptr, AV_ERR_INVALID_VAL, "Input window surface is nullptr!");

    window->surface->Disconnect();
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->SetOutputSurface(window->surface);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Prepare(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerVideoSinkObject *streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Prepare();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_StartDecoder(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->StartDecode();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_StartRenderer(OH_LowPowerVideoSink *streamer)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_StartRenderer");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->StartRender();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Pause(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Pause();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Resume(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Resume();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Flush(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Flush();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Stop(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Stop();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Reset(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Reset();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_Destroy(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->Release();
    MEDIA_LOGI("videostreamer release result is %{public}d", res);
    delete streamerObj->framePacket_;
    delete streamerObj;
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerVideoSink_SetSyncAudioSink(
    OH_LowPowerVideoSink *videoStreamer, OH_LowPowerAudioSink *audioStreamer)
{
    CHECK_AND_RETURN_RET_LOG(videoStreamer != nullptr, AV_ERR_INVALID_VAL, "videoStreamer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(audioStreamer != nullptr, AV_ERR_INVALID_VAL, "audioStreamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(videoStreamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    auto audioStreamerObj = reinterpret_cast<LowPowerAudioSinkObject *>(audioStreamer);
    CHECK_AND_RETURN_RET_LOG(audioStreamerObj != nullptr, AV_ERR_INVALID_VAL, "audioStreamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(
        audioStreamerObj->audioStreamer_ != nullptr, AV_ERR_INVALID_VAL, "audioStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->SetSyncAudioStreamer(audioStreamerObj->audioStreamer_);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_SetTargetStartFrame(OH_LowPowerVideoSink *streamer, const long framePts,
    OH_LowPowerVideoSink_OnTargetArrived onTargetArrived, const long timeoutMs, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    std::shared_ptr<VideoStreamerCallback> cb = streamerObj->videoStreamer_->GetLppVideoStreamerCallback();
    CHECK_AND_RETURN_RET_LOG(cb != nullptr, AV_ERR_INVALID_VAL, "VideoStreamerCallback is nullptr");
    OH_LowPowerVideoSinkCallback *callback = static_cast<OH_LowPowerVideoSinkCallback*>(cb.get());
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr");
    callback->SetTargetArrivedListener(onTargetArrived, userData);
    int32_t res = streamerObj->videoStreamer_->SetTargetStartFrame(framePts, timeoutMs);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_SetPlaybackSpeed(OH_LowPowerVideoSink *streamer, const float speed)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->SetPlaybackSpeed(speed);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_ReturnSamples(OH_LowPowerVideoSink *streamer, OH_AVSamplesBuffer *frames)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(frames != nullptr, AV_ERR_INVALID_VAL, "frames is nullptr");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    AVSamplesBufferObject *framePacket = reinterpret_cast<AVSamplesBufferObject *>(frames);
    CHECK_AND_RETURN_RET_LOG(framePacket != nullptr, AV_ERR_INVALID_VAL, "framePacket is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_ != nullptr, AV_ERR_INVALID_VAL, "lppDataPacket is nullptr");
    CHECK_AND_RETURN_RET_LOG(framePacket->lppDataPacket_->IsEnable(), AV_ERR_INVALID_VAL, "data packet is not in user");
    framePacket->lppDataPacket_->Disable();
    int32_t res = streamerObj->videoStreamer_->ReturnFrames(framePacket->lppDataPacket_);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, LppMsErrToOHAvErr(res), "ReturnFrames failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerVideoSink_RenderFirstFrame(OH_LowPowerVideoSink *streamer)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerVideoSinkObject *streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->RenderFirstFrame();
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_RegisterCallback(
    OH_LowPowerVideoSink *streamer, OH_LowPowerVideoSinkCallback *callback)
{
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    auto streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    callback->SetLowPowerVideoSink(streamer);
    std::shared_ptr<VideoStreamerCallback> callbackPtr(callback);
    int32_t res = streamerObj->videoStreamer_->SetLppVideoStreamerCallback(callbackPtr);
    return LppMsErrToOHAvErr(res);
}

OH_LowPowerVideoSinkCallback *OH_LowPowerVideoSinkCallback_Create()
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_Create");
    OH_LowPowerVideoSinkCallback *callback = new (std::nothrow) OH_LowPowerVideoSinkCallback();
    return callback;
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_Destroy(OH_LowPowerVideoSinkCallback *callback)
{
    MEDIA_LOGD("OH_OH_LowPowerVideoSinkCallback_Destroy");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    return AV_ERR_OK;
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetDataNeededListener(
    OH_LowPowerVideoSinkCallback *callback, OH_LowPowerVideoSink_OnDataNeeded onDataNeeded, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetDataNeededListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onDataNeeded != nullptr, AV_ERR_INVALID_VAL, "onDataNeeded is nullptr!");
    int32_t res = callback->SetDataNeededListener(onDataNeeded, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetErrorListener(
    OH_LowPowerVideoSinkCallback *callback, OH_LowPowerVideoSink_OnError onError, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetErrorListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onError != nullptr, AV_ERR_INVALID_VAL, "onError is nullptr!");
    int32_t res = callback->SetErrorListener(onError, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetRenderStartListener(
    OH_LowPowerVideoSinkCallback *callback, OH_LowPowerVideoSink_OnRenderStarted onRenderStarted, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetRenderStartListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onRenderStarted != nullptr, AV_ERR_INVALID_VAL, "onRenderStarted is nullptr!");
    int32_t res = callback->SetRenderStartListener(onRenderStarted, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetEosListener(
    OH_LowPowerVideoSinkCallback *callback, OH_LowPowerVideoSink_OnEos onEos, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetEosListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onEos != nullptr, AV_ERR_INVALID_VAL, "onEos is nullptr!");
    int32_t res = callback->SetEosListener(onEos, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetStreamChangedListener(
    OH_LowPowerVideoSinkCallback *callback, OH_LowPowerVideoSink_OnStreamChanged onStreamChanged, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetStreamChangedListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onStreamChanged != nullptr, AV_ERR_INVALID_VAL, "onStreamChanged is nullptr!");
    int32_t res = callback->SetStreamChangedListener(onStreamChanged, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSinkCallback_SetFirstFrameDecodedListener(OH_LowPowerVideoSinkCallback *callback,
    OH_LowPowerVideoSink_OnFirstFrameDecoded onFirstFrameDecoded, void *userData)
{
    MEDIA_LOGD("OH_LowPowerVideoSinkCallback_SetFirstFrameDecodedListener");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "callback is nullptr!");
    CHECK_AND_RETURN_RET_LOG(onFirstFrameDecoded != nullptr, AV_ERR_INVALID_VAL, "onFirstFrameDecoded is nullptr!");
    int32_t res = callback->SetFirstFrameReadyListener(onFirstFrameDecoded, userData);
    return LppMsErrToOHAvErr(res);
}

OH_AVErrCode OH_LowPowerVideoSink_GetLatestPts(OH_LowPowerVideoSink *streamer, int64_t *pts)
{
    MEDIA_LOGD("OH_LowPowerVideoSink_GetLatestPts");
    CHECK_AND_RETURN_RET_LOG(streamer != nullptr, AV_ERR_INVALID_VAL, "streamer is nullptr!");
    LowPowerVideoSinkObject *streamerObj = reinterpret_cast<LowPowerVideoSinkObject *>(streamer);
    CHECK_AND_RETURN_RET_LOG(streamerObj != nullptr, AV_ERR_INVALID_VAL, "streamerObj is nullptr");
    CHECK_AND_RETURN_RET_LOG(streamerObj->videoStreamer_ != nullptr, AV_ERR_INVALID_VAL, "videoStreamer_ is nullptr");
    int32_t res = streamerObj->videoStreamer_->GetLatestPts(*pts);
    return LppMsErrToOHAvErr(res);
}

OH_LowPowerAVSink_Capability *OH_LowPowerAVSink_GetCapability()
{
    MEDIA_LOGD("OH_LowPowerAVSink_GetCapability");
    LppAvCapabilityInfo *info = VideoStreamerFactory::GetLppCapacity();
    CHECK_AND_RETURN_RET_LOG(info != nullptr, nullptr, "info is nullptr!");
    std::shared_ptr<LppAvCapabilityInfo> sharedPtr(info);
    info = nullptr;
    CHECK_AND_RETURN_RET_LOG(sharedPtr != nullptr, nullptr, "sharedPtr is nullptr!");
    LowPowerAVSinkCapabilityObject *object = new(std::nothrow) LowPowerAVSinkCapabilityObject(sharedPtr);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "object is nullptr!");
    MEDIA_LOGI("OH_LowPowerAVSink_Capability *OH_LowPowerAVSink_GetCapability() %{public}zu %{public}zu",
        object->lppCapibility_->videoCap_.size(), object->lppCapibility_->audioCap_.size());
    return object;
}
