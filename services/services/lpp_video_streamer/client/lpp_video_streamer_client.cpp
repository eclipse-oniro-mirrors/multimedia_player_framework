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

#include "lpp_video_streamer_client.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppVideoStreamerClient"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<LppVideoStreamerClient> LppVideoStreamerClient::Create(
    const sptr<IStandardLppVideoStreamerService> &ipcProxy)
{
    std::shared_ptr<LppVideoStreamerClient> lppAudioPlayer = std::make_shared<LppVideoStreamerClient>(ipcProxy);

    lppAudioPlayer->CreateListenerObject();

    return lppAudioPlayer;
}

LppVideoStreamerClient::LppVideoStreamerClient(const sptr<IStandardLppVideoStreamerService> &ipcProxy)
    : playerProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppVideoStreamerClient::~LppVideoStreamerClient()
{
    std::lock_guard<std::mutex> lock(mutex_);
}

int32_t LppVideoStreamerClient::Init(const std::string &mime)
{
    MEDIA_LOGD("LppVideoStreamerClient::Init");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Init(mime);
}

int32_t LppVideoStreamerClient::SetParameter(const Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetParameter(param);
}
 
int32_t LppVideoStreamerClient::GetParameter(Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetParameter(param);
}
 
int32_t LppVideoStreamerClient::Configure(const Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Configure(param);
}

int32_t LppVideoStreamerClient::Prepare()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Prepare();
}

int32_t LppVideoStreamerClient::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Start();
}

int32_t LppVideoStreamerClient::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Pause();
}

int32_t LppVideoStreamerClient::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Resume();
}

int32_t LppVideoStreamerClient::Flush()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Flush();
}

int32_t LppVideoStreamerClient::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Stop();
}

int32_t LppVideoStreamerClient::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Reset();
}

int32_t LppVideoStreamerClient::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Release();
}

int32_t LppVideoStreamerClient::StartDecode()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->StartDecode();
}

int32_t LppVideoStreamerClient::StartRender()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->StartRender();
}

int32_t LppVideoStreamerClient::SetOutputSurface(sptr<Surface> surface)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetOutputSurface(std::move(surface));
}

int32_t LppVideoStreamerClient::SetSyncAudioStreamer(AudioStreamer *audioStreamer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetSyncAudioStreamer(audioStreamer);
}

int32_t LppVideoStreamerClient::SetTargetStartFrame(const int64_t targetPts, const int timeoutMs)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetTargetStartFrame(targetPts, timeoutMs);
}

int32_t LppVideoStreamerClient::SetVolume(float volume)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetVolume(volume);
}

int32_t LppVideoStreamerClient::SetPlaybackSpeed(float speed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlaybackSpeed(speed);
}

int32_t LppVideoStreamerClient::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->ReturnFrames(framePacket);
}

int32_t LppVideoStreamerClient::RegisterCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->RegisterCallback();
}

int32_t LppVideoStreamerClient::SetLppVideoStreamerCallback(const std::shared_ptr<VideoStreamerCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input param callback is nullptr..");
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, MSERR_NO_MEMORY, "listenerStub_ is nullptr..");
    callback_ = callback;
    listenerStub_->SetLppVideoStreamerCallback(callback);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLppVideoStreamerCallback();
}

int32_t LppVideoStreamerClient::CreateListenerObject()
{
    std::lock_guard<std::mutex> lock(mutex_);
    listenerStub_ = new (std::nothrow) LppVideoStreamerListenerStub();
    CHECK_AND_RETURN_RET_LOG(
        listenerStub_ != nullptr, MSERR_NO_MEMORY, "failed to new LppAudioStreamListenerStub object");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");
    return playerProxy_->SetListenerObject(object);
}

int32_t LppVideoStreamerClient::SetLppAudioStreamerId(const std::string videoStreamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLppAudioStreamerId(videoStreamId);
}

std::string LppVideoStreamerClient::GetStreamerId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, "", "player service does not exist..");
    return playerProxy_->GetStreamerId();
}

int32_t LppVideoStreamerClient::RenderFirstFrame()
{
    MEDIA_LOGI("LppVideoStreamerClient::RenderFirstFrame");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_INVALID_OPERATION, "player service does not exist..");
    auto ret = playerProxy_->RenderFirstFrame();
    return ret;
}

void LppVideoStreamerClient::MediaServerDied()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        playerProxy_ = nullptr;
        listenerStub_ = nullptr;
    }
    if (callback_ != nullptr) {
        callback_->OnError(MSERR_SERVICE_DIED,
            "mediaserver is died, please create a new video sink instance again");
    }
}

int32_t LppVideoStreamerClient::GetLatestPts(int64_t &pts)
{
    MEDIA_LOGI("LppVideoStreamerClient GetLatestPts");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED,
        "LppVideoStreamerClient GetLatestPts player service does not exist.");
    int32_t ret = playerProxy_->GetLatestPts(pts);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "LppVideoStreamerClient GetLatestPts failed.");
    return MSERR_OK;
}
}  // namespace Media
}  // namespace OHOS