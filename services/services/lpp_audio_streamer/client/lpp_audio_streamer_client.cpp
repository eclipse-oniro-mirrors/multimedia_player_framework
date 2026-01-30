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

#include "lpp_audio_streamer_client.h"
#include "media_log.h"
#include "media_errors.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "LppAudioStreamerClient"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<LppAudioStreamerClient> LppAudioStreamerClient::Create(
    const sptr<IStandardLppAudioStreamerService> &ipcProxy)
{
    std::shared_ptr<LppAudioStreamerClient> lppAudioPlayer = std::make_shared<LppAudioStreamerClient>(ipcProxy);

    lppAudioPlayer->CreateListenerObject();

    return lppAudioPlayer;
}

LppAudioStreamerClient::LppAudioStreamerClient(const sptr<IStandardLppAudioStreamerService> &ipcProxy)
    : playerProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

LppAudioStreamerClient::~LppAudioStreamerClient()
{
    std::lock_guard<std::mutex> lock(mutex_);
}

int32_t LppAudioStreamerClient::Init(const std::string &mime)
{
    MEDIA_LOGD("LppAudioStreamerClient::Init");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Init(mime);
}

int32_t LppAudioStreamerClient::SetParameter(const Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetParameter(param);
}

int32_t LppAudioStreamerClient::Configure(const Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Configure(param);
}

int32_t LppAudioStreamerClient::Prepare()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Prepare();
}

int32_t LppAudioStreamerClient::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Start();
}

int32_t LppAudioStreamerClient::Pause()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Pause();
}

int32_t LppAudioStreamerClient::Resume()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Resume();
}

int32_t LppAudioStreamerClient::Flush()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Flush();
}

int32_t LppAudioStreamerClient::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Stop();
}

int32_t LppAudioStreamerClient::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Reset();
}

int32_t LppAudioStreamerClient::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Release();
}

int32_t LppAudioStreamerClient::SetVolume(float volume)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetVolume(volume);
}

int32_t LppAudioStreamerClient::SetLoudnessGain(const float loudnessGain)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLoudnessGain(loudnessGain);
}

int32_t LppAudioStreamerClient::SetPlaybackSpeed(float speed)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlaybackSpeed(speed);
}

int32_t LppAudioStreamerClient::ReturnFrames(sptr<LppDataPacket> framePacket)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->ReturnFrames(framePacket);
}

int32_t LppAudioStreamerClient::RegisterCallback()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->RegisterCallback();
}

int32_t LppAudioStreamerClient::SetLppAudioStreamerCallback(const std::shared_ptr<AudioStreamerCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "input param callback is nullptr..");
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, MSERR_NO_MEMORY, "listenerStub_ is nullptr..");
    callback_ = callback;
    listenerStub_->SetLppAudioStreamerCallback(callback);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLppAudioStreamerCallback();
}

int32_t LppAudioStreamerClient::CreateListenerObject()
{
    std::lock_guard<std::mutex> lock(mutex_);
    listenerStub_ = new (std::nothrow) LppAudioStreamerListenerStub();
    CHECK_AND_RETURN_RET_LOG(
        listenerStub_ != nullptr, MSERR_NO_MEMORY, "failed to new LppAudioStreamListenerStub object");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");

    sptr<IRemoteObject> object = listenerStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");
    return playerProxy_->SetListenerObject(object);
}

int32_t LppAudioStreamerClient::SetLppVideoStreamerId(const std::string videoStreamId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLppVideoStreamerId(videoStreamId);
}

std::string LppAudioStreamerClient::GetStreamerId()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, "", "player service does not exist..");
    return playerProxy_->GetStreamerId();
}

void LppAudioStreamerClient::MediaServerDied()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        playerProxy_ = nullptr;
        listenerStub_ = nullptr;
    }
    CHECK_AND_RETURN(callback_ != nullptr);
    callback_->OnError(MSERR_SERVICE_DIED,
        "mediaserver is died, please create a new audio sink instance again");
}
}  // namespace Media
}  // namespace OHOS