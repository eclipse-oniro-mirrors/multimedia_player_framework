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

#include "player_client.h"
#include "media_log.h"
#include "media_errors.h"
#include "../media_source/loader/media_loader.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "PlayerClient"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<PlayerClient> PlayerClient::Create(const sptr<IStandardPlayerService> &ipcProxy)
{
    std::shared_ptr<PlayerClient> player = std::make_shared<PlayerClient>(ipcProxy);

    int32_t ret = player->CreateListenerObject();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to create listener object..");

    return player;
}

PlayerClient::PlayerClient(const sptr<IStandardPlayerService> &ipcProxy)
    : playerProxy_(ipcProxy)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

PlayerClient::~PlayerClient()
{
    std::lock_guard<std::mutex> lock(mutex_);
    (void)DisableMonitor();
    callback_ = nullptr;
    listenerStub_ = nullptr;
    if (playerProxy_ != nullptr) {
        (void)playerProxy_->DestroyStub();
        playerProxy_ = nullptr;
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t PlayerClient::CreateListenerObject()
{
    std::lock_guard<std::mutex> lock(mutex_);
    listenerStub_ = new(std::nothrow) PlayerListenerStub();
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, MSERR_NO_MEMORY, "failed to new PlayerListenerStub object");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");

    (void)listenerStub_->SetMonitor(weak_from_this());
    sptr<IRemoteObject> object = listenerStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");

    MEDIA_LOGD("SetListenerObject");
    return playerProxy_->SetListenerObject(object);
}

void PlayerClient::MediaServerDied()
{
    std::shared_ptr<PlayerCallback> callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        playerProxy_ = nullptr;
        listenerStub_ = nullptr;
        callback = callback_;
    }
    
    if (callback != nullptr) {
        callback->OnError(MSERR_SERVICE_DIED,
            "mediaserver is died, please create a new playback instance again");
    }
}

int32_t PlayerClient::SetPlayerProducer(const PlayerProducer producer)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetPlayerProducer %{public}d", FAKE_POINTER(this), producer);
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlayerProducer(producer);
}

int32_t PlayerClient::SetSource(const std::string &url)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetSource url in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetSource(url);
}

int32_t PlayerClient::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetSource dataSrc in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(dataSrc != nullptr, MSERR_NO_MEMORY, "data source is nullptr");

    dataSrcStub_ = new(std::nothrow) MediaDataSourceStub(dataSrc);
    CHECK_AND_RETURN_RET_LOG(dataSrcStub_ != nullptr, MSERR_NO_MEMORY, "failed to new dataSrcStub object");

    sptr<IRemoteObject> object = dataSrcStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");
    return playerProxy_->SetSource(object);
}

int32_t PlayerClient::SetSource(int32_t fd, int64_t offset, int64_t size)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetSource in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetSource(fd, offset, size);
}

int32_t PlayerClient::DisableWhenOK(int32_t ret)
{
    if (ret == MSERR_OK) {
        (void)DisableMonitor();
    }
    return ret;
}

int32_t PlayerClient::AddSubSource(const std::string &url)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->AddSubSource(url);
}

int32_t PlayerClient::AddSubSource(int32_t fd, int64_t offset, int64_t size)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->AddSubSource(fd, offset, size);
}

int32_t PlayerClient::Play()
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " Play in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    (void)EnableMonitor();
    return playerProxy_->Play();
}

int32_t PlayerClient::SetPlayRange(int64_t start, int64_t end)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlayRange(start, end);
}

int32_t PlayerClient::SetPlayRangeWithMode(int64_t start, int64_t end, PlayerSeekMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlayRangeWithMode(start, end, mode);
}

int32_t PlayerClient::SetStartFrameRateOptEnabled(bool enabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetStartFrameRateOptEnabled(enabled);
}

int32_t PlayerClient::Prepare()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Prepare();
}

int32_t PlayerClient::SetRenderFirstFrame(bool display)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetRenderFirstFrame(display);
}

int32_t PlayerClient::PrepareAsync()
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " PrepareAsync in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->PrepareAsync();
}

int32_t PlayerClient::Pause()
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " Pause in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return DisableWhenOK(playerProxy_->Pause());
}

int32_t PlayerClient::Stop()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return DisableWhenOK(playerProxy_->Stop());
}

int32_t PlayerClient::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    dataSrcStub_ = nullptr;
    sourceLoaderStub_ = nullptr;
    dolbyPassthroughStub_ = nullptr;
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return DisableWhenOK(playerProxy_->Reset());
}

int32_t PlayerClient::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = nullptr;
    listenerStub_ = nullptr;
    dataSrcStub_ = nullptr;
    dolbyPassthroughStub_ = nullptr;
    sourceLoaderStub_ = nullptr;
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return DisableWhenOK(playerProxy_->Release());
}

int32_t PlayerClient::ReleaseSync()
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = nullptr;
    listenerStub_ = nullptr;
    dataSrcStub_ = nullptr;
    sourceLoaderStub_ = nullptr;
    dolbyPassthroughStub_ = nullptr;
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return DisableWhenOK(playerProxy_->ReleaseSync());
}

int32_t PlayerClient::SetVolume(float leftVolume, float rightVolume)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetVolume(leftVolume, rightVolume);
}

int32_t PlayerClient::SetVolumeMode(int32_t mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetVolumeMode(mode);
}

int32_t PlayerClient::Seek(int32_t mSeconds, PlayerSeekMode mode)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " Seek in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->Seek(mSeconds, mode);
}

int32_t PlayerClient::GetCurrentTime(int32_t &currentTime)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetCurrentTime(currentTime);
}

int32_t PlayerClient::GetPlaybackPosition(int32_t &playbackPosition)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetPlaybackPosition(playbackPosition);
}

int32_t PlayerClient::GetCurrentPresentationTimestamp(int64_t &currentPresentation)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetCurrentPresentationTimestamp(currentPresentation);
}

int32_t PlayerClient::GetVideoTrackInfo(std::vector<Format> &videoTrack)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetVideoTrackInfo(videoTrack);
}

int32_t PlayerClient::SetSeiMessageCbStatus(bool status, const std::vector<int32_t> &payloadTypes)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerProxy_->SetSeiMessageCbStatus(status, payloadTypes);
}

int32_t PlayerClient::GetPlaybackInfo(Format &playbackInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetPlaybackInfo(playbackInfo);
}

int32_t PlayerClient::GetPlaybackStatisticMetrics(Format &playbackStatisticMetrics)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetPlaybackStatisticMetrics(playbackStatisticMetrics);
}

int32_t PlayerClient::GetAudioTrackInfo(std::vector<Format> &audioTrack)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetAudioTrackInfo(audioTrack);
}

int32_t PlayerClient::GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetSubtitleTrackInfo(subtitleTrack);
}

int32_t PlayerClient::GetVideoWidth()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetVideoWidth();
}

int32_t PlayerClient::GetVideoHeight()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetVideoHeight();
}

int32_t PlayerClient::SetPlaybackSpeed(PlaybackRateMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlaybackSpeed(mode);
}

int32_t PlayerClient::SetPlaybackRate(float rate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlaybackRate(rate);
}

int32_t PlayerClient::SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetMediaSource in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(mediaSource != nullptr, MSERR_INVALID_VAL, "mediaSource is nullptr!");
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");

    bool isCacheAble = mediaSource->GetenableOfflineCache();
    if (mediaSource->mediaSourceLoaderCb_ != nullptr && mediaSource->GetenableOfflineCache()) {
        MEDIA_LOGE("Cannot set local cache and proxy download at the same time.");
        mediaSource->sourceLoader_ = nullptr;
        return playerProxy_->SetMediaSource(mediaSource, strategy);
    }

    if (mediaSource->mediaSourceLoaderCb_ != nullptr) {
        MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " mediaSource->mediaSourceLoaderCb_ in", FAKE_POINTER(this));
        sourceLoaderStub_ = new(std::nothrow) MediaSourceLoaderStub(mediaSource->mediaSourceLoaderCb_);
        CHECK_AND_RETURN_RET_LOG(sourceLoaderStub_ != nullptr, MSERR_NO_MEMORY, "failed to new LoaderStub object");
 
        sptr<IRemoteObject> object = sourceLoaderStub_->AsObject();
        CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");
 
        CHECK_AND_RETURN_RET_LOG(playerProxy_->SetSourceLoader(object) == MSERR_OK,
            MSERR_UNKNOWN, "SetSourceLoader error");
    } else {
        if (isCacheAble) {
            std::shared_ptr<LoaderCallback> mediaSourceLoaderCb = std::make_shared<MediaLoader>(mediaSource->url);
            mediaSource->mediaSourceLoaderCb_ = mediaSourceLoaderCb;

            MEDIA_LOGI("PlayerClient:0x%{public}06" PRIXPTR
                " mediaSource->mediaSourceLoaderCb_ in", FAKE_POINTER(this));
            sourceLoaderStub_ = new(std::nothrow) MediaSourceLoaderStub(mediaSource->mediaSourceLoaderCb_);
            CHECK_AND_RETURN_RET_LOG(sourceLoaderStub_ != nullptr, MSERR_NO_MEMORY, "failed to new LoaderStub object");

            sptr<IRemoteObject> object = sourceLoaderStub_->AsObject();
            CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");

            CHECK_AND_RETURN_RET_LOG(playerProxy_->SetSourceLoader(object) == MSERR_OK,
                MSERR_UNKNOWN, "Custom SetSourceLoader error");
        }
    }
    MEDIA_LOGD("url_=%{private}s playMediaStreamVec_size=%{public}zu mimeType_=%{public}s",
        mediaSource->url.c_str(),
        mediaSource->GetAVPlayMediaStreamList().size(),
        mediaSource->GetMimeType().c_str());
    return playerProxy_->SetMediaSource(mediaSource, strategy);
}

int32_t PlayerClient::GetPlaybackSpeed(PlaybackRateMode &mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetPlaybackSpeed(mode);
}

int32_t PlayerClient::GetPlaybackRate(float &rate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetPlaybackRate(rate);
}

int32_t PlayerClient::SelectBitRate(uint32_t bitRate)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SelectBitRate(bitRate);
}

int32_t PlayerClient::GetDuration(int32_t &duration)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetDuration(duration);
}

int32_t PlayerClient::GetApiVersion(int32_t &apiVersion)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetApiVersion(apiVersion);
}

#ifdef SUPPORT_VIDEO
int32_t PlayerClient::SetVideoSurface(sptr<Surface> surface)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_NO_MEMORY, "surface is nullptr..");
    return playerProxy_->SetVideoSurface(surface);
}
#endif

bool PlayerClient::IsPlaying()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, false, "player service does not exist..");
    return playerProxy_->IsPlaying();
}

bool PlayerClient::IsLooping()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, false, "player service does not exist..");
    return playerProxy_->IsLooping();
}

int32_t PlayerClient::SetLooping(bool loop)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLooping(loop);
}

int32_t PlayerClient::SetParameter(const Format &param)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetParameter(param);
}

int32_t PlayerClient::SetPlayerCallback(const std::shared_ptr<PlayerCallback> &callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "input param callback is nullptr..");
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, MSERR_NO_MEMORY, "listenerStub_ is nullptr..");

    callback_ = callback;
    listenerStub_->SetPlayerCallback(callback);

    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetPlayerCallback();
}

int32_t PlayerClient::SelectTrack(int32_t index, PlayerSwitchMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SelectTrack(index, mode);
}

int32_t PlayerClient::DeselectTrack(int32_t index)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->DeselectTrack(index);
}

int32_t PlayerClient::GetCurrentTrack(int32_t trackType, int32_t &index)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetCurrentTrack(trackType, index);
}


int32_t PlayerClient::SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp)
{
    MEDIA_LOGI("PlayerClient SetDecryptConfig");
#ifdef SUPPORT_AVPLAYER_DRM
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(keySessionProxy != nullptr, MSERR_NO_MEMORY, "keySessionProxy is nullptr..");
    return playerProxy_->SetDecryptConfig(keySessionProxy, svp);
#else
    (void)keySessionProxy;
    (void)svp;
    return 0;
#endif
}

int32_t PlayerClient::SetDeviceChangeCbStatus(bool status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerProxy_->SetDeviceChangeCbStatus(status);
}

int32_t PlayerClient::SetPlaybackStrategy(AVPlayStrategy playbackStrategy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_INVALID_VAL, "playerProxy_ not exist");
    return playerProxy_->SetPlaybackStrategy(playbackStrategy);
}

int32_t PlayerClient::SetMediaMuted(OHOS::Media::MediaType mediaType, bool isMuted)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_INVALID_VAL, "playerProxy_ not exist");
    return playerProxy_->SetMediaMuted(mediaType, isMuted);
}

int32_t PlayerClient::SetSuperResolution(bool enabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetSuperResolution(enabled);
}

int32_t PlayerClient::SetVideoWindowSize(int32_t width, int32_t height)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetVideoWindowSize(width, height);
}

int32_t PlayerClient::SetMaxAmplitudeCbStatus(bool status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerProxy_->SetMaxAmplitudeCbStatus(status);
}

bool PlayerClient::IsSeekContinuousSupported()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, false, "player service does not exist.");
    return playerProxy_->IsSeekContinuousSupported();
}

int32_t PlayerClient::SetReopenFd(int32_t fd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist.");
    return playerProxy_->SetReopenFd(fd);
}
 
int32_t PlayerClient::EnableCameraPostprocessing()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->EnableCameraPostprocessing();
}

int32_t PlayerClient::SetCameraPostprocessing(bool isOpen)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " SetCameraPostprocessing in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetCameraPostprocessing(isOpen);
}

int32_t PlayerClient::EnableReportMediaProgress(bool enable)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " EnableReportMediaProgress in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->EnableReportMediaProgress(enable);
}

int32_t PlayerClient::EnableReportAudioInterrupt(bool enable)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " EnableReportAudioInterrupt in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->EnableReportAudioInterrupt(enable);
}

int32_t PlayerClient::ForceLoadVideo(bool status)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->ForceLoadVideo(status);
}

int32_t PlayerClient::SetLoudnessGain(float loudnessGain)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->SetLoudnessGain(loudnessGain);
}

int32_t PlayerClient::GetGlobalInfo(std::shared_ptr<Meta> &globalInfo)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " GetGlobalInfo in", FAKE_POINTER(this));
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetGlobalInfo(globalInfo);
}

int32_t PlayerClient::GetMediaDescription(Format &format)
{
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetMediaDescription(format);
}

int32_t PlayerClient::GetTrackDescription(Format &format, uint32_t trackIndex)
{
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    return playerProxy_->GetTrackDescription(format, trackIndex);
}

int32_t PlayerClient::RegisterDeviceCapability(IsAudioPassthrough callback, GetDolbyList getDolbyList)
{
    MEDIA_LOGD("PlayerClient:0x%{public}06" PRIXPTR " RegisterDeviceCapability", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(playerProxy_ != nullptr, MSERR_SERVICE_DIED, "player service does not exist..");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_NO_MEMORY, "isAudioPassthrough is nullptr");
    CHECK_AND_RETURN_RET_LOG(getDolbyList != nullptr, MSERR_NO_MEMORY, "getDolbyList is nullptr");
    dolbyPassthroughStub_ = new(std::nothrow) DolbyPassthroughStub(callback, getDolbyList);
    
    CHECK_AND_RETURN_RET_LOG(dolbyPassthroughStub_ != nullptr, MSERR_NO_MEMORY,
        "failed to new dolbyPassthroughStub object");
    sptr<IRemoteObject> object = dolbyPassthroughStub_->AsObject();
    CHECK_AND_RETURN_RET_LOG(object != nullptr, MSERR_NO_MEMORY, "listener object is nullptr..");
    return playerProxy_->RegisterDeviceCapability(object);
}
} // namespace Media
} // namespace OHOS