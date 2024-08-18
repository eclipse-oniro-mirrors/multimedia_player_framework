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

#ifndef PLAYER_SERVICE_PROXY_H
#define PLAYER_SERVICE_PROXY_H

#include "i_standard_player_service.h"
#include "media_parcel.h"

namespace OHOS {
namespace Media {
class PlayerServiceProxy : public IRemoteProxy<IStandardPlayerService> {
public:
    explicit PlayerServiceProxy(const sptr<IRemoteObject> &impl);
    virtual ~PlayerServiceProxy();
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override;
    int32_t SetSource(const std::string &url) override;
    int32_t Reset() override;
    int32_t Prepare() override;
    int32_t Pause() override;
    int32_t SetSource(const sptr<IRemoteObject> &object) override;
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size) override;
    int32_t SetRenderFirstFrame(bool display) override;
    int32_t SetPlayRange(int64_t start, int64_t end) override;
    int32_t PrepareAsync() override;
    int32_t Play() override;
    int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) override;
    int32_t AddSubSource(const std::string &url) override;
    int32_t SetPlaybackSpeed(PlaybackRateMode mode) override;
    int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) override;
    int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) override;
    int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) override;
    int32_t Stop() override;
    int32_t GetPlaybackSpeed(PlaybackRateMode &mode) override;
    int32_t Release() override;
    int32_t GetVideoHeight() override;
    int32_t ReleaseSync() override;
    int32_t GetVideoWidth() override;
    int32_t SetVolume(float leftVolume, float rightVolume) override;
    int32_t GetCurrentTime(int32_t &currentTime) override;
    int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) override;
    int32_t GetPlaybackInfo(Format& playbackInfo) override;
    int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) override;
    int32_t GetDuration(int32_t &duration) override;
#ifdef SUPPORT_VIDEO
    int32_t SetVideoSurface(sptr<Surface> surface) override;
#endif
    bool IsPlaying() override;
    bool IsLooping() override;
    int32_t GetCurrentTrack(int32_t trackType, int32_t &index) override;
    int32_t SetPlayerCallback() override;
    int32_t SelectBitRate(uint32_t bitRate) override;
    int32_t SelectTrack(int32_t index, PlayerSwitchMode mode) override;
    int32_t SetLooping(bool loop) override;
    int32_t SetParameter(const Format &param) override;
    int32_t DeselectTrack(int32_t index) override;
    int32_t DestroyStub() override;
    int32_t SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp) override;
private:
    int32_t SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
    static inline BrokerDelegator<PlayerServiceProxy> delegator_;
    std::map<uint32_t, std::string> playerFuncs_;
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_SERVICE_PROXY_H
