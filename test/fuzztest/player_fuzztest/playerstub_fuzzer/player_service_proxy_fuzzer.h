/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef PLAYER_SERVICE_PROXY_FUZZER_H
#define PLAYER_SERVICE_PROXY_FUZZER_H

#include "stub_common.h"
#include "i_standard_player_service.h"

namespace OHOS {
namespace Media {
class PlayerServiceProxyFuzzer : public IRemoteProxy<IStandardPlayerService> {
public:
    static sptr<PlayerServiceProxyFuzzer> Create();
    explicit PlayerServiceProxyFuzzer(const sptr<IRemoteObject> &impl);
    virtual ~PlayerServiceProxyFuzzer() {}
    void SendRequest(uint32_t code, uint8_t *inputData, size_t size, bool isFuzz);
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override
    {
        return 0;
    }
    int32_t SetSource(const std::string &url) override
    {
        return 0;
    }
    int32_t SetSource(const sptr<IRemoteObject> &object) override
    {
        return 0;
    }
    int32_t SetSource(int32_t fd, int64_t offset, int64_t size) override
    {
        return 0;
    }
    int32_t SetMediaSource(const std::shared_ptr<AVMediaSource> &mediaSource, AVPlayStrategy strategy) override
    {
        return 0;
    }
    int32_t SetSourceLoader(const sptr<IRemoteObject> &object) override
    {
        return 0;
    }
    int32_t AddSubSource(const std::string &url) override
    {
        return 0;
    }
    int32_t AddSubSource(int32_t fd, int64_t offset, int64_t size) override
    {
        return 0;
    }
    int32_t Play() override
    {
        return 0;
    }
    int32_t Prepare() override
    {
        return 0;
    }
    int32_t PrepareAsync() override
    {
        return 0;
    }
    int32_t Pause() override
    {
        return 0;
    }
    int32_t Stop() override
    {
        return 0;
    }
    int32_t Reset() override
    {
        return 0;
    }
    int32_t Release() override
    {
        return 0;
    }
    int32_t ReleaseSync() override
    {
        return 0;
    }
    int32_t SetVolume(float leftVolume, float rightVolume) override
    {
        return 0;
    }
    int32_t SetVolumeMode(int32_t mode) override
    {
        return 0;
    }
    int32_t Seek(int32_t mSeconds, PlayerSeekMode mode) override
    {
        return 0;
    }
    int32_t GetCurrentTime(int32_t &currentTime) override
    {
        return 0;
    }
    int32_t GetVideoTrackInfo(std::vector<Format> &videoTrack) override
    {
        return 0;
    }
    int32_t GetPlaybackInfo(Format& playbackInfo) override
    {
        return 0;
    }
    int32_t GetAudioTrackInfo(std::vector<Format> &audioTrack) override
    {
        return 0;
    }
    int32_t GetSubtitleTrackInfo(std::vector<Format> &subtitleTrack) override
    {
        return 0;
    }
    int32_t GetVideoWidth() override
    {
        return 0;
    }
    int32_t GetVideoHeight() override
    {
        return 0;
    }
    int32_t GetDuration(int32_t &duration) override
    {
        return 0;
    }
    int32_t SetPlaybackSpeed(PlaybackRateMode mode) override
    {
        return 0;
    }
    int32_t GetPlaybackSpeed(PlaybackRateMode &mode) override
    {
        return 0;
    }
    int32_t SetVideoSurface(sptr<Surface> surface) override
    {
        return 0;
    }
    bool IsPlaying() override
    {
        return 0;
    }
    bool IsLooping() override
    {
        return 0;
    }
    int32_t SetLooping(bool loop) override
    {
        return 0;
    }
    int32_t SetParameter(const Format &param) override
    {
        return 0;
    }
    int32_t DestroyStub() override
    {
        return 0;
    }
    int32_t SetPlayerCallback() override
    {
        return 0;
    }
    int32_t SelectBitRate(uint32_t bitRate) override
    {
        return 0;
    }
    int32_t SelectTrack(int32_t index, PlayerSwitchMode mode) override
    {
        return 0;
    }
    int32_t DeselectTrack(int32_t index) override
    {
        return 0;
    }
    int32_t GetCurrentTrack(int32_t trackType, int32_t &index) override
    {
        return 0;
    }
    int32_t SetDecryptConfig(const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy,
        bool svp) override
    {
        return 0;
    }
    int32_t SetMediaMuted(MediaType mediaType, bool isMuted) override
    {
        return 0;
    }
    static int32_t SetListenerObjectStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetMediaDataSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
        bool isFuzz);
    static int32_t SetFdSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t AddSubSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t AddSubFdSourceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t PlayStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t PrepareStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t PrepareAsyncStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t PauseStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t StopStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t ResetStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t ReleaseStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetVolumeStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SeekStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetCurrentTimeStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetPlaybackPositionStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
        bool isFuzz);
    static int32_t GetDurationStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetPlaybackSpeedStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetPlaybackSpeedStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetVideoSurfaceStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t IsPlayingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t IsLoopingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetLoopingStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetParameterStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t DestroyStubStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SetPlayerCallbackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetVideoTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetPlaybackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetAudioTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetSubtitleTrackInfoStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size,
        bool isFuzz);
    static int32_t GetVideoWidthStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetVideoHeightStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SelectBitRateStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t SelectTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t DeselectTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);
    static int32_t GetCurrentTrackStatic(PlayerServiceProxyFuzzer* ptr, uint8_t *inputData, size_t size, bool isFuzz);

private:
    int32_t SendRequest(uint32_t code, MessageParcel &inputData, MessageParcel &reply, MessageOption &option);
    static inline BrokerDelegator<PlayerServiceProxyFuzzer> delegator_;
};
}
}

#endif // PLAYER_SERVICE_PROXY_FUZZER_H

