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

#ifndef PLAYER_SERVICE_STUB_H
#define PLAYER_SERVICE_STUB_H

#include <map>
#include <gmock/gmock.h>
#include "i_standard_player_service.h"
#include "i_standard_player_listener.h"
#include "media_death_recipient.h"
#include "player_server.h"
#include "monitor_server_object.h"
#include "media_source.h"

namespace OHOS {
namespace Media {
using PlayerStubFunc = std::function<int32_t (MessageParcel &, MessageParcel &)>;
constexpr int32_t TEST_NUM = 1234;
class PlayerServiceStub
    : public IRemoteStub<IStandardPlayerService>,
      public MonitorServerObject,
      public NoCopyable {
public:
    static sptr<PlayerServiceStub> Create()
    {
        sptr<PlayerServiceStub> playerStub = new(std::nothrow) PlayerServiceStub();
        return playerStub;
    }
    virtual ~PlayerServiceStub() = default;

    MOCK_METHOD(int, OnRemoteRequest, (uint32_t code, MessageParcel &data,
        MessageParcel &reply, MessageOption &option), (override));
    MOCK_METHOD(int32_t, SetPlayerProducer, (const PlayerProducer producer), (override));
    MOCK_METHOD(int32_t, AddSubSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, Play, (), (override));
    MOCK_METHOD(int32_t, SetSource, ((const sptr<IRemoteObject> &object)), (override));
    MOCK_METHOD(int32_t, SetListenerObject, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
    MOCK_METHOD(int32_t, SetSource, (const std::string &url), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, Seek, (int32_t mSeconds, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, AddSubSource, (int32_t fd, int64_t offset, int64_t size), (override));
    MOCK_METHOD(int32_t, SetRenderFirstFrame, (bool display), (override));
    MOCK_METHOD(int32_t, SetPlayRange, (int64_t start, int64_t end), (override));
    MOCK_METHOD(int32_t, SetPlayRangeWithMode, (int64_t start, int64_t end, PlayerSeekMode mode), (override));
    MOCK_METHOD(int32_t, PrepareAsync, (), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, SetVolume, (float leftVolume, float rightVolume), (override));
    MOCK_METHOD(int32_t, SetVolumeMode, (int32_t mode), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (PlaybackRateMode mode), (override));
    MOCK_METHOD(int32_t, SetPlaybackRate, (float rate), (override));
    MOCK_METHOD(int32_t, GetVideoWidth, (), (override));
    MOCK_METHOD(int32_t, GetAudioTrackInfo, (std::vector<Format> &audioTrack), (override));
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), (override));
    MOCK_METHOD(int32_t, GetPlaybackPosition, (int32_t &playbackPosition), (override));
    MOCK_METHOD(int32_t, GetVideoTrackInfo, (std::vector<Format> &videoTrack), (override));
    MOCK_METHOD(int32_t, GetPlaybackInfo, (Format &playbackInfo), (override));
    MOCK_METHOD(int32_t, GetPlaybackStatisticMetrics, (Format &playbackStatisticMetrics), (override));
    MOCK_METHOD(int32_t, GetPlaybackSpeed, (PlaybackRateMode &mode), (override));
    MOCK_METHOD(int32_t, GetSubtitleTrackInfo, (std::vector<Format> &subtitleTrack), (override));
    MOCK_METHOD(int32_t, GetVideoHeight, (), (override));
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), (override));
    MOCK_METHOD(int32_t, GetApiVersion, (int32_t &apiVersion), (override));
    MOCK_METHOD(int32_t, SetPlaybackStrategy, (AVPlayStrategy playbackStrategy), (override));
    MOCK_METHOD(int32_t, SetMediaMuted, (OHOS::Media::MediaType mediaType, bool isMuted), (override));
    MOCK_METHOD(int32_t, SetSuperResolution, (bool enabled), (override));
    MOCK_METHOD(int32_t, SetVideoWindowSize, (int32_t width, int32_t height), (override));
    MOCK_METHOD(int32_t, Freeze, (), ());
    MOCK_METHOD(int32_t, UnFreeze, (), ());
#ifdef SUPPORT_VIDEO
    MOCK_METHOD(int32_t, SetVideoSurface, ((sptr<Surface> surface)), (override));
#endif
    MOCK_METHOD(int32_t, SetLooping, (bool loop), (override));
    MOCK_METHOD(int32_t, SetParameter, (const Format &param), (override));
    MOCK_METHOD(int32_t, SelectBitRate, (uint32_t bitRate), (override));
    MOCK_METHOD(int32_t, SelectTrack, (int32_t index, PlayerSwitchMode mode), (override));
    MOCK_METHOD(int32_t, DestroyStub, (), (override));
    MOCK_METHOD(int32_t, SetPlayerCallback, (), (override));
    MOCK_METHOD(int32_t, DumpInfo, (int32_t fd), ());
    MOCK_METHOD(int32_t, DeselectTrack, (int32_t index), (override));
    MOCK_METHOD(int32_t, GetCurrentTrack, (int32_t trackType, int32_t &index), (override));
    MOCK_METHOD(int32_t, SetSourceLoader, (const sptr<IRemoteObject> &object), (override));
    MOCK_METHOD(int32_t, SetMediaSource, (const std::shared_ptr<AVMediaSource> &mediaSource,
        AVPlayStrategy strategy), (override));
    MOCK_METHOD(bool, IsPlaying, (), (override));
    MOCK_METHOD(bool, IsLooping, (), (override));
    MOCK_METHOD(int32_t, SetDecryptConfig,
        (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp), (override));
    MOCK_METHOD(int32_t, DoIpcAbnormality, (), (override));
    MOCK_METHOD(int32_t, DoIpcRecovery, (bool fromMonitor), (override));
    MOCK_METHOD(int32_t, SetDeviceChangeCbStatus, (bool status), (override));
    MOCK_METHOD(int32_t, SetMaxAmplitudeCbStatus, (bool status), (override));
    MOCK_METHOD(bool, IsSeekContinuousSupported, (), (override));
    MOCK_METHOD(int32_t, SetSeiMessageCbStatus, (bool status, const std::vector<int32_t> &payloadTypes), (override));
    MOCK_METHOD(int32_t, SetStartFrameRateOptEnabled, (bool enabled), (override));
    uint32_t GetMemoryUsage()
    {
        return TEST_NUM;
    }
    MOCK_METHOD(int32_t, SetReopenFd, (int32_t fd), (override));
    MOCK_METHOD(int32_t, EnableCameraPostprocessing, (), (override));
    MOCK_METHOD(int32_t, EnableReportMediaProgress, (bool enable), (override));
    MOCK_METHOD(int32_t, EnableReportAudioInterrupt, (bool enable), (override));
    MOCK_METHOD(int32_t, ForceLoadVideo, (bool status), (override));
    virtual int32_t Init()
    {
        return 0;
    }
};
} // namespace Media
} // namespace OHOS
#endif // PLAYER_SERVICE_STUB_H
