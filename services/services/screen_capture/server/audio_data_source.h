/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef AUDIO_DATA_SOURCE_H
#define AUDIO_DATA_SOURCE_H

#include "audio_capturer_wrapper.h"
#include "audio_stream_manager.h"
#include "media_data_source.h"

namespace OHOS::Media {
using namespace AudioStandard;

class ScreenCaptureServer;

// clang-format off
enum class AVScreenCaptureMixMode : int32_t {
    MIX_MODE = 0,
    MIC_MODE = 1,
    INNER_MODE = 2,
    INVALID_MODE = 3
};
// clang-format on

enum class AVScreenCaptureMixBufferType : int32_t {
    MIX = 0,
    MIC = 1,
    INNER = 2,
    SILENT = 3,
    INVALID = 4,
};

class AudioDataSource : public IAudioDataSource,
                        public AudioBufferAvailableCallback,
                        public std::enable_shared_from_this<AudioDataSource> {
public:
    AudioDataSource(AVScreenCaptureMixMode type, ScreenCaptureServer *screenCaptureServer)
        : type_(type), screenCaptureServer_(screenCaptureServer)
    {
    }
    ~AudioDataSource() override;

    AudioDataSourceReadAtActionState ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override;
    int32_t GetSize(int64_t &size) override;
    void SetVideoFirstFramePts(int64_t firstFramePts) override;
    void SetListener(std::shared_ptr<IAudioDataSourceListener> listener) override;
    void OnBufferAvailable(AudioCaptureSourceType type) override;
    void MixAudio(const CacheBuffer &inner, const CacheBuffer &mic, uint8_t *out, int32_t channels);
    int32_t RegisterAudioRendererEventListener(const int32_t clientPid,
        const std::shared_ptr<AudioRendererStateChangeCallback> &callback);
    int32_t UnregisterAudioRendererEventListener(const int32_t clientPid);
    void SetAppPid(int32_t appid);
    int32_t GetAppPid();
    uint32_t GetAudioRendererState();
    void SetAudioRendererState(uint32_t state);
    bool IsInWaitMicSyncState();
    void Pause();
    void Resume();
    void SetInnerCapture(std::shared_ptr<AudioCapturerWrapper> capture);
    void SetMicCapture(std::shared_ptr<AudioCapturerWrapper> capture);
    inline AVScreenCaptureMixMode GetType() const
    {
        return type_;
    }

private:
    void NotifyDataReady();
    int64_t GetFirstAudioTime(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void SetAudioFirstFramePts(int64_t firstFramePts);
    AudioDataSourceReadAtActionState MixModeBufferWrite(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void HandlePastMicBuffer(std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void HandleSwitchToSpeakerOptimise(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void HandleBufferTimeStamp(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void ReleaseAudioBuffer(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    void SetMixAudioTypeLog(AVScreenCaptureMixBufferType bufferType);
    AudioDataSourceReadAtActionState ReadAudioBuffer();
    AudioDataSourceReadAtActionState WriteInnerAudio(std::shared_ptr<CacheBuffer> &innerAudioBuffer);
    AudioDataSourceReadAtActionState WriteMicAudio(std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState WriteMixAudio(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMix(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMixCore(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState InnerMicAudioSync(std::shared_ptr<CacheBuffer> &innerAudioBuffer,
        std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState VideoAudioSyncMixMode(int64_t timeWindow,
        std::shared_ptr<CacheBuffer> &innerAudioBuffer, std::shared_ptr<CacheBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadAtMixMode();
    AudioDataSourceReadAtActionState ReadAtMicMode();
    AudioDataSourceReadAtActionState ReadAtInnerMode();
    AudioDataSourceReadAtActionState VideoAudioSyncInnerMode(int64_t timeWindow,
        std::shared_ptr<CacheBuffer> &innerAudioBuffer);
    int64_t LostFrameNum(const int64_t &timestamp);
    int64_t writedFrameTime_ = 0;
    int64_t firstAudioFramePts_ = -1;
    std::shared_ptr<CacheBuffer> cacheBuffer_;
    std::vector<uint8_t> zeroBuffer_;
    int32_t appPid_{0};
    std::atomic<uint32_t> audioRendererState_{0};
    std::atomic<int64_t> firstVideoFramePts_{-1};
    std::atomic<int64_t> lastWriteAudioFramePts_{0};
    std::atomic<int64_t> lastMicAudioFramePts_{0};
    std::atomic<AVScreenCaptureMixBufferType> audioType_{AVScreenCaptureMixBufferType::INVALID};
    std::atomic<uint64_t> audioTypeSize_{0};
    std::atomic<AVScreenCaptureMixBufferType> lastWriteType_{AVScreenCaptureMixBufferType::INVALID};
    int32_t stableStopInnerSwitchCount_ = 0;
    bool mixModeAddAudioMicFrame_ = false;
    std::atomic<bool> isInWaitMicSyncState_{false};
    AVScreenCaptureMixMode type_;
    ScreenCaptureServer *screenCaptureServer_;
    std::shared_ptr<AudioCapturerWrapper> innerCapture_;
    std::shared_ptr<AudioCapturerWrapper> micCapture_;
    std::weak_ptr<IAudioDataSourceListener> listener_;
    std::mutex mutex_;
    std::atomic<int64_t> pauseStartTime_{0};
    std::atomic<int64_t> pauseDuration_{0};

    static constexpr int32_t INNER_SWITCH_MIC_REQUIRE_COUNT = 10;
    static constexpr int32_t ADS_LOG_SKIP_NUM = 1000;
    static constexpr int64_t MAX_INNER_AUDIO_TIMEOUT_IN_NS = 2000000000; // 2s
    static constexpr int64_t AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS = 10000000; // 10ms
    static constexpr int64_t AUDIO_INTERVAL_IN_NS = 21333334;            // 20ms
    static constexpr int64_t NEG_AUDIO_INTERVAL_IN_NS = -21333334;       // 20ms
    static constexpr int64_t MAX_MIC_BEFORE_INNER_TIME_IN_NS = 40000000; // 40ms
    static constexpr int32_t FILL_AUDIO_FRAME_DURATION_IN_NS = 20000000; // 20ms
};
} // namespace OHOS::Media
#endif
