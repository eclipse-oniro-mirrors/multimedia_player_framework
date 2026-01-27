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

#ifndef AUDIO_DATA_SOURCE_H
#define AUDIO_DATA_SOURCE_H

#include "audio_capturer_wrapper.h"
#include "audio_stream_manager.h"
#include "media_data_source.h"

namespace OHOS::Media {
using namespace AudioStandard;

class ScreenCaptureServer;

enum class AVScreenCaptureMixMode : int32_t {
    MIX_MODE = 0,
    MIC_MODE = 1,
    INNER_MODE = 2,
    INVALID_MODE = 3
};

enum class AVScreenCaptureMixBufferType : int32_t {
    MIX = 0,
    MIC = 1,
    INNER = 2,
    INVALID = 3
};

class AudioDataSource : public IAudioDataSource {
    class CacheBuffer {
    private:
        std::shared_ptr<AudioBuffer> refBuf_{nullptr};
        std::unique_ptr<uint8_t[]> buf_{nullptr};
    public:
        CacheBuffer() = delete;
        explicit CacheBuffer(const std::shared_ptr<AudioBuffer> &buf);
        CacheBuffer(std::unique_ptr<uint8_t[]> &buf, const int64_t &timestamp);
        int64_t timestamp{0};
        void WriteTo(const std::shared_ptr<AVMemory> &avMem, const uint32_t &len);
    };
public:
    AudioDataSource(AVScreenCaptureMixMode type, ScreenCaptureServer* screenCaptureServer) : type_(type),
        screenCaptureServer_(screenCaptureServer) {}

    int64_t GetFirstAudioTime(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState WriteInnerAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer);
    AudioDataSourceReadAtActionState WriteMicAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState WriteMixAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMix(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMixCore(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState InnerMicAudioSync(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState VideoAudioSyncMixMode(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadAtMixMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAtMicMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAtInnerMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override;
    AudioDataSourceReadAtActionState VideoAudioSyncInnerMode(std::shared_ptr<AVBuffer> &buffer,
        uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer);
    int32_t GetSize(int64_t &size) override;
    int32_t RegisterAudioRendererEventListener(const int32_t clientPid,
        const std::shared_ptr<AudioRendererStateChangeCallback> &callback);
    int32_t UnregisterAudioRendererEventListener(const int32_t clientPid);
    void SpeakerStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    bool HasSpeakerStream(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void VoIPStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    bool HasVoIPStream(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void SetAppPid(int32_t appid);
    void SetAppName(std::string appName);
    int32_t GetAppPid();
    bool GetIsInVoIPCall();
    bool GetSpeakerAliveStatus();
    bool IsInWaitMicSyncState();
#ifdef SUPPORT_CALL
    void TelCallAudioStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
#endif
    void SetVideoFirstFramePts(int64_t firstFramePts) override;
    void SetAudioFirstFramePts(int64_t firstFramePts);
    AudioDataSourceReadAtActionState MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem);
    void HandlePastMicBuffer(std::shared_ptr<AudioBuffer> &micAudioBuffer);
    void HandleSwitchToSpeakerOptimise(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    void HandleBufferTimeStamp(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    ScreenCaptureServer* GetScreenCaptureServer();
private:
    void MixAudio(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer, char* mixData, int channels);
    AudioDataSourceReadAtActionState ReadAudioBuffer(std::shared_ptr<AVBuffer> &buffer, const uint32_t &length);
    int32_t LostFrameNum(const int64_t &timestamp);
    void FillLostBuffer(const int64_t &lostNum, const int64_t &timestamp, const uint32_t &bufferSize);
    int64_t writedFrameTime_{0};
    std::deque<CacheBuffer> audioBufferQ_;
    int32_t appPid_ { 0 };
    std::string appName_;
    bool speakerAliveStatus_ = true;
    std::atomic<bool> isInVoIPCall_ = false;
    std::mutex voipStatusChangeMutex_;
    std::atomic<int64_t> firstAudioFramePts_{-1};
    std::atomic<int64_t> firstVideoFramePts_{-1};
    std::atomic<int64_t> lastWriteAudioFramePts_{0};
    std::atomic<int64_t> lastMicAudioFramePts_{0};
    AVScreenCaptureMixBufferType lastWriteType_ = AVScreenCaptureMixBufferType::INVALID;
    int32_t stableStopInnerSwitchCount_ = 0;
    bool mixModeAddAudioMicFrame_ = false;
    bool isInWaitMicSyncState_ = false;
    AVScreenCaptureMixMode type_;
    ScreenCaptureServer* screenCaptureServer_;

    static constexpr int32_t INNER_SWITCH_MIC_REQUIRE_COUNT = 10;
    static constexpr int32_t ADS_LOG_SKIP_NUM = 1000;
    static constexpr int64_t MAX_INNER_AUDIO_TIMEOUT_IN_NS = 2000000000; // 2s
    static constexpr int64_t AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS = 10000000; // 10ms
    static constexpr int64_t AUDIO_INTERVAL_IN_NS = 21333334; // 20ms
    static constexpr int64_t NEG_AUDIO_INTERVAL_IN_NS = -21333334; // 20ms
    static constexpr int64_t SEC_TO_NS = 1000000000; // 1s
    static constexpr int64_t MAX_MIC_BEFORE_INNER_TIME_IN_NS = 40000000; // 40ms
    static constexpr int32_t FILL_AUDIO_FRAME_DURATION_IN_NS = 20000000; // 20ms
    static constexpr int32_t FILL_LOST_FRAME_COUNT_THRESHOLD = 5;
};
}
#endif