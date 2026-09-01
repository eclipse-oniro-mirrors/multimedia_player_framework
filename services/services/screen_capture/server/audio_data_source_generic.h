/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUDIO_DATA_SOURCE_GENERIC_H
#define AUDIO_DATA_SOURCE_GENERIC_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include "audio_capturer_wrapper.h"
#include "cache_buffer.h"
#include "media_data_source.h"
#include "screen_capture.h"

namespace OHOS {
namespace Media {

enum class AudioCombinePolicy : int32_t {
    PASSTHROUGH,
    MIX_ALL,
};

enum class CaptureSlotState : int32_t {
    INACTIVE,
    UNSTABLE,
    STABLE,
};

enum class AudioOutputTag : int32_t {
    INVALID,
    SINGLE,
    MIXED,
    SILENT,
};

struct CaptureSlot {
    AudioCaptureSourceType type;
    std::shared_ptr<AudioCapturerWrapper> capture;
    CaptureSlotState state{CaptureSlotState::INACTIVE};
    std::shared_ptr<CacheBuffer> currentBuf;
    int64_t lastTs{0};
};

struct LastEmit {
    AudioOutputTag type{AudioOutputTag::INVALID};
    AudioCaptureSourceType source{AudioCaptureSourceType::SOURCE_DEFAULT};
    int64_t pts{0};
};

struct AudioBufferLogStats {
    AudioOutputTag type{AudioOutputTag::INVALID};
    AudioCaptureSourceType source{AudioCaptureSourceType::SOURCE_DEFAULT};
    uint64_t size{0};
    void Update(AudioOutputTag tag, AudioCaptureSourceType src);
    void Log() const;
};

class AudioDataSourceGeneric : public IAudioDataSource,
                               public AudioBufferAvailableCallback,
                               public std::enable_shared_from_this<AudioDataSourceGeneric> {
public:
    AudioDataSourceGeneric(AudioCombinePolicy policy, bool recorderFileWithVideo);
    ~AudioDataSourceGeneric() override;

    AudioDataSourceGeneric(const AudioDataSourceGeneric &) = delete;
    AudioDataSourceGeneric &operator=(const AudioDataSourceGeneric &) = delete;
    AudioDataSourceGeneric(AudioDataSourceGeneric &&) = delete;
    AudioDataSourceGeneric &operator=(AudioDataSourceGeneric &&) = delete;

    AudioDataSourceReadAtActionState ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override;
    int32_t GetSize(int64_t &size) override;
    void SetVideoFirstFramePts(int64_t firstFramePts) override;
    void SetListener(std::shared_ptr<IAudioDataSourceListener> listener) override;
    void OnBufferAvailable(AudioCaptureSourceType type) override;

    void SetCapture(AudioCaptureSourceType type, std::shared_ptr<AudioCapturerWrapper> capture);
    void Pause();
    void Resume();
    void Stop();
    inline AudioCombinePolicy GetPolicy() const
    {
        return policy_;
    }

private:
    AudioDataSourceReadAtActionState ReadAudioBuffer();
    bool AcquireReady();
    AudioDataSourceReadAtActionState AlignOrCombine();
    AudioDataSourceReadAtActionState Combine();
    AudioDataSourceReadAtActionState VideoAudioSyncIfNeed();
    void MixAudio(const std::vector<const CacheBuffer *> &srcs, uint8_t *out);
    int64_t LostFrameNum(const int64_t &timestamp);
    void SetMixAudioTypeLog(AudioOutputTag bufferType);

    const AudioCombinePolicy policy_;
    bool recorderFileWithVideo_;
    std::atomic<bool> active_{true};
    std::shared_ptr<CacheBuffer> cacheBuffer_;
    std::vector<CaptureSlot> captures_;
    std::vector<uint8_t> zeroBuffer_;
    std::weak_ptr<IAudioDataSourceListener> listener_;
    std::mutex mutex_;
    LastEmit lastEmit_;
    int64_t writedFrameTime_{0};
    std::atomic<int64_t> firstVideoFramePts_{-1};
    bool avSynced_{false};
    std::atomic<int64_t> pauseStartTime_{0};
    std::atomic<int64_t> pauseDuration_{0};
    AudioBufferLogStats logStats_;
};

} // namespace Media
} // namespace OHOS
#endif // AUDIO_DATA_SOURCE_GENERIC_H
