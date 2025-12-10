/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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
#ifndef SOUND_PARSER_H
#define SOUND_PARSER_H

#include <atomic>
#include <deque>
#include <memory>
#include <mutex>

#include "ashmem.h"
#include "audio_shared_memory.h"
#include "audio_stream.h"
#include "avcodec_audio_decoder.h"
#include "avcodec_codec_name.h"
#include "avcodec_errors.h"
#include "avdemuxer.h"
#include "avsource.h"
#include "buffer/avsharedmemory.h"
#include "cpp/mutex.h"
#include "isoundpool.h"
#include "media_description.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "securec.h"

namespace OHOS {
namespace Media {
using namespace MediaAVCodec;
struct AudioBufferEntry;

class SoundDecoderCallback : public AVCodecCallback, public NoCopyable {
public:
    class SoundDecodeListener {
    public:
        SoundDecodeListener()
        {
            (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN_SOUNDPOOL, "SoundDecodeListener",
                "Construction SoundDecodeListener");
        }
        virtual ~SoundDecodeListener()
        {
            (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN_SOUNDPOOL, "SoundDecodeListener",
                "Destruction SoundDecodeListener");
        }
        virtual void OnSoundDecodeCompleted(const std::shared_ptr<AudioBufferEntry> &fullCacheData) = 0;
        virtual void SetSoundBufferTotalSize(size_t soundBufferTotalSize) = 0;
    };

    SoundDecoderCallback(int32_t soundID, const std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> &audioDec,
        const std::shared_ptr<MediaAVCodec::AVDemuxer> &demuxer, bool isRawFile);
    ~SoundDecoderCallback();
    int32_t SetDecodeCallback(const std::shared_ptr<SoundDecodeListener> &listener)
    {
        (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN_SOUNDPOOL, "SoundDecoderCallback",
            "%{public}s:%{public}d", __func__, __LINE__);
        if (listener == nullptr) {
            (void)HILOG_IMPL(LOG_CORE, LOG_INFO, LOG_DOMAIN_SOUNDPOOL, "SoundDecodeListener", "Invalid listener");
            return MSERR_INVALID_VAL;
        }
        listener_ = listener;
        return MSERR_OK;
    }
    void OnError(AVCodecErrorType errorType, int32_t errorCode) override;
    void OnOutputFormatChanged(const Format &format) override;
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVSharedMemory> buffer) override;
    void OnOutputBufferAvailable(uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag,
        std::shared_ptr<AVSharedMemory> buffer) override;

    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t ReCombineCacheData();
    int32_t Release();

private:
    void DealBufferRawFile(MediaAVCodec::AVCodecBufferFlag bufferFlag, MediaAVCodec::AVCodecBufferInfo sampleInfo,
        uint32_t index, std::shared_ptr<AVSharedMemory> buffer);

    int32_t soundID_ = 0;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec_ = nullptr;
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer_ = nullptr;
    std::shared_ptr<SoundDecodeListener> listener_ = nullptr;
    bool isRawFile_ = false;
    bool eosFlag_ = false;
    std::deque<std::shared_ptr<AudioBufferEntry>> availableAudioBuffers_;
    std::shared_ptr<AudioBufferEntry> fullPcmBuffer_ = nullptr;
    bool decodeShouldCompleted_ = false;
    int32_t currentSoundBufferSize_ = 0;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    std::mutex amutex_;
};

class SoundParser : public std::enable_shared_from_this<SoundParser> {
public:
    SoundParser(int32_t soundID, const std::string &url);
    SoundParser(int32_t soundID, int32_t fd, int64_t offset, int64_t length);
    ~SoundParser();
    int32_t DoParser();
    int32_t GetSoundID() const
    {
        return soundID_;
    }
    int32_t GetSoundData(std::shared_ptr<AudioBufferEntry> &soundData) const;
    size_t GetSoundDataTotalSize() const;
    MediaAVCodec::Format GetSoundTrackFormat() const
    {
        return trackFormat_;
    }
    bool IsSoundParserCompleted() const;

    int32_t SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback);
    int32_t Release();
    int64_t GetSourceDuration();

private:
    class SoundParserListener : public SoundDecoderCallback::SoundDecodeListener {
    public:
        explicit SoundParserListener(const std::weak_ptr<SoundParser> soundParser) : soundParserInner_(soundParser) {}
        void OnSoundDecodeCompleted(const std::shared_ptr<AudioBufferEntry> &fullPcmBuffer) override;
        void SetSoundBufferTotalSize(size_t soundBufferTotalSize) override;
        int32_t GetSoundData(std::shared_ptr<AudioBufferEntry> &soundData) const;
        size_t GetSoundDataTotalSize() const;
        bool IsSoundParserCompleted() const;

    private:
        std::weak_ptr<SoundParser> soundParserInner_;
        std::shared_ptr<AudioBufferEntry> soundData_ = nullptr;
        std::shared_ptr<AudioStandard::AudioSharedMemory> sharedMemory_ = nullptr;
        size_t soundBufferTotalSize_ = 0;
        std::atomic<bool> isSoundParserCompleted_ = false;
    };

    int32_t DoDemuxer(MediaAVCodec::Format *trackFormat);
    int32_t DoDecode(MediaAVCodec::Format &trackFormat);
    int32_t soundID_ = 0;
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer_ = nullptr;
    std::shared_ptr<MediaAVCodec::AVSource> source_ = nullptr;
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec_ = nullptr;
    std::shared_ptr<SoundDecoderCallback> audioDecCb_ = nullptr;
    ffrt::mutex soundParserLock_;
    std::shared_ptr<SoundParserListener> soundParserListener_ = nullptr;
    std::shared_ptr<ISoundPoolCallback> callback_ = nullptr;
    bool isRawFile_ = false;
    int32_t fdSource_ = -1;

    MediaAVCodec::Format trackFormat_;
    int64_t sourceDurationInfo_ = 0;

    static constexpr int32_t AUDIO_SOURCE_TRACK_COUNT = 1;
    static constexpr int32_t AUDIO_SOURCE_TRACK_INDEX = 0;
    static constexpr int64_t MIN_FD = 3;
};
} // namespace Media
} // namespace OHOS
#endif // SOUND_PARSER_H
