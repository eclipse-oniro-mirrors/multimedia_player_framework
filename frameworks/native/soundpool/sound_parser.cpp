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

#include <fcntl.h>
#include <functional>
#include <cstdio>
#include "isoundpool.h"
#include "sound_parser.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundParser"};
    static constexpr int32_t MAX_SOUND_BUFFER_SIZE = 1 * 1024 * 1024;
    static const std::string AUDIO_RAW_MIMETYPE_INFO = "audio/raw";
    static const std::string AUDIO_MPEG_MIMETYPE_INFO = "audio/mpeg";
    static constexpr int32_t MAX_CODEC_BUFFER_SIZE = 5 * 1024 * 1024;
}

namespace OHOS {
namespace Media {
SoundParser::SoundParser(int32_t soundID, std::string url)
{
    std::shared_ptr<MediaAVCodec::AVSource> source = MediaAVCodec::AVSourceFactory::CreateWithURI(url);
    CHECK_AND_RETURN_LOG(source != nullptr, "Create AVSource failed");
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = MediaAVCodec::AVDemuxerFactory::CreateWithSource(source);
    CHECK_AND_RETURN_LOG(demuxer != nullptr, "Create AVDemuxer failed");
    soundID_ = soundID;
    demuxer_ = demuxer;
    source_ = source;
}

SoundParser::SoundParser(int32_t soundID, int32_t fd, int64_t offset, int64_t length)
{
    fdSource_ = fcntl(fd, F_DUPFD_CLOEXEC, MIN_FD); // dup(fd) + close on exec to prevent leaks.
    offset = offset >= INT64_MAX ? INT64_MAX : offset;
    length = length >= INT64_MAX ? INT64_MAX : length;
    MEDIA_LOGI("SoundParser::SoundParser fd:%{public}d, fdSource_:%{public}d,", fd, fdSource_);
    std::shared_ptr<MediaAVCodec::AVSource> source =
        MediaAVCodec::AVSourceFactory::CreateWithFD(fdSource_, offset, length);
    CHECK_AND_RETURN_LOG(source != nullptr, "Create AVSource failed");
    std::shared_ptr<MediaAVCodec::AVDemuxer> demuxer = MediaAVCodec::AVDemuxerFactory::CreateWithSource(source);
    CHECK_AND_RETURN_LOG(demuxer != nullptr, "Create AVDemuxer failed");

    soundID_ = soundID;
    demuxer_ = demuxer;
    source_ = source;
}

SoundParser::~SoundParser()
{
    MEDIA_LOGI("SoundParser Destruction, soundID:%{public}d", soundID_);
    Release();
}

int32_t SoundParser::DoParser()
{
    MediaTrace trace("SoundParser::DoParser");
    MEDIA_LOGI("SoundParser::DoParser start, soundID:%{public}d", soundID_);
    std::unique_lock<ffrt::mutex> lock(soundParserLock_);
    CHECK_AND_RETURN_RET_LOG(source_ != nullptr, MSERR_INVALID_VAL, "DoParser source_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(demuxer_ != nullptr, MSERR_INVALID_VAL, "DoParser demuxer_ is nullptr");
    int32_t result = MSERR_OK;
    result = DoDemuxer(&trackFormat_);
    if (result != MSERR_OK && callback_ != nullptr) {
        MEDIA_LOGI("DoDemuxer failed, call callback");
        callback_->OnError(MSERR_UNSUPPORT_FILE);
        SoundPoolUtils::ErrorInfo errorInfo{
            .errorCode = MSERR_UNSUPPORT_FILE,
            .soundId = soundID_,
            .errorType = ERROR_TYPE::LOAD_ERROR,
            .callback = callback_};
        SoundPoolUtils::SendErrorInfo(errorInfo);
        return MSERR_INVALID_VAL;
    } else if (result != MSERR_OK && callback_ == nullptr) {
        MEDIA_LOGI("DoDemuxer failed, callback is nullptr");
        return MSERR_INVALID_VAL;
    }
    result = DoDecode(trackFormat_);
    if (result != MSERR_OK && callback_ != nullptr) {
        MEDIA_LOGI("DoDecode failed, call callback");
        callback_->OnError(MSERR_UNSUPPORT_FILE);
        SoundPoolUtils::ErrorInfo errorInfo{
            .errorCode = MSERR_UNSUPPORT_FILE,
            .soundId = soundID_,
            .errorType = ERROR_TYPE::LOAD_ERROR,
            .callback = callback_};
        SoundPoolUtils::SendErrorInfo(errorInfo);
        return MSERR_INVALID_VAL;
    } else if (result != MSERR_OK && callback_ == nullptr) {
        MEDIA_LOGI("DoDecode failed, callback is nullptr");
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGI("SoundParser::DoParser end, soundID:%{public}d", soundID_);
    return MSERR_OK;
}

int32_t SoundParser::DoDemuxer(MediaAVCodec::Format *trackFormat)
{
    MediaTrace trace("SoundParser::DoDemuxer");
    MEDIA_LOGI("SoundParser::DoDemuxer start, soundID:%{public}d", soundID_);
    MediaAVCodec::Format sourceFormat;
    int32_t sourceTrackCountInfo = 0;
    int64_t sourceDurationInfo = 0;
    CHECK_AND_RETURN_RET_LOG(source_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain av source");
    CHECK_AND_RETURN_RET_LOG(demuxer_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain demuxer");
    CHECK_AND_RETURN_RET_LOG(trackFormat != nullptr, MSERR_INVALID_VAL, "Invalid trackFormat.");
    int32_t ret = source_->GetSourceFormat(sourceFormat);
    if (ret != 0) {
        MEDIA_LOGE("Get source format failed:%{public}d", ret);
    }
    sourceFormat.GetIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_TRACK_COUNT, sourceTrackCountInfo);
    sourceFormat.GetLongValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_DURATION, sourceDurationInfo);

    sourceDurationInfo_ = sourceDurationInfo;

    MEDIA_LOGI("SoundParser sourceTrackCountInfo:%{public}d", sourceTrackCountInfo);
    for (int32_t sourceTrackIndex = 0; sourceTrackIndex < sourceTrackCountInfo; sourceTrackIndex++) {
        int32_t trackType = 0;
        ret = source_->GetTrackFormat(*trackFormat, sourceTrackIndex);
        if (ret != 0) {
            MEDIA_LOGE("Get track format failed:%{public}d", ret);
        }
        trackFormat->GetIntValue(MediaDescriptionKey::MD_KEY_TRACK_TYPE, trackType);
        MEDIA_LOGI("SoundParser trackType:%{public}d", trackType);
        if (trackType == MEDIA_TYPE_AUD) {
            demuxer_->SelectTrackByID(sourceTrackIndex);
            std::string trackMimeTypeInfo;
            trackFormat->GetStringValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CODEC_MIME, trackMimeTypeInfo);
            if (AUDIO_RAW_MIMETYPE_INFO.compare(trackMimeTypeInfo) != 0) {
                // resample format
                trackFormat->PutIntValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_AUDIO_SAMPLE_FORMAT,
                    MediaAVCodec::SAMPLE_S16LE);
            } else {
                isRawFile_ = true;
                trackFormat->PutStringValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CODEC_MIME,
                    AUDIO_MPEG_MIMETYPE_INFO);
            }
            break;
        }
    }
    MEDIA_LOGI("SoundParser::DoDemuxer end, soundID:%{public}d", soundID_);
    return MSERR_OK;
}

int32_t SoundParser::DoDecode(MediaAVCodec::Format &trackFormat)
{
    MediaTrace trace("SoundParser::DoDecode");
    MEDIA_LOGI("SoundParser::DoDecode start, soundID:%{public}d", soundID_);
    int32_t trackTypeInfo;
    trackFormat.GetIntValue(MediaDescriptionKey::MD_KEY_TRACK_TYPE, trackTypeInfo);
    if (trackTypeInfo == MEDIA_TYPE_AUD) {
        std::string trackMimeTypeInfo;
        trackFormat.GetStringValue(MediaAVCodec::MediaDescriptionKey::MD_KEY_CODEC_MIME, trackMimeTypeInfo);
        MEDIA_LOGI("SoundParser mime type:%{public}s", trackMimeTypeInfo.c_str());
        audioDec_ = MediaAVCodec::AudioDecoderFactory::CreateByMime(trackMimeTypeInfo);
        CHECK_AND_RETURN_RET_LOG(audioDec_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain audioDecorder.");
        int32_t ret = audioDec_->Configure(trackFormat);
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "Failed to configure audioDecorder.");
        audioDecCb_ = std::make_shared<SoundDecoderCallback>(soundID_, audioDec_, demuxer_, isRawFile_);
        CHECK_AND_RETURN_RET_LOG(audioDecCb_ != nullptr, MSERR_INVALID_VAL, "Failed to obtain decode callback.");
        ret = audioDec_->SetCallback(audioDecCb_);
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "Failed to setCallback audioDecorder");
        soundParserListener_ = std::make_shared<SoundParserListener>(weak_from_this());
        CHECK_AND_RETURN_RET_LOG(soundParserListener_ != nullptr, MSERR_INVALID_VAL, "Invalid sound parser listener");
        audioDecCb_->SetDecodeCallback(soundParserListener_);
        if (callback_ != nullptr) audioDecCb_->SetCallback(callback_);
        ret = audioDec_->Start();
        CHECK_AND_RETURN_RET_LOG(ret == 0, MSERR_INVALID_VAL, "Failed to Start audioDecorder.");
        MEDIA_LOGI("SoundParser::DoDecode, audioDec_ started, soundID:%{public}d", soundID_);
    }
    return MSERR_OK;
}

int32_t SoundParser::GetSoundData(std::shared_ptr<AudioBufferEntry> &soundData) const
{
    CHECK_AND_RETURN_RET_LOG(soundParserListener_ != nullptr, MSERR_INVALID_VAL, "Invalid sound parser listener");
    return soundParserListener_->GetSoundData(soundData);
}

size_t SoundParser::GetSoundDataTotalSize() const
{
    CHECK_AND_RETURN_RET_LOG(soundParserListener_ != nullptr, 0, "Invalid sound parser listener");
    return soundParserListener_->GetSoundDataTotalSize();
}

bool SoundParser::IsSoundParserCompleted() const
{
    CHECK_AND_RETURN_RET_LOG(soundParserListener_ != nullptr, false, "Invalid sound parser listener");
    return soundParserListener_->IsSoundParserCompleted();
}

int32_t SoundParser::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    callback_ = callback;
    return MSERR_OK;
}

int64_t SoundParser::GetSourceDuration()
{
    return sourceDurationInfo_;
}

int32_t SoundParser::Release()
{
    MediaTrace trace("SoundParser::Release");
    MEDIA_LOGI("SoundParser::Release start, soundID:%{public}d", soundID_);
    int32_t ret = MSERR_OK;
    std::shared_ptr<SoundDecoderCallback> audioDecCbRelease;
    {
        std::unique_lock<ffrt::mutex> lock(soundParserLock_);
        if (soundParserListener_ != nullptr) soundParserListener_.reset();
        audioDecCbRelease = std::move(audioDecCb_);
        audioDecCb_ = nullptr;
    }
    if (audioDecCbRelease != nullptr) {
        ret = audioDecCbRelease->Release();
        audioDecCbRelease.reset();
    }
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDecRelease;
    {
        std::unique_lock<ffrt::mutex> lock(soundParserLock_);
        audioDecRelease = std::move(audioDec_);
        audioDec_ = nullptr;
    }
    if (audioDecRelease != nullptr) {
        ret = audioDecRelease->Release();
        audioDecRelease.reset();
    }
    std::unique_lock<ffrt::mutex> lock(soundParserLock_);
    if (demuxer_ != nullptr) demuxer_.reset();
    if (source_ != nullptr) source_.reset();
    if (callback_ != nullptr) callback_.reset();
    if (fdSource_ > 0) {
        MEDIA_LOGI("SoundParser::Release() fdSource_:%{public}d", fdSource_);
        (void)close(fdSource_);
        fdSource_ = -1;
    }
    MEDIA_LOGI("SoundParser::Release end, soundID:%{public}d", soundID_);
    return ret;
}

SoundDecoderCallback::SoundDecoderCallback(const int32_t soundID,
    const std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> &audioDec,
    const std::shared_ptr<MediaAVCodec::AVDemuxer> &demuxer,
    const bool isRawFile) : soundID_(soundID), audioDec_(audioDec),
    demuxer_(demuxer), isRawFile_(isRawFile), eosFlag_(false),
    decodeShouldCompleted_(false), currentSoundBufferSize_(0)
{
    MEDIA_LOGI("Construction SoundDecoderCallback");
}

SoundDecoderCallback::~SoundDecoderCallback()
{
    MEDIA_LOGI("Destruction SoundDecoderCallback");
    Release();
}
void SoundDecoderCallback::OnError(AVCodecErrorType errorType, int32_t errorCode)
{
    if (isRawFile_) {
        MEDIA_LOGI("Recive error, errorType:%{public}d,errorCode:%{public}d", errorType, errorCode);
    }
}

void SoundDecoderCallback::OnOutputFormatChanged(const Format &format)
{
    (void)format;
}

void SoundDecoderCallback::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVSharedMemory> buffer)
{
    amutex_.lock();
    MediaAVCodec::AVCodecBufferFlag bufferFlag = MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_NONE;
    MediaAVCodec::AVCodecBufferInfo sampleInfo;
    if (demuxer_ == nullptr || audioDec_ == nullptr) {
        MEDIA_LOGE("SoundDecoderCallback Input demuxer_:%{public}d, audioDec_:%{public}d,",
            demuxer_ == nullptr, audioDec_ == nullptr);
        amutex_.unlock();
        return;
    }

    if (buffer != nullptr && isRawFile_ && !decodeShouldCompleted_) {
        DealBufferRawFile(bufferFlag, sampleInfo, index, buffer);
        amutex_.unlock();
        return;
    }

    if (buffer != nullptr && !eosFlag_ && !decodeShouldCompleted_) {
        if (demuxer_->ReadSample(0, buffer, sampleInfo, bufferFlag) != AVCS_ERR_OK) {
            MEDIA_LOGE("SoundDecoderCallback demuxer error.");
            amutex_.unlock();
            return;
        }
        if (bufferFlag == AVCODEC_BUFFER_FLAG_EOS) {
            eosFlag_ = true;
        }
        audioDec_->QueueInputBuffer(index, sampleInfo, bufferFlag);
    }
    amutex_.unlock();
}

void SoundDecoderCallback::DealBufferRawFile(MediaAVCodec::AVCodecBufferFlag bufferFlag,
    MediaAVCodec::AVCodecBufferInfo sampleInfo, uint32_t index, std::shared_ptr<AVSharedMemory> buffer)
{
    if (demuxer_->ReadSample(0, buffer, sampleInfo, bufferFlag) != AVCS_ERR_OK) {
        MEDIA_LOGE("SoundDecoderCallback demuxer error.");
        return;
    }
    if (!decodeShouldCompleted_ && (currentSoundBufferSize_ > MAX_SOUND_BUFFER_SIZE ||
            bufferFlag == AVCODEC_BUFFER_FLAG_EOS)) {
        decodeShouldCompleted_ = true;
        ReCombineCacheData();
        CHECK_AND_RETURN_LOG(listener_ != nullptr, "sound decode listener invalid.");
        listener_->OnSoundDecodeCompleted(fullCacheData_);
        listener_->SetSoundBufferTotalSize(static_cast<size_t>(currentSoundBufferSize_));
        CHECK_AND_RETURN_LOG(callback_ != nullptr, "sound decode:soundpool callback invalid.");
        callback_->OnLoadCompleted(soundID_);
        return;
    }
    int32_t size = sampleInfo.size;
    uint8_t *buf = new(std::nothrow) uint8_t[size];
    if (buf != nullptr) {
        if (memcpy_s(buf, size, buffer->GetBase(), size) != EOK) {
            delete[] buf;
            MEDIA_LOGI("audio buffer copy failed:%{public}s", strerror(errno));
        } else {
            availableAudioBuffers_.push_back(std::make_shared<AudioBufferEntry>(buf, size));
        }
    }
    currentSoundBufferSize_ += size;
    audioDec_->QueueInputBuffer(index, sampleInfo, bufferFlag);
    return;
}

void SoundDecoderCallback::OnOutputBufferAvailable(uint32_t index, AVCodecBufferInfo info, AVCodecBufferFlag flag,
    std::shared_ptr<AVSharedMemory> buffer)
{
    amutex_.lock();
    if (demuxer_ == nullptr || audioDec_ == nullptr) {
        MEDIA_LOGE("SoundDecoderCallback Output demuxer_:%{public}d, audioDec_:%{public}d,",
            demuxer_ == nullptr, audioDec_ == nullptr);
        amutex_.unlock();
        return;
    }
    if (isRawFile_) {
        audioDec_->ReleaseOutputBuffer(index);
        amutex_.unlock();
        return;
    }
    if (buffer != nullptr && !decodeShouldCompleted_) {
        if (currentSoundBufferSize_ > MAX_SOUND_BUFFER_SIZE || flag == AVCODEC_BUFFER_FLAG_EOS) {
            decodeShouldCompleted_ = true;
            ReCombineCacheData();
            if (listener_ != nullptr) {
                listener_->OnSoundDecodeCompleted(fullCacheData_);
                listener_->SetSoundBufferTotalSize(static_cast<size_t>(currentSoundBufferSize_));
            }
            if (callback_ != nullptr) {
                callback_->OnLoadCompleted(soundID_);
            }
            amutex_.unlock();
            return;
        }
        int32_t size = info.size;
        if (size <= 0 || size > MAX_CODEC_BUFFER_SIZE) {
            MEDIA_LOGE("SoundDecoderCallback output size :%{public}d", size);
            amutex_.unlock();
            return;
        }
        uint8_t *buf = new(std::nothrow) uint8_t[size];
        if (buf != nullptr) {
            if (memcpy_s(buf, size, buffer->GetBase(), info.size) != EOK) {
                delete[] buf;
                MEDIA_LOGI("audio buffer copy failed:%{public}s", strerror(errno));
            } else {
                availableAudioBuffers_.push_back(std::make_shared<AudioBufferEntry>(buf, size));
            }
        }
        currentSoundBufferSize_ += size;
    }
    audioDec_->ReleaseOutputBuffer(index);
    amutex_.unlock();
}

int32_t SoundDecoderCallback::ReCombineCacheData()
{
    MEDIA_LOGI("ReCombine start currentSoundBufferSize_:%{public}d", currentSoundBufferSize_);
    uint8_t *fullBuffer = new(std::nothrow) uint8_t[currentSoundBufferSize_];
    CHECK_AND_RETURN_RET_LOG(fullBuffer != nullptr, MSERR_INVALID_VAL, "Invalid fullBuffer");
    int32_t copyIndex = 0;
    int32_t remainBufferSize = static_cast<int32_t>(currentSoundBufferSize_);
    MEDIA_LOGI("ReCombine start copyIndex:%{public}d, remainSize:%{public}d", copyIndex, remainBufferSize);
    for (std::shared_ptr<AudioBufferEntry> bufferEntry : availableAudioBuffers_) {
        if (bufferEntry != nullptr && bufferEntry->size > 0 && bufferEntry->buffer != nullptr) {
            if (remainBufferSize < bufferEntry->size) {
                delete[] fullBuffer;
                MEDIA_LOGE("ReCombine not enough remainBufferSize:%{public}d, bufferEntry->size:%{public}d",
                    remainBufferSize, bufferEntry->size);
                return MSERR_INVALID_VAL;
            }
            int32_t ret = memcpy_s(fullBuffer + copyIndex, remainBufferSize,
                bufferEntry->buffer, bufferEntry->size);
            if (ret != MSERR_OK) {
                delete[] fullBuffer;
                MEDIA_LOGE("ReCombine memcpy failed");
                return MSERR_INVALID_VAL;
            }
            copyIndex += bufferEntry->size;
            remainBufferSize -= bufferEntry->size;
        } else {
            MEDIA_LOGE("ReCombineCacheData, bufferEntry size:%{public}d, buffer:%{public}d",
                bufferEntry->size, bufferEntry->buffer != nullptr);
        }
    }
    MEDIA_LOGI("ReCombine finish copyIndex:%{public}d, remainSize:%{public}d", copyIndex, remainBufferSize);

    fullCacheData_ = std::make_shared<AudioBufferEntry>(fullBuffer, currentSoundBufferSize_);

    if (!availableAudioBuffers_.empty()) {
        availableAudioBuffers_.clear();
    }
    return MSERR_OK;
}

int32_t SoundDecoderCallback::SetCallback(const std::shared_ptr<ISoundPoolCallback> &callback)
{
    MEDIA_LOGI("SoundDecoderCallback::SetCallback");
    callback_ = callback;
    return MSERR_OK;
}

int32_t SoundDecoderCallback::Release()
{
    int32_t ret = MSERR_OK;
    MEDIA_LOGI("SoundDecoderCallback::Release");
    //here use audioDec, the reason is the same reason in CacheBuffer::Release().please check it
    //in CacheBuffer::Release()
    std::shared_ptr<MediaAVCodec::AVCodecAudioDecoder> audioDec;
    {
        std::lock_guard lock(amutex_);
        audioDec = std::move(audioDec_);
        audioDec_ = nullptr;
    }
    if (audioDec != nullptr) {
        ret = audioDec->Release();
        audioDec.reset();
        audioDec = nullptr;
    }
    std::lock_guard lock(amutex_);
    if (demuxer_ != nullptr) demuxer_.reset();
    if (listener_ != nullptr) listener_.reset();
    if (!availableAudioBuffers_.empty()) availableAudioBuffers_.clear();
    if (callback_ != nullptr) callback_.reset();
    if (fullCacheData_ != nullptr) fullCacheData_.reset();
    return ret;
}

void SoundParser::SoundParserListener::OnSoundDecodeCompleted(
    const std::shared_ptr<AudioBufferEntry> &fullCacheData)
{
    if (std::shared_ptr<SoundParser> soundPaser = soundParserInner_.lock()) {
        std::unique_lock<ffrt::mutex> lock(soundPaser->soundParserLock_);
        soundData_ = fullCacheData;
        isSoundParserCompleted_.store(true);
    }
}

void SoundParser::SoundParserListener::SetSoundBufferTotalSize(const size_t soundBufferTotalSize)
{
    if (std::shared_ptr<SoundParser> soundPaser = soundParserInner_.lock()) {
        std::unique_lock<ffrt::mutex> lock(soundPaser->soundParserLock_);
        soundBufferTotalSize_ = soundBufferTotalSize;
    }
}

int32_t SoundParser::SoundParserListener::GetSoundData(
    std::shared_ptr<AudioBufferEntry> &soundData) const
{
    if (std::shared_ptr<SoundParser> soundPaser = soundParserInner_.lock()) {
        std::unique_lock<ffrt::mutex> lock(soundPaser->soundParserLock_);
        soundData = soundData_;
    }
    return MSERR_OK;
}

size_t SoundParser::SoundParserListener::GetSoundDataTotalSize() const
{
    return soundBufferTotalSize_;
}

bool SoundParser::SoundParserListener::IsSoundParserCompleted() const
{
    return isSoundParserCompleted_.load();
}

} // namespace Media
} // namespace OHOS
