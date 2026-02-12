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

#include "av_thumbnail_generator.h"

#include "avcodec_errors.h"
#include "avcodec_info.h"
#include "avcodec_list.h"
#include "buffer/avbuffer_common.h"
#include "common/media_source.h"
#include "ibuffer_consumer_listener.h"
#include "graphic_common_c.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_description.h"
#include "meta/meta.h"
#include "meta/meta_key.h"
#include "plugin/plugin_time.h"
#include "sync_fence.h"
#include "uri_helper.h"
#include "media_dfx.h"

#include "v1_0/cm_color_space.h"
#include "v1_0/hdr_static_metadata.h"
#include "v1_0/buffer_handle_meta_key_type.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "AVThumbnailGenerator" };
}

namespace OHOS {
namespace Media {
using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
using FileType = OHOS::Media::Plugins::FileType;
constexpr float BYTES_PER_PIXEL_YUV = 1.5;
constexpr int32_t RATE_UV = 2;
constexpr int32_t SHIFT_BITS_P010_2_NV12 = 8;
constexpr double VIDEO_FRAME_RATE = 2000.0;
constexpr int32_t MAX_WAIT_TIME_SECOND = 3;
constexpr uint32_t REQUEST_BUFFER_TIMEOUT = 0; // Requesting buffer overtimes 0ms means no retry
constexpr uint32_t ERROR_AGAIN_SLEEP_TIME_US = 1000;
const std::string AV_THUMBNAIL_GENERATOR_INPUT_BUFFER_QUEUE_NAME = "AVThumbnailGeneratorInputBufferQueue";

class ThumnGeneratorCodecCallback : public OHOS::MediaAVCodec::MediaCodecCallback {
public:
    explicit ThumnGeneratorCodecCallback(std::shared_ptr<AVThumbnailGenerator> generator) : generator_(generator) {}

    ~ThumnGeneratorCodecCallback() = default;

    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) override
    {
        if (auto generator = generator_.lock()) {
            generator->OnError(errorType, errorCode);
        } else {
            MEDIA_LOGE("invalid AVThumbnailGenerator");
        }
    }

    void OnOutputFormatChanged(const MediaAVCodec::Format &format) override
    {
        if (auto generator = generator_.lock()) {
            generator->OnOutputFormatChanged(format);
        } else {
            MEDIA_LOGE("invalid AVThumbnailGenerator");
        }
    }

    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
        if (auto generator = generator_.lock()) {
            generator->OnInputBufferAvailable(index, buffer);
        } else {
            MEDIA_LOGE("invalid AVThumbnailGenerator");
        }
    }

    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
    {
        if (auto generator = generator_.lock()) {
            generator->OnOutputBufferAvailable(index, buffer);
        } else {
            MEDIA_LOGE("invalid AVThumbnailGenerator");
        }
    }

private:
    std::weak_ptr<AVThumbnailGenerator> generator_;
};

class ThumbnailGeneratorAVBufferAvailableListener : public OHOS::Media::IConsumerListener {
public:
    explicit ThumbnailGeneratorAVBufferAvailableListener(std::shared_ptr<AVThumbnailGenerator> generator)
        : generator_(generator)
    {
    }

    void OnBufferAvailable() override
    {
        if (auto generator = generator_.lock()) {
            generator->AcquireAvailableInputBuffer();
        } else {
            MEDIA_LOGE("invalid AVThumbnailGenerator");
        }
    }
private:
    std::weak_ptr<AVThumbnailGenerator> generator_;
};

AVThumbnailGenerator::AVThumbnailGenerator(std::shared_ptr<MediaDemuxer> &mediaDemuxer, int32_t appUid, int32_t appPid,
    uint32_t appTokenId, uint64_t appFullTokenId) : mediaDemuxer_(mediaDemuxer), appUid_(appUid), appPid_(appPid),
    appTokenId_(appTokenId), appFullTokenId_(appFullTokenId)
{
    MEDIA_LOGI("Constructor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
}

AVThumbnailGenerator::~AVThumbnailGenerator()
{
    MEDIA_LOGI("Destructor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
    Destroy();
}

void AVThumbnailGenerator::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGE("OnError, instance is 0x%{public}06" PRIXPTR ", errorType is %{public}d, errorCode is %{public}d",
        FAKE_POINTER(this), static_cast<int32_t>(errorType), errorCode);
    if (errorCode == MediaAVCodec::AVCodecServiceErrCode::AVCS_ERR_UNSUPPORTED_CODEC_SPECIFICATION) {
        {
            MEDIA_LOGI("OnError, before onErrorMutex_");
            std::unique_lock<std::mutex> lock(onErrorMutex_);
            CHECK_AND_RETURN_LOG(!hasReceivedCodecErrCodeOfUnsupported_.load(),
                "hasReceivedCodecErrCodeOfUnsupported_ is true");
            hasReceivedCodecErrCodeOfUnsupported_.store(true);
        }

        {
            MEDIA_LOGI("OnError, before mutex_ and queueMutex_");
            std::scoped_lock lock(mutex_, queueMutex_);
            stopProcessing_ = true;
        }
        bufferAvailableCond_.notify_all();
        {
            MEDIA_LOGI("OnError, before readTaskMutex_");
            std::unique_lock<std::mutex> readTaskLock(readTaskMutex_);
            MEDIA_LOGI("OnError, get readTaskMutex_");
            readTaskAvailableCond_.wait(readTaskLock, [this]() {
                return readTaskExited_.load();
            });
            MEDIA_LOGI("OnError, after waiting for readTaskLock");
        }
        cond_.notify_all();
        return;
    }

    {
        std::scoped_lock lock(mutex_, queueMutex_);
        stopProcessing_ = true;
    }
    cond_.notify_all();
    bufferAvailableCond_.notify_all();
}

Status AVThumbnailGenerator::InitDecoder(const std::string& codecName)
{
    MEDIA_LOGD("Init decoder start.");
    if (videoDecoder_ != nullptr) {
        MEDIA_LOGD("AVThumbnailGenerator InitDecoder already.");
        Format format;
        format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
        videoDecoder_->SetParameter(format);
        videoDecoder_->Start();
        return Status::OK;
    }
    Format format;
    int32_t ret = 0;
    std::shared_ptr<Media::Meta> callerInfo = std::make_shared<Media::Meta>();
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_PID, appPid_);
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_UID, appUid_);
    callerInfo->SetData(Media::Tag::AV_CODEC_FORWARD_CALLER_PROCESS_NAME, appName_);
    format.SetMeta(callerInfo);
    ret = codecName == "" ? MediaAVCodec::VideoDecoderFactory::CreateByMime(trackMime_, format, videoDecoder_) :
        MediaAVCodec::VideoDecoderFactory::CreateByName(codecName, format, videoDecoder_);
    MEDIA_LOGI("VideoDecoderAdapter::Init CreateByMime errorCode %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(videoDecoder_ != nullptr, Status::ERROR_NO_MEMORY, "Create videoDecoder_ is nullptr");
    MEDIA_LOGI("appUid: %{public}d, appPid: %{public}d, appName: %{public}s", appUid_, appPid_, appName_.c_str());
    CHECK_AND_RETURN_RET_LOG(trackInfo_ != nullptr, Status::ERROR_NULL_POINTER, "track info init failed");
    Format trackFormat{};
    if (fileType_ == FileType::AVI) {
        trackInfo_->SetData(Tag::MEDIA_FILE_TYPE, FileType::AVI);
    }
    trackFormat.SetMeta(trackInfo_);
    trackFormat.GetIntValue(MediaDescriptionKey::MD_KEY_WIDTH, width_);
    trackFormat.GetIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, height_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Init decoder trackFormat width:%{public}d, height:%{public}d",
               FAKE_POINTER(this), width_, height_);
    trackFormat.PutIntValue(MediaDescriptionKey::MD_KEY_PIXEL_FORMAT,
                            static_cast<int32_t>(Plugins::VideoPixelFormat::NV12));
    trackFormat.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, VIDEO_FRAME_RATE);
    videoDecoder_->Configure(trackFormat);
    std::shared_ptr<MediaAVCodec::MediaCodecCallback> mediaCodecCallback =
        std::make_shared<ThumnGeneratorCodecCallback>(shared_from_this());
    videoDecoder_->SetCallback(mediaCodecCallback);
    videoDecoder_->Prepare();
    auto res = videoDecoder_->Start();
    CHECK_AND_RETURN_RET(res == MSERR_OK, Status::ERROR_WRONG_STATE);
    return Status::OK;
}

void AVThumbnailGenerator::SwitchToSoftWareDecoder()
{
    MEDIA_LOGI("SwitchToSoftWareDecoder start");
    CHECK_AND_RETURN_LOG(videoDecoder_ != nullptr && !trackMime_.empty(),
        "videoDecoder_ is nullptr or trackMime_ is empty");
    Format format;
    videoDecoder_->GetCodecInfo(format);
    MEDIA_LOGI("SwitchToSoftWareDecoder, GetCodecInfo successfully");
    int32_t isHardWareDecoder = 0;
    format.GetIntValue(Media::Tag::MEDIA_IS_HARDWARE, isHardWareDecoder);
    if (isHardWareDecoder == static_cast<int32_t>(true)) {
        MEDIA_LOGI("SwitchToSoftWareDecoder, videoDecoder_ will be released");
        videoDecoder_->Stop();
        videoDecoder_->Release();
        videoDecoder_ = nullptr;
        MEDIA_LOGI("SwitchToSoftWareDecoder, videoDecoder_ has been released");
        std::shared_ptr<MediaAVCodec::AVCodecList> codeclist = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
        CHECK_AND_RETURN_LOG(codeclist != nullptr, "CreateAVCodecList failed, codeclist is nullptr.");
        MediaAVCodec::CapabilityData *capabilityData = codeclist->GetCapability(trackMime_, false,
            MediaAVCodec::AVCodecCategory::AVCODEC_SOFTWARE);
        CHECK_AND_RETURN_LOG(capabilityData != nullptr, "GetCapability failed, capabilityData is nullptr.");
        const std::string codecName = capabilityData->codecName;
        CHECK_AND_RETURN_LOG(!codecName.empty(), "codecName is empty");
        FlushBufferQueue();
        inputBufferQueue_ = nullptr;
        Init();
        {
            std::unique_lock lock(queueMutex_);
            hasFetchedFrame_.store(false);
        }
        auto res = SeekToTime(Plugins::Us2Ms(currentFetchFrameYuvTimeUs_),
            static_cast<Plugins::SeekMode>(currentFetchFrameYuvOption_), currentFetchFrameYuvTimeUs_);
        CHECK_AND_RETURN_LOG(res == Status::OK, "Seek failed.");
        CHECK_AND_RETURN_LOG(InitDecoder(codecName) == Status::OK, "Failed to create software decoder.");
    }
    MEDIA_LOGI("SwitchToSoftWareDecoder end");
}

int32_t AVThumbnailGenerator::Init()
{
    CHECK_AND_RETURN_RET_LOG(inputBufferQueue_ == nullptr, MSERR_OK, "InputBufferQueue already create");

    inputBufferQueue_ = AVBufferQueue::Create(0,
        MemoryType::UNKNOWN_MEMORY, AV_THUMBNAIL_GENERATOR_INPUT_BUFFER_QUEUE_NAME, true);
    CHECK_AND_RETURN_RET_LOG(inputBufferQueue_ != nullptr, MSERR_NO_MEMORY, "BufferQueue is nullptr");

    inputBufferQueueProducer_ = inputBufferQueue_->GetProducer();
    CHECK_AND_RETURN_RET_LOG(inputBufferQueueProducer_ != nullptr, MSERR_UNKNOWN, "QueueProducer is nullptr");

    inputBufferQueueConsumer_ = inputBufferQueue_->GetConsumer();
    CHECK_AND_RETURN_RET_LOG(inputBufferQueueConsumer_ != nullptr, MSERR_UNKNOWN, "QueueConsumer is nullptr");

    sptr<IConsumerListener> listener = new ThumbnailGeneratorAVBufferAvailableListener(shared_from_this());
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_NO_MEMORY, "listener is nullptr");
    inputBufferQueueConsumer_->SetBufferAvailableListener(listener);

    readTask_ = std::make_unique<Task>(std::string("AVThumbReadLoop"));
    CHECK_AND_RETURN_RET_LOG(readTask_ != nullptr, MSERR_NO_MEMORY, "Task is nullptr");
    readTask_->RegisterJob([this] {return ReadLoop();});
    readTask_->Start();

    return MSERR_OK;
}

void AVThumbnailGenerator::SetClientBundleName(std::string appName)
{
    appName_ = appName;
    return;
}

void AVThumbnailGenerator::AcquireAvailableInputBuffer()
{
    CHECK_AND_RETURN_LOG(inputBufferQueueConsumer_ != nullptr, "QueueConsumer is nullptr");

    std::shared_ptr<AVBuffer> filledInputBuffer;
    Status ret = inputBufferQueueConsumer_->AcquireBuffer(filledInputBuffer);
    CHECK_AND_RETURN_LOG(ret == Status::OK, "AcquireBuffer fail");

    if (fileType_ == FileType::AVI) {
        GetInputBufferDts(filledInputBuffer);
    }
    CHECK_AND_RETURN_LOG(filledInputBuffer != nullptr && filledInputBuffer->meta_ != nullptr,
        "filledInputBuffer is invalid.");
    uint32_t index;
    CHECK_AND_RETURN_LOG(filledInputBuffer->meta_->GetData(Tag::BUFFER_INDEX, index), "get index failed.");

    CHECK_AND_RETURN_LOG(videoDecoder_ != nullptr, "videoDecoder_ is nullptr.");
    if (videoDecoder_->QueueInputBuffer(index) != ERR_OK) {
        MEDIA_LOGE("QueueInputBuffer failed, index: %{public}u,  bufferid: %{public}" PRIu64
            ", pts: %{public}" PRIu64", flag: %{public}u", index, filledInputBuffer->GetUniqueId(),
            filledInputBuffer->pts_, filledInputBuffer->flag_);
    } else {
        MEDIA_LOGD("QueueInputBuffer success, index: %{public}u,  bufferid: %{public}" PRIu64
            ", pts: %{public}" PRIu64", flag: %{public}u", index, filledInputBuffer->GetUniqueId(),
            filledInputBuffer->pts_, filledInputBuffer->flag_);
    }
}

void AVThumbnailGenerator::GetInputBufferDts(std::shared_ptr<AVBuffer> &inputBuffer)
{
    CHECK_AND_RETURN_NOLOG(inputBuffer != nullptr);
    std::unique_lock<std::mutex> lock(dtsQueMutex_);
    inputBufferDtsQue_.push_back(inputBuffer->dts_);
    MEDIA_LOGD("Inputbuffer DTS: %{public}" PRId64 " dtsQue_ size: %{public}" PRIu64,
        inputBuffer->dts_, static_cast<uint64_t>(inputBufferDtsQue_.size()));
}

void AVThumbnailGenerator::InitMediaInfoFromGlobalMeta()
{
    auto meta = mediaDemuxer_->GetGlobalMetaInfo();
    CHECK_AND_RETURN_LOG(meta != nullptr, "Global info is nullptr");
    (void)meta->Get<Tag::MEDIA_DURATION>(duration_);
    MEDIA_LOGI("%{public}" PRId64, duration_);
    CHECK_AND_RETURN_NOLOG(meta->GetData(Tag::MEDIA_FILE_TYPE, fileType_));
    MEDIA_LOGI("file type is: %{public}" PRId32, static_cast<int32_t>(fileType_));
}

std::shared_ptr<Meta> AVThumbnailGenerator::GetVideoTrackInfo()
{
    CHECK_AND_RETURN_RET(trackInfo_ == nullptr, trackInfo_);
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr, nullptr, "GetTargetTrackInfo demuxer is nullptr");
    InitMediaInfoFromGlobalMeta();
    std::vector<std::shared_ptr<Meta>> trackInfos = mediaDemuxer_->GetStreamMetaInfo();
    size_t trackCount = trackInfos.size();
    CHECK_AND_RETURN_RET_LOG(trackCount > 0, nullptr, "GetTargetTrackInfo trackCount is invalid");
    for (size_t index = 0; index < trackCount; index++) {
        CHECK_AND_CONTINUE_LOG(trackInfos[index] != nullptr, "trackInfos[%{public}zu] is nullptr", index);
        if (!(trackInfos[index]->GetData(Tag::MIME_TYPE, trackMime_))) {
            MEDIA_LOGW("GetTargetTrackInfo get mime type failed %{public}s", trackMime_.c_str());
            continue;
        }
        bool isCover = trackInfos[index]->Find(Tag::MEDIA_COVER) != trackInfos[index]->end();
        MEDIA_LOGI("isCover is %{public}d", isCover);
        if (!isCover && trackMime_.find("image/jpeg") == 0) {
            trackMime_ = "video/mjpeg";
        }
        if (trackMime_.find("video/") == 0) {
            Plugins::MediaType mediaType;
            CHECK_AND_RETURN_RET_LOG(trackInfos[index]->GetData(Tag::MEDIA_TYPE, mediaType), nullptr,
                                     "GetTargetTrackInfo failed to get mediaType, index:%{public}zu", index);
            CHECK_AND_RETURN_RET_LOG(
                mediaType == Plugins::MediaType::VIDEO, nullptr,
                "GetTargetTrackInfo mediaType is not video, index:%{public}zu, mediaType:%{public}d", index,
                static_cast<int32_t>(mediaType));
            CHECK_AND_RETURN_RET_LOG(trackInfos[index]->Get<Tag::VIDEO_FRAME_RATE>(frameRate_) && frameRate_ > 0,
                nullptr, "failed to get video frame rate");
            trackIndex_ = index;
            MEDIA_LOGI("0x%{public}06" PRIXPTR " GetTrackInfo success trackIndex_:%{public}zu, trackMime_:%{public}s",
                       FAKE_POINTER(this), trackIndex_, trackMime_.c_str());
            trackInfos[index]->Get<Tag::VIDEO_ROTATION>(rotation_);
            trackInfos[index]->Get<Tag::VIDEO_ORIENTATION_TYPE>(orientation_);
            MEDIA_LOGI("Rotation is %{public}d, orientation is %{public}d", static_cast<int32_t>(rotation_),
                static_cast<int32_t>(orientation_));
            trackInfos[index]->Get<Tag::ORIGINAL_CODEC_NAME>(codecMimeName_);
            MEDIA_LOGI("ORIGINAL_CODEC_NAME is %{public}s", codecMimeName_.c_str());

            return trackInfos[trackIndex_];
        }
    }
    MEDIA_LOGW("GetTargetTrackInfo FAILED.");
    return nullptr;
}

void AVThumbnailGenerator::OnOutputFormatChanged(const MediaAVCodec::Format &format)
{
    MEDIA_LOGD("OnOutputFormatChanged");
    outputFormat_ = format;
    int32_t width = 0;
    int32_t height = 0;
    bool hasWidth = format.GetIntValue(Tag::VIDEO_PIC_WIDTH, width);
    bool hasHeight = format.GetIntValue(Tag::VIDEO_PIC_HEIGHT, height);
    CHECK_AND_RETURN_LOG(hasWidth && hasHeight, "OutputFormat doesn't have width or height");
    width_ = width;
    height_ = height;
}

void AVThumbnailGenerator::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    CHECK_AND_RETURN_LOG(buffer != nullptr && buffer->meta_ != nullptr, "meta_ is nullptr.");

    MEDIA_LOGD("OnInputBufferAvailable enter. index: %{public}u, bufferid: %{public}" PRIu64", pts: %{public}" PRIu64
        ", flag: %{public}u", index, buffer->GetUniqueId(), buffer->pts_, buffer->flag_);

    buffer->meta_->SetData(Tag::BUFFER_INDEX, index);

    CHECK_AND_RETURN_LOG(inputBufferQueueConsumer_ != nullptr, "QueueConsumer is nullptr");

    if (stopProcessing_.load() || hasFetchedFrame_.load() || readErrorFlag_.load()) {
        MEDIA_LOGD("stop or has fetched frame, need not queue input buffer");
        return;
    }

    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        if (inputBufferQueueConsumer_->IsBufferInQueue(buffer)) {
            if (inputBufferQueueConsumer_->ReleaseBuffer(buffer) != Status::OK) {
                MEDIA_LOGE("IsBufferInQueue ReleaseBuffer failed. index: %{public}u, bufferid: %{public}" PRIu64
                    ", pts: %{public}" PRIu64", flag: %{public}u", index, buffer->GetUniqueId(),
                    buffer->pts_, buffer->flag_);
                return;
            } else {
                MEDIA_LOGD("IsBufferInQueue ReleaseBuffer success. index: %{public}u, bufferid: %{public}" PRIu64
                    ", pts: %{public}" PRIu64", flag: %{public}u", index, buffer->GetUniqueId(),
                    buffer->pts_, buffer->flag_);
            }
        } else {
            uint32_t size = inputBufferQueueConsumer_->GetQueueSize() + 1;
            MEDIA_LOGI("AttachBuffer enter. index: %{public}u,  size: %{public}u , bufferid: %{public}" PRIu64,
                index, size, buffer->GetUniqueId());
            inputBufferQueueConsumer_->SetQueueSizeAndAttachBuffer(size, buffer, false);
            bufferVector_.push_back(buffer);
        }
        isBufferAvailable_.store(true);
    }
    bufferAvailableCond_.notify_all();
}

int64_t AVThumbnailGenerator::ReadLoop()
{
    std::shared_ptr<AVBuffer> emptyBuffer = nullptr;
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        bufferAvailableCond_.wait(lock, [this] {
            return stopProcessing_.load() ||
                   (!hasFetchedFrame_.load() && !readErrorFlag_.load() && isBufferAvailable_.load());
        });

        CHECK_AND_RETURN_RET_LOG(!stopProcessing_.load(), StopTask(), "Stop Readloop");

        CHECK_AND_RETURN_RET_LOG(inputBufferQueueProducer_ != nullptr, StopTask(), "QueueProducer is nullptr");

        AVBufferConfig avBufferConfig;
        auto res = inputBufferQueueProducer_->RequestBuffer(emptyBuffer, avBufferConfig, REQUEST_BUFFER_TIMEOUT);
        if (res != Status::OK) {
            isBufferAvailable_.store(false);
            return 0;
        }
    }

    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr, StopTask(), "mediaDemuxer is nullptr");

    auto readSampleRes = mediaDemuxer_->ReadSample(trackIndex_, emptyBuffer);
    if (readSampleRes != Status::OK && readSampleRes != Status::END_OF_STREAM && readSampleRes != Status::ERROR_AGAIN) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            readErrorFlag_.store(true);
        }
        cond_.notify_all();
        inputBufferQueueProducer_->PushBuffer(emptyBuffer, false);
        return 0;
    }
    if (readSampleRes == Status::ERROR_AGAIN) {
        inputBufferQueueProducer_->PushBuffer(emptyBuffer, false);
        return ERROR_AGAIN_SLEEP_TIME_US;
    }
    if (fileType_ == FileType::AVI) {
        SetDemuxerOutputBufferPts(emptyBuffer);
    }
    inputBufferQueueProducer_->PushBuffer(emptyBuffer, true);
    return 0;
}

void AVThumbnailGenerator::SetDemuxerOutputBufferPts(std::shared_ptr<AVBuffer> &outputBuffer)
{
    CHECK_AND_RETURN_NOLOG(outputBuffer != nullptr);
    MEDIA_LOGD("OutputBuffer PTS: %{public}" PRId64 " DTS: %{public}" PRId64, outputBuffer->pts_, outputBuffer->dts_);
    outputBuffer->pts_ = outputBuffer->dts_;
}

int64_t AVThumbnailGenerator::StopTask()
{
    if (readTask_ != nullptr) {
        readTask_->Stop();
        readTaskExited_.store(true);
        readTaskAvailableCond_.notify_all();
    }
    return 0;
}

void AVThumbnailGenerator::SetDecoderOutputBufferPts(std::shared_ptr<AVBuffer> &outputBuffer)
{
    CHECK_AND_RETURN_NOLOG(outputBuffer != nullptr);
    std::unique_lock<std::mutex> lock(dtsQueMutex_);
    if (!inputBufferDtsQue_.empty()) {
        outputBuffer->pts_ = inputBufferDtsQue_.front();
        inputBufferDtsQue_.pop_front();
        MEDIA_LOGD("DecOutputbuf PTS: %{public}" PRId64 " dtsQue_ size: %{public}" PRIu64,
            outputBuffer->pts_, static_cast<uint64_t>(inputBufferDtsQue_.size()));
    } else {
        MEDIA_LOGW("DtsQue_ is empty. DecOutputbuf DTS: %{public}" PRId64, outputBuffer->dts_);
        outputBuffer->pts_ = outputBuffer->dts_;
    }
}

void AVThumbnailGenerator::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
{
    if (fileType_ == FileType::AVI) {
        SetDecoderOutputBufferPts(buffer);
    }
    CHECK_AND_RETURN_LOG(buffer != nullptr, "buffer is nullptr");
    MEDIA_LOGD("OnOutputBufferAvailable index:%{public}u , pts %{public}" PRId64, index, buffer->pts_);
    CHECK_AND_RETURN_LOG(videoDecoder_ != nullptr, "Video decoder not exist");
    bool isEosBuffer = buffer->flag_ & (uint32_t)(AVBufferFlag::EOS);
    bool isValidBuffer = buffer != nullptr && buffer->memory_ != nullptr &&
         (buffer->memory_->GetSize() != 0 || buffer->memory_->GetSurfaceBuffer() != nullptr || isEosBuffer);
    bool isValidState = !hasFetchedFrame_.load() && !stopProcessing_.load();
    if (!isValidBuffer || !isValidState) {
        MEDIA_LOGW("isValidBuffer %{public}d isValidState %{public}d", isValidBuffer, isValidState);
        videoDecoder_->ReleaseOutputBuffer(index, false);
        return;
    }
    bool isClosest = seekMode_ == Plugins::SeekMode::SEEK_CLOSEST;
    bool isAvailableFrame = !isClosest || buffer->pts_ >= seekTime_ || isEosBuffer;
    if (!isAvailableFrame) {
        videoDecoder_->ReleaseOutputBuffer(bufferIndex_, false);
        bufferIndex_ = index;
        avBuffer_ = buffer;
        return;
    }
    
    {
        std::unique_lock<std::mutex> lock(mutex_);
        hasFetchedFrame_.store(true);
    }
    if (isClosest && avBuffer_ != nullptr) {
        int64_t preDiff = seekTime_ - avBuffer_->pts_;
        int64_t nextDiff = buffer->pts_ - seekTime_;
        if (preDiff > nextDiff && !(buffer->flag_ & (uint32_t)(AVBufferFlag::EOS))) {
            videoDecoder_->ReleaseOutputBuffer(bufferIndex_, false);
            bufferIndex_ = index;
            avBuffer_ = buffer;
        } else {
            videoDecoder_->ReleaseOutputBuffer(index, false);
        }
    } else {
        bufferIndex_ = index;
        avBuffer_ = buffer;
    }
    MEDIA_LOGI("dstTime %{public}" PRId64 " resTime %{public}" PRId64, seekTime_, buffer->pts_);
    MEDIA_LOGI("dstTime %{public}" PRId64 " avBuffer_resTime %{public}" PRId64, seekTime_, avBuffer_->pts_);
    cond_.notify_all();
    PauseFetchFrame();
}

std::shared_ptr<AVSharedMemory> AVThumbnailGenerator::FetchFrameAtTime(int64_t timeUs, int32_t option,
                                                                       const OutputConfiguration &param)
{
    MEDIA_LOGI("Fetch frame 0x%{public}06" PRIXPTR " timeUs:%{public}" PRId64 ", option:%{public}d,"
               "dstWidth:%{public}d, dstHeight:%{public}d, colorFormat:%{public}d",
               FAKE_POINTER(this), timeUs, option, param.dstWidth, param.dstHeight,
               static_cast<int32_t>(param.colorFormat));
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr, nullptr, "FetchFrameAtTime demuxer is nullptr");

    readErrorFlag_.store(false);
    hasFetchedFrame_.store(false);
    isBufferAvailable_.store(false);
    outputConfig_ = param;
    seekTime_ = timeUs;
    trackInfo_ = GetVideoTrackInfo();
    CHECK_AND_RETURN_RET_LOG(trackInfo_ != nullptr, nullptr, "FetchFrameAtTime trackInfo_ is nullptr.");
    mediaDemuxer_->Resume();
    mediaDemuxer_->SelectTrack(trackIndex_);
    int64_t realSeekTime = timeUs;
    auto res = SeekToTime(Plugins::Us2Ms(timeUs), static_cast<Plugins::SeekMode>(option), realSeekTime);
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, nullptr, "Seek fail");
    CHECK_AND_RETURN_RET_LOG(InitDecoder() == Status::OK, nullptr, "FetchFrameAtTime InitDecoder failed.");
    bool fetchFrameRes = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);

        // wait up to 3s to fetch frame AVSharedMemory at time.
        fetchFrameRes = cond_.wait_for(lock, std::chrono::seconds(MAX_WAIT_TIME_SECOND),
            [this] { return hasFetchedFrame_.load() || readErrorFlag_.load() || stopProcessing_.load(); });
    }
    if (fetchFrameRes) {
        HandleFetchFrameAtTimeRes();
    } else {
        PauseFetchFrame();
    }
    return fetchedFrameAtTime_;
}

void AVThumbnailGenerator::HandleFetchFrameAtTimeRes()
{
    CHECK_AND_RETURN_RET_LOG(!readErrorFlag_.load(), PauseFetchFrame(), "ReadSample error, exit fetchFrame");
    CHECK_AND_RETURN_RET_LOG(!stopProcessing_.load(), PauseFetchFrame(), "Destroy or Decoder error, exit fetchFrame");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Fetch frame OK width:%{public}d, height:%{public}d",
            FAKE_POINTER(this), outputConfig_.dstWidth, outputConfig_.dstHeight);
    ConvertToAVSharedMemory();
    videoDecoder_->ReleaseOutputBuffer(bufferIndex_, false);
}

void AVThumbnailGenerator::DfxReport(std::string apiCall)
{
    nlohmann::json metaInfoJson;
    OHOS::Media::MediaEvent event;
    if (mediaDemuxer_ == nullptr) {
        std::string events = metaInfoJson.dump();
        event.MediaKitStatistics("AVImageGenerator", appName_, std::to_string(appPid_), apiCall, events);
        return;
    }
    const std::shared_ptr<Meta> globalInfo = mediaDemuxer_->GetGlobalMetaInfo();
    Plugins::FileType fileType =  Plugins::FileType::UNKNOW;
    globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType);
    metaInfoJson["fileType"] = static_cast<int32_t>(fileType);
    const std::vector<std::shared_ptr<Meta>> trackInfos = mediaDemuxer_->GetStreamMetaInfo();
    size_t trackCount = trackInfos.size();
    for (size_t index = 0; index < trackCount; index++) {
        std::shared_ptr<Meta> meta = trackInfos[index];
        CHECK_AND_RETURN_LOG(meta != nullptr, "DfxReport meta is nullptr");
        std::string mime;
        meta->Get<Tag::MIME_TYPE>(mime);
        if (mime.find("video/") == 0) {
            metaInfoJson["videoMime"] = mime;
            int32_t originalWidth = 0;
            meta->GetData(Tag::VIDEO_WIDTH, originalWidth);
            metaInfoJson["originalWidth"] = originalWidth;
            int32_t originalHeight = 0;
            meta->GetData(Tag::VIDEO_HEIGHT, originalHeight);
            metaInfoJson["originalHeight"] = originalHeight;
            double frameRate = 0;
            if (meta->GetData(Tag::VIDEO_FRAME_RATE, frameRate)) {
                metaInfoJson["frameRate"] = frameRate;
            }
        }
        if (mime.find("audio/") == 0) {
            metaInfoJson["audioMime"] = mime;
        }
    }
    std::string events = metaInfoJson.dump();
    event.MediaKitStatistics("AVImageGenerator", appName_, std::to_string(appPid_), apiCall, events);
}

std::shared_ptr<AVBuffer> AVThumbnailGenerator::FetchFrameYuv(int64_t timeUs, int32_t option,
                                                              const OutputConfiguration &param)
{
    MEDIA_LOGI("Fetch frame 0x%{public}06" PRIXPTR " timeUs:%{public}" PRId64 ", option:%{public}d,"
               "dstWidth:%{public}d, dstHeight:%{public}d, colorFormat:%{public}d", FAKE_POINTER(this), timeUs, option,
               param.dstWidth, param.dstHeight, static_cast<int32_t>(param.colorFormat));
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr, nullptr, "FetchFrameAtTime demuxer is nullptr");
    ResetParamsBeforeFetchFrame(timeUs, option, param);

    trackInfo_ = GetVideoTrackInfo();
    CHECK_AND_RETURN_RET_LOG(trackInfo_ != nullptr, nullptr, "FetchFrameAtTime trackInfo_ is nullptr.");

    mediaDemuxer_->SelectTrack(trackIndex_);
    int64_t realSeekTime = timeUs;
    auto res = SeekToTime(Plugins::Us2Ms(timeUs), static_cast<Plugins::SeekMode>(option), realSeekTime);
    if (res == Status::END_OF_STREAM && fileType_ == FileType::MPEGTS
        && (codecMimeName_ == "mpeg4" || codecMimeName_ == "vc1")) {
        std::shared_ptr<AVBuffer> mpeg4EosBuffer(AVBuffer::CreateAVBuffer());
        mpeg4EosBuffer->flag_ = (uint32_t)(AVBufferFlag::EOS);
        return mpeg4EosBuffer;
    }
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, nullptr, "Seek fail");
    CHECK_AND_RETURN_RET_LOG(InitDecoder() == Status::OK, nullptr, "FetchFrameAtTime InitDecoder failed.");
    DfxReport("AVImageGenerator call");
    bool fetchFrameRes = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        // wait up to 3s to fetch frame AVSharedMemory at time.
        fetchFrameRes = cond_.wait_for(lock, std::chrono::seconds(MAX_WAIT_TIME_SECOND),
            [this] { return hasFetchedFrame_.load() || readErrorFlag_.load() || stopProcessing_.load(); });
    }

    MEDIA_LOGI("FetchFrameYuv, retry fetch frame");
    if (hasReceivedCodecErrCodeOfUnsupported_.load()) {
        stopProcessing_.store(false);
        SwitchToSoftWareDecoder();
        {
        std::unique_lock fetchFrameLock(mutex_);
        MEDIA_LOGI("FetchFrameYuv, retry fetch frame, wait for the lock");
        fetchFrameRes = cond_.wait_for(fetchFrameLock, std::chrono::seconds(MAX_WAIT_TIME_SECOND),
            [this] { return hasFetchedFrame_.load() || readErrorFlag_.load() || stopProcessing_.load(); });
        }
    }

    if (fetchFrameRes) {
        HandleFetchFrameYuvRes();
    } else {
        DfxReport("AVImageGenerator fail");
        HandleFetchFrameYuvFailed();
    }
    return avBuffer_;
}

std::shared_ptr<AVBuffer> AVThumbnailGenerator::FetchFrameYuvs(int64_t timeUs, int32_t option,
    const OutputConfiguration &param, bool &errCallback)
{
    MEDIA_LOGI("Fetch frame 0x%{public}06" PRIXPTR " timeUs:%{public}" PRId64 ", option:%{public}d,"
               "dstWidth:%{public}d, dstHeight:%{public}d, colorFormat:%{public}d",
               FAKE_POINTER(this), timeUs, option, param.dstWidth, param.dstHeight,
               static_cast<int32_t>(param.colorFormat));
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr, nullptr, "FetchFrameAtTime demuxer is nullptr");
    ResetParamsBeforeFetchFrame(timeUs, option, param);

    trackInfo_ = GetVideoTrackInfo();
    CHECK_AND_RETURN_RET_LOG(trackInfo_ != nullptr, nullptr, "FetchFrameAtTime trackInfo_ is nullptr.");
    mediaDemuxer_->SelectTrack(trackIndex_);
    int64_t realSeekTime = timeUs;
    auto res = SeekToTime(Plugins::Us2Ms(timeUs), static_cast<Plugins::SeekMode>(option), realSeekTime);
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, nullptr, "Seek fail");
    CHECK_AND_RETURN_RET_LOG(InitDecoder() == Status::OK, nullptr, "FetchFrameAtTime InitDecoder failed.");
    bool fetchFrameRes = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        // wait up to 3s to fetch frame AVSharedMemory at time.
        fetchFrameRes = cond_.wait_for(lock, std::chrono::seconds(MAX_WAIT_TIME_SECOND),
            [this] { return hasFetchedFrame_.load() || readErrorFlag_.load() || stopProcessing_.load(); });
    }

    if (hasReceivedCodecErrCodeOfUnsupported_.load()) {
        stopProcessing_.store(false);
        SwitchToSoftWareDecoder();
        {
            std::unique_lock fetchFrameLock(mutex_);
            fetchFrameRes = cond_.wait_for(fetchFrameLock, std::chrono::seconds(MAX_WAIT_TIME_SECOND),
                [this] { return hasFetchedFrame_.load() || readErrorFlag_.load() || stopProcessing_.load(); });
        }
    }
    if (fetchFrameRes) {
        HandleFetchFrameYuvRes();
    } else {
        errCallback = true;
        HandleFetchFrameYuvFailed();
    }
    return avBuffer_;
}

void AVThumbnailGenerator::ResetParamsBeforeFetchFrame(int64_t timeUs, int32_t option, const OutputConfiguration &param)
{
    avBuffer_ = nullptr;
    readErrorFlag_.store(false);
    hasFetchedFrame_.store(false);
    isBufferAvailable_.store(false);
    hasReceivedCodecErrCodeOfUnsupported_.store(false);
    outputConfig_ = param;
    seekTime_ = timeUs;
    currentFetchFrameYuvTimeUs_ = timeUs;
    currentFetchFrameYuvOption_ = option;
}

void AVThumbnailGenerator::HandleFetchFrameYuvRes()
{
    CHECK_AND_RETURN_RET_LOG(!readErrorFlag_.load(), HandleFetchFrameYuvFailed(), "ReadSample error, exit fetchFrame");
    CHECK_AND_RETURN_RET_LOG(!stopProcessing_.load(), HandleFetchFrameYuvFailed(),
                             "Destroy or Decoder error, exit fetchFrame");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Fetch frame OK width:%{public}d, height:%{public}d",
                FAKE_POINTER(this), outputConfig_.dstWidth, outputConfig_.dstHeight);
    avBuffer_ = GenerateAlignmentAvBuffer();
    if (avBuffer_ != nullptr && avBuffer_->meta_ != nullptr) {
        avBuffer_->meta_->Set<Tag::VIDEO_WIDTH>(width_);
        avBuffer_->meta_->Set<Tag::VIDEO_HEIGHT>(height_);
        avBuffer_->meta_->Set<Tag::VIDEO_ROTATION>(rotation_);
        avBuffer_->meta_->Set<Tag::VIDEO_ORIENTATION_TYPE>(orientation_);
    }
}

void AVThumbnailGenerator::HandleFetchFrameYuvFailed()
{
    CHECK_AND_RETURN_LOG(videoDecoder_ != nullptr, "videoDecoder_ is nullptr");
    videoDecoder_->ReleaseOutputBuffer(bufferIndex_, false);
    PauseFetchFrame();
}

Status AVThumbnailGenerator::SeekToTime(int64_t timeMs, Plugins::SeekMode option, int64_t realSeekTime)
{
    seekMode_ = option;
    if (option == Plugins::SeekMode::SEEK_CLOSEST) {
        option = Plugins::SeekMode::SEEK_PREVIOUS_SYNC;
    }
    timeMs = duration_ > 0 ? std::min(timeMs, Plugins::Us2Ms(duration_)) : timeMs;
    Status res = Status::OK;
    if (fileType_ == FileType::MPEGTS && (codecMimeName_ == "mpeg4" || codecMimeName_ == "vc1")) {
        res = mediaDemuxer_->SeekToKeyFrame(timeMs, option, realSeekTime, MediaDemuxer::CallerType::AVMETADATA);
    } else {
        res = mediaDemuxer_->SeekTo(timeMs, option, realSeekTime);
    }
    /* SEEK_NEXT_SYNC or SEEK_PREVIOUS_SYNC may cant find I frame and return seek failed
       if seek failed, use SEEK_CLOSEST_SYNC seek again */
    if (res != Status::OK && option != Plugins::SeekMode::SEEK_CLOSEST_SYNC
        && (fileType_ != FileType::MPEGTS || codecMimeName_ != "mpeg4")
        && (fileType_ != FileType::MPEGTS || codecMimeName_ != "vc1")) {
        res = mediaDemuxer_->SeekTo(timeMs, Plugins::SeekMode::SEEK_CLOSEST_SYNC, realSeekTime);
        seekMode_ = Plugins::SeekMode::SEEK_CLOSEST_SYNC;
    }
    return res;
}

void AVThumbnailGenerator::ConvertToAVSharedMemory()
{
    auto surfaceBuffer = avBuffer_->memory_->GetSurfaceBuffer();
    if (surfaceBuffer != nullptr) {
        auto ret = GetYuvDataAlignStride(surfaceBuffer);
        CHECK_AND_RETURN_LOG(ret == MSERR_OK, "Copy frame failed");
        OutputFrame *frame = reinterpret_cast<OutputFrame *>(fetchedFrameAtTime_->GetBase());
        frame->width_ = surfaceBuffer->GetWidth();
        frame->height_ = surfaceBuffer->GetHeight();
        frame->stride_ = frame->width_ * RATE_UV;
        frame->bytesPerPixel_ = RATE_UV;
        frame->size_ = frame->width_ * frame->height_ * BYTES_PER_PIXEL_YUV;
        frame->rotation_ = static_cast<int32_t>(rotation_);
        return;
    }

    int32_t width;
    int32_t height;
    outputFormat_.GetIntValue(MediaDescriptionKey::MD_KEY_WIDTH, width);
    outputFormat_.GetIntValue(MediaDescriptionKey::MD_KEY_HEIGHT, height);
    if (width == 0 || height == 0) {
        width = width_;
        height = height_;
    }

    fetchedFrameAtTime_ = std::make_shared<AVSharedMemoryBase>(sizeof(OutputFrame) + avBuffer_->memory_->GetSize(),
        AVSharedMemory::Flags::FLAGS_READ_WRITE, "FetchedFrameMemory");
    int32_t ret = fetchedFrameAtTime_->Init();
    CHECK_AND_RETURN_LOG(ret == static_cast<int32_t>(Status::OK), "Create AVSharedmemory failed, ret:%{public}d", ret);
    OutputFrame *frame = reinterpret_cast<OutputFrame *>(fetchedFrameAtTime_->GetBase());
    frame->width_ = width;
    frame->height_ = height;
    frame->stride_ = width * RATE_UV;
    frame->bytesPerPixel_ = RATE_UV;
    frame->size_ = avBuffer_->memory_->GetSize();
    frame->rotation_ = static_cast<int32_t>(rotation_);
    fetchedFrameAtTime_->Write(avBuffer_->memory_->GetAddr(), frame->size_, sizeof(OutputFrame));
}

void AVThumbnailGenerator::ConvertP010ToNV12(const sptr<SurfaceBuffer> &surfaceBuffer, uint8_t *dstNV12,
                                             int32_t strideWidth, int32_t strideHeight)
{
    int32_t width = surfaceBuffer->GetWidth();
    int32_t height = surfaceBuffer->GetHeight();
    uint8_t *srcP010 = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr());

    // copy src Y component to dst
    for (int32_t i = 0; i < height; i++) {
        uint16_t *srcY = reinterpret_cast<uint16_t *>(srcP010 + strideWidth * i);
        uint8_t *dstY = dstNV12 + width * i;
        for (int32_t j = 0; j < width; j++) {
            *dstY = static_cast<uint8_t>(*srcY >> SHIFT_BITS_P010_2_NV12);
            srcY++;
            dstY++;
        }
    }

    uint8_t *maxDstAddr = dstNV12 + width * height + width * height / RATE_UV;
    uint8_t *originSrcAddr = srcP010;
    uint16_t *maxSrcAddr = reinterpret_cast<uint16_t *>(originSrcAddr) + surfaceBuffer->GetSize();

    srcP010 = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + strideWidth * strideHeight;
    dstNV12 = dstNV12 + width * height;

    // copy src UV component to dst, height(UV) = height(Y) / 2;
    for (int32_t i = 0; i < height / 2; i++) {
        uint16_t *srcUV = reinterpret_cast<uint16_t *>(srcP010 + strideWidth * i);
        uint8_t *dstUV = dstNV12 + width * i;
        for (int32_t j = 0; j < width && srcUV < maxSrcAddr && dstUV < maxDstAddr; j++) {
            *dstUV = static_cast<uint8_t>(*srcUV >> SHIFT_BITS_P010_2_NV12);
            *(dstUV + 1) = static_cast<uint8_t>(*(srcUV + 1) >> SHIFT_BITS_P010_2_NV12);
            srcUV += 2;  // srcUV move by 2 to process U and V component
            dstUV += 2;  // dstUV move by 2 to process U and V component
        }
    }
}

std::shared_ptr<AVBuffer> AVThumbnailGenerator::GenerateAlignmentAvBuffer()
{
    CHECK_AND_RETURN_RET_LOG(avBuffer_ != nullptr && avBuffer_->memory_ != nullptr, nullptr,
        "Generate Alignment AvBuffer failed, avBuffer_ or avBuffer_->memory_ is nullptr.");
    if (avBuffer_->memory_->GetSize() != 0 && avBuffer_->memory_->GetSurfaceBuffer() == nullptr) {
        return GenerateAvBufferFromFCodec();
    }
    CHECK_AND_RETURN_RET_LOG(avBuffer_->memory_->GetSurfaceBuffer() != nullptr, nullptr,
        "Memory size is 0, SurfaceBuffer is nullptr.");
    auto srcSurfaceBuffer = avBuffer_->memory_->GetSurfaceBuffer();
    auto width = srcSurfaceBuffer->GetWidth();
    auto height = srcSurfaceBuffer->GetHeight();
    bool isHdr = srcSurfaceBuffer->GetFormat() ==
                 static_cast<int32_t>(GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010);

    sptr<SurfaceBuffer> dstSurfaceBuffer = SurfaceBuffer::Create();
    BufferRequestConfig requestConfig = {
        .width = width,
        .height = height,
        .strideAlignment = 0x2,
        .format = srcSurfaceBuffer->GetFormat(),  // always yuv
        .usage = srcSurfaceBuffer->GetUsage(),
        .timeout = 0,
    };
    CHECK_AND_RETURN_RET_LOG(dstSurfaceBuffer != nullptr, nullptr, "Create surfaceBuffer failed");
    GSError allocRes = dstSurfaceBuffer->Alloc(requestConfig);
    CHECK_AND_RETURN_RET_LOG(allocRes == 0, nullptr, "Alloc surfaceBuffer failed, ecode %{public}d", allocRes);

    CopySurfaceBufferInfo(srcSurfaceBuffer, dstSurfaceBuffer);
    int32_t copyRes = memcpy_s(dstSurfaceBuffer->GetVirAddr(), dstSurfaceBuffer->GetSize(),
                               srcSurfaceBuffer->GetVirAddr(), srcSurfaceBuffer->GetSize());
    CHECK_AND_RETURN_RET_LOG(copyRes == EOK, nullptr, "copy surface buffer pixels failed, copyRes %{public}d", copyRes);
    int32_t outputHeight;
    auto hasSliceHeight = outputFormat_.GetIntValue(Tag::VIDEO_SLICE_HEIGHT, outputHeight);
    if (!hasSliceHeight || outputHeight < height) {
        outputHeight = height;
    }

    // create avBuffer from surfaceBuffer
    std::shared_ptr<AVBuffer> targetAvBuffer = AVBuffer::CreateAVBuffer(dstSurfaceBuffer);
    bool ret = targetAvBuffer && targetAvBuffer->memory_ && targetAvBuffer->meta_ &&
               targetAvBuffer->memory_->GetSurfaceBuffer() != nullptr;
    CHECK_AND_RETURN_RET_LOG(ret, nullptr, "create avBuffer failed");
    targetAvBuffer->meta_->Set<Tag::VIDEO_IS_HDR_VIVID>(isHdr);
    targetAvBuffer->meta_->Set<Tag::VIDEO_SLICE_HEIGHT>(outputHeight);
    targetAvBuffer->flag_ = avBuffer_->flag_;
    targetAvBuffer->dts_ = avBuffer_->dts_;
    targetAvBuffer->pts_ = avBuffer_->pts_;
    return targetAvBuffer;
}

std::shared_ptr<AVBuffer> AVThumbnailGenerator::GenerateAvBufferFromFCodec()
{
    AVBufferConfig avBufferConfig;
    avBufferConfig.size = avBuffer_->memory_->GetSize();
    avBufferConfig.memoryType = MemoryType::SHARED_MEMORY;
    avBufferConfig.memoryFlag = MemoryFlag::MEMORY_READ_WRITE;
    std::shared_ptr<AVBuffer> targetAvBuffer = AVBuffer::CreateAVBuffer(avBufferConfig);
    CHECK_AND_RETURN_RET_LOG(targetAvBuffer != nullptr && targetAvBuffer->memory_ != nullptr, nullptr,
        "Create avBuffer failed");
    targetAvBuffer->memory_->Write(avBuffer_->memory_->GetAddr(), avBuffer_->memory_->GetSize(), 0);
    targetAvBuffer->flag_ = avBuffer_->flag_;
    targetAvBuffer->dts_ = avBuffer_->dts_;
    targetAvBuffer->pts_ = avBuffer_->pts_;
    return targetAvBuffer;
}

int32_t AVThumbnailGenerator::GetYuvDataAlignStride(const sptr<SurfaceBuffer> &surfaceBuffer)
{
    int32_t width = surfaceBuffer->GetWidth();
    int32_t height = surfaceBuffer->GetHeight();
    int32_t stride = surfaceBuffer->GetStride();
    int32_t outputHeight;
    auto hasSliceHeight = outputFormat_.GetIntValue(Tag::VIDEO_SLICE_HEIGHT, outputHeight);
    if (!hasSliceHeight || outputHeight < height) {
        outputHeight = height;
    }
    MEDIA_LOGD("GetYuvDataAlignStride stride:%{public}d, strideWidth:%{public}d, outputHeight:%{public}d", stride,
               stride, outputHeight);

    fetchedFrameAtTime_ =
        std::make_shared<AVSharedMemoryBase>(sizeof(OutputFrame) + width * height * BYTES_PER_PIXEL_YUV,
            AVSharedMemory::Flags::FLAGS_READ_WRITE, "FetchedFrameMemory");
    auto ret = fetchedFrameAtTime_->Init();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "Create AVSharedmemory failed, ret:%{public}d", ret);
    uint8_t *dstPtr = static_cast<uint8_t *>(sizeof(OutputFrame) + fetchedFrameAtTime_->GetBase());
    uint8_t *srcPtr = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr());
    int32_t format = surfaceBuffer->GetFormat();
    if (format == static_cast<int32_t>(GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010)) {
        ConvertP010ToNV12(surfaceBuffer, dstPtr, stride, outputHeight);
        return MSERR_OK;
    }

    // copy src Y component to dst
    for (int32_t y = 0; y < height; y++) {
        auto ret = memcpy_s(dstPtr, width, srcPtr, width);
        if (ret != EOK) {
            MEDIA_LOGW("Memcpy Y component failed.");
        }
        srcPtr += stride;
        dstPtr += width;
    }

    srcPtr = static_cast<uint8_t *>(surfaceBuffer->GetVirAddr()) + stride * outputHeight;

    // copy src UV component to dst, height(UV) = height(Y) / 2
    for (int32_t uv = 0; uv < height / 2; uv++) {
        auto ret = memcpy_s(dstPtr, width, srcPtr, width);
        if (ret != EOK) {
            MEDIA_LOGW("Memcpy UV component failed.");
        }
        srcPtr += stride;
        dstPtr += width;
    }
    return MSERR_OK;
}

void AVThumbnailGenerator::Reset()
{
    if (mediaDemuxer_ != nullptr) {
        mediaDemuxer_->Reset();
    }

    if (videoDecoder_ != nullptr) {
        videoDecoder_->Reset();
    }

    FlushBufferQueue();

    hasFetchedFrame_.store(false);
    hasReceivedCodecErrCodeOfUnsupported_ = false;
    fileType_ = FileType::UNKNOW;
    trackInfo_ = nullptr;
}

void AVThumbnailGenerator::FlushBufferQueue()
{
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        if (inputBufferQueueConsumer_ != nullptr) {
            for (auto &buffer : bufferVector_) {
                inputBufferQueueConsumer_->DetachBuffer(buffer);
            }
            bufferVector_.clear();
            inputBufferQueueConsumer_->SetQueueSize(0);
        }
        isBufferAvailable_.store(false);
    }
    {
        std::unique_lock<std::mutex> lock(dtsQueMutex_);
        if (!inputBufferDtsQue_.empty()) {
            MEDIA_LOGI("Clear dtsQue_, currrent size: %{public}" PRIu64,
                static_cast<uint64_t>(inputBufferDtsQue_.size()));
            inputBufferDtsQue_.clear();
        }
    }
}

void AVThumbnailGenerator::CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst)
{
    if (source == nullptr || dst == nullptr) {
        MEDIA_LOGI("CopySurfaceBufferInfo failed, source or dst is nullptr");
        return;
    }
    std::vector<uint8_t> hdrMetadataTypeVec;
    std::vector<uint8_t> colorSpaceInfoVec;
    std::vector<uint8_t> staticData;
    std::vector<uint8_t> dynamicData;

    if (source->GetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec) == GSERROR_OK) {
        dst->SetMetadata(ATTRKEY_HDR_METADATA_TYPE, hdrMetadataTypeVec);
    }
    if (source->GetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec) == GSERROR_OK) {
        dst->SetMetadata(ATTRKEY_COLORSPACE_INFO, colorSpaceInfoVec);
    }
    if (GetSbStaticMetadata(source, staticData) && (staticData.size() > 0)) {
        SetSbStaticMetadata(dst, staticData);
    }
    if (GetSbDynamicMetadata(source, dynamicData) && (dynamicData.size()) > 0) {
        SetSbDynamicMetadata(dst, dynamicData);
    }
}

bool AVThumbnailGenerator::GetSbStaticMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &staticMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

bool AVThumbnailGenerator::GetSbDynamicMetadata(const sptr<SurfaceBuffer> &buffer,
                                                std::vector<uint8_t> &dynamicMetadata)
{
    return buffer->GetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

bool AVThumbnailGenerator::SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &staticMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_STATIC_METADATA, staticMetadata) == GSERROR_OK;
}

bool AVThumbnailGenerator::SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer,
                                                const std::vector<uint8_t> &dynamicMetadata)
{
    return buffer->SetMetadata(ATTRKEY_HDR_DYNAMIC_METADATA, dynamicMetadata) == GSERROR_OK;
}

void AVThumbnailGenerator::Destroy()
{
    {
        std::unique_lock<std::mutex> lock(queueMutex_);
        stopProcessing_.store(true);
    }
    bufferAvailableCond_.notify_all();

    if (readTask_ != nullptr) {
        readTask_->Stop();
    }

    if (videoDecoder_ != nullptr) {
        videoDecoder_->Stop();
        videoDecoder_->Release();
    }
    mediaDemuxer_ = nullptr;
    videoDecoder_ = nullptr;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Finish Destroy.", FAKE_POINTER(this));
}

void AVThumbnailGenerator::PauseFetchFrame()
{
    hasFetchedFrame_.store(true);
    mediaDemuxer_->Pause();
    mediaDemuxer_->Flush();
    videoDecoder_->Flush();
    Format format;
    format.PutDoubleValue(MediaDescriptionKey::MD_KEY_FRAME_RATE, frameRate_);
    videoDecoder_->SetParameter(format);
    FlushBufferQueue();
}
}  // namespace Media
}  // namespace OHOS