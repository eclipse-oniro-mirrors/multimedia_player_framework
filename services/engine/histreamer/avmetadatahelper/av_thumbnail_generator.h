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

#ifndef AV_THUMBNAIL_GENERATOR
#define AV_THUMBNAIL_GENERATOR

#include <unordered_map>
#include <set>
#include <deque>
#include <condition_variable>
#include <mutex>
#include <nocopyable.h>

#include "buffer/avsharedmemorybase.h"
#include "common/status.h"
#include "i_avmetadatahelper_service.h"
#include "media_demuxer.h"
#include "pipeline/pipeline.h"
#include "video_decoder_adapter.h"
#include "buffer/avbuffer.h"

namespace OHOS {
namespace Media {
class AVThumbnailGenerator : public NoCopyable, public std::enable_shared_from_this<AVThumbnailGenerator> {
public:
    explicit AVThumbnailGenerator(std::shared_ptr<MediaDemuxer> &mediaDemuxer, int32_t appUid, int32_t appPid,
        uint32_t appTokenId, uint64_t appFullTokenId);
    ~AVThumbnailGenerator();
    std::shared_ptr<AVSharedMemory> FetchFrameAtTime(int64_t timeUs, int32_t option, const OutputConfiguration &param);
    std::shared_ptr<AVBuffer> FetchFrameYuv(int64_t timeUs, int32_t option, const OutputConfiguration &param);
    std::shared_ptr<AVBuffer> FetchFrameYuvs(int64_t timeUs, int32_t option, const OutputConfiguration &param,
        bool &errCallback);
    std::shared_ptr<AVSharedMemory> FetchArtPicture();

    void DfxReport(std::string apiCall);
    void Reset();
    void Destroy();
    void OnEvent(const Event &event);
    void OnCallback(std::shared_ptr<OHOS::Media::Pipeline::Filter> filter,
        const OHOS::Media::Pipeline::FilterCallBackCommand cmd, OHOS::Media::Pipeline::StreamType outType);
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void OnOutputFormatChanged(const MediaAVCodec::Format &format);
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer);
    void OnFetchedFrameBufferAvailable();
    int32_t Init();
    void SetClientBundleName(std::string appName);
    void AcquireAvailableInputBuffer();

private:
    OutputConfiguration outputConfig_;
    Format outputFormat_;
    int64_t seekTime_{0};
    std::atomic_bool hasFetchedFrame_{ false };
    std::atomic_bool stopProcessing_{ false };
    std::atomic_bool readErrorFlag_{ false };
    std::atomic_bool isBufferAvailable_{ false };
    std::atomic_bool readTaskExited_{ false };
    std::string trackMime_;
    Plugins::VideoRotation rotation_ = Plugins::VideoRotation::VIDEO_ROTATION_0;
    Plugins::VideoOrientationType orientation_ = Plugins::VideoOrientationType::ROTATE_NONE;
    size_t trackIndex_{0};
    std::shared_ptr<Meta> trackInfo_;
    std::mutex mutex_;
    std::mutex queueMutex_;
    std::mutex dtsQueMutex_;
    std::mutex onErrorMutex_;
    std::mutex readTaskMutex_;
    FileType fileType_ = FileType::UNKNOW;
    std::deque<int64_t> inputBufferDtsQue_;
    std::condition_variable cond_;
    std::condition_variable bufferAvailableCond_;
    std::condition_variable readTaskAvailableCond_;
    std::atomic<uint32_t> bufferIndex_;
    std::shared_ptr<AVBuffer> avBuffer_;
    sptr<SurfaceBuffer> surfaceBuffer_;
    std::shared_ptr<AVSharedMemoryBase> fetchedFrameAtTime_;
    std::shared_ptr<OHOS::Media::MediaDemuxer> mediaDemuxer_;
    std::shared_ptr<MediaAVCodec::AVCodecVideoDecoder> videoDecoder_;
    std::shared_ptr<Media::AVBufferQueue> inputBufferQueue_;
    sptr<Media::AVBufferQueueProducer> inputBufferQueueProducer_;
    sptr<Media::AVBufferQueueConsumer> inputBufferQueueConsumer_;
    std::unique_ptr<Task> readTask_ = nullptr;
    std::vector<std::shared_ptr<AVBuffer>> bufferVector_;

    Status InitDecoder(const std::string& codecName = "");
    void SwitchToSoftWareDecoder();
    std::shared_ptr<Meta> GetVideoTrackInfo();
    void SetDemuxerOutputBufferPts(std::shared_ptr<AVBuffer> &outputBuffer);
    void GetInputBufferDts(std::shared_ptr<AVBuffer> &inputBuffer);
    void SetDecoderOutputBufferPts(std::shared_ptr<AVBuffer> &outputBuffer);
    void ConvertToAVSharedMemory();
    void ConvertP010ToNV12(
        const sptr<SurfaceBuffer> &surfaceBuffer, uint8_t *dstNV12, int32_t strideWidth, int32_t strideHeight);
    int32_t GetYuvDataAlignStride(const sptr<SurfaceBuffer> &surfaceBuffer);
    Status SeekToTime(int64_t timeMs, Plugins::SeekMode option, int64_t realSeekTime);
    int32_t width_ = 0;
    int32_t height_ = 0;
    int32_t appUid_{0};
    int32_t appPid_{0};
    uint32_t appTokenId_{0};
    uint64_t appFullTokenId_{0};
    std::string appName_;
    double frameRate_ { 0.0 };
    Plugins::SeekMode seekMode_ {};
    int64_t duration_ = 0;
    bool hasReceivedCodecErrCodeOfUnsupported_ = false;
    int64_t currentFetchFrameYuvTimeUs_ = 0;
    int32_t currentFetchFrameYuvOption_ = 0;

    std::shared_ptr<AVBuffer> GenerateAlignmentAvBuffer();
    std::shared_ptr<AVBuffer> GenerateAvBufferFromFCodec();
    void CopySurfaceBufferInfo(sptr<SurfaceBuffer> &source, sptr<SurfaceBuffer> &dst);
    bool GetSbStaticMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &staticMetadata);
    bool GetSbDynamicMetadata(const sptr<SurfaceBuffer> &buffer, std::vector<uint8_t> &dynamicMetadata);
    bool SetSbStaticMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &staticMetadata);
    bool SetSbDynamicMetadata(sptr<SurfaceBuffer> &buffer, const std::vector<uint8_t> &dynamicMetadata);

    void HandleFetchFrameYuvRes();
    void HandleFetchFrameYuvFailed();
    void HandleFetchFrameAtTimeRes();

    void PauseFetchFrame();
    void InitMediaInfoFromGlobalMeta();
    int64_t ReadLoop();
    void FlushBufferQueue();
    int64_t StopTask();
};
}  // namespace Media
}  // namespace OHOS
#endif  // AV_THUMBNAIL_GENERATOR