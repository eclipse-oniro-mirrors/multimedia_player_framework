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

#ifndef AVMETADATAHELPER_HST_IMPL_H
#define AVMETADATAHELPER_HST_IMPL_H

#include <condition_variable>
#include <mutex>

#include "avmetadata_collector.h"
#include "av_thumbnail_generator.h"
#include "buffer/avsharedmemorybase.h"
#include "common/status.h"
#include "i_avmetadatahelper_engine.h"
#include "i_avmetadatahelper_service.h"
#include "media_demuxer.h"
#include "nocopyable.h"
#include "interrupt_monitor.h"

namespace OHOS {
namespace Media {
class TimeAndIndexConversion;
class AVMetadataHelperImpl : public IAVMetadataHelperEngine,
                             public std::enable_shared_from_this<AVMetadataHelperImpl>,
                             public NoCopyable {
public:
    AVMetadataHelperImpl(int32_t appUid, int32_t appPid, uint32_t appTokenId, std::string appName);
    ~AVMetadataHelperImpl();

    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    int32_t SetSource(const std::string &uri, int32_t usage) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    int32_t SetAVMetadataCaller(AVMetadataCaller caller) override;
    int32_t SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header) override;
    std::string ResolveMetadata(int32_t key) override;
    std::unordered_map<int32_t, std::string> ResolveMetadata() override;
    std::shared_ptr<Meta> GetAVMetadata() override;
    std::shared_ptr<AVSharedMemory> FetchFrameAtTime(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) override;
    std::shared_ptr<AVBuffer> FetchFrameYuv(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) override;
    std::shared_ptr<AVBuffer> FetchFrameYuvs(
        int64_t timeUs, int32_t option, const OutputConfiguration &param, bool &errCallback) override;
    std::shared_ptr<AVSharedMemory> FetchArtPicture() override;
    int32_t GetTimeByFrameIndex(uint32_t index, uint64_t &time) override;
    int32_t GetFrameIndexByTime(uint64_t time, uint32_t &index) override;
    void SetInterruptState(bool isInterruptNeeded) override;

private:
    std::shared_ptr<OHOS::Media::MediaDemuxer> mediaDemuxer_;
    std::shared_ptr<AVMetaDataCollector> metadataCollector_;
    std::shared_ptr<AVThumbnailGenerator> thumbnailGenerator_;
    std::unordered_map<int32_t, std::string> collectedMeta_;
    std::shared_ptr<AVSharedMemory> collectedArtPicture_;
    std::shared_ptr<AVSharedMemoryBase> fetchedFrameAtTime_;
    std::shared_ptr<OHOS::Media::TimeAndIndexConversion> conversion_ { nullptr };
    std::shared_ptr<InterruptMonitor> interruptMonitor_ {nullptr};
    std::atomic_bool stopProcessing_{ false };
    std::atomic_bool isForFrameConvert_{ false };

    Status SetSourceInternel(const std::string &uri, bool isForFrameConvert);
    Status SetSourceInternel(const std::shared_ptr<IMediaDataSource> &dataSrc);
    Status SetSourceInternel(const std::string &uri, const std::map<std::string, std::string> &header);
    Status SetSourceForFrameConvert(const std::string &uri);
    Status InitMetadataCollector();
    Status InitThumbnailGenerator();
    int32_t GetTimeForFrameConvert(uint32_t index, uint64_t &time);
    int32_t GetIndexForFrameConvert(uint64_t time, uint32_t &index);
    int64_t GetDurationMs();

    void Reset();
    void Destroy();
    std::string groupId_;
    std::atomic<bool> isInterruptNeeded_ = false;
    int32_t appUid_{0};
    int32_t appPid_{0};
    uint32_t appTokenId_{0};
    int64_t succTimeUs_{0};
    std::string appName_;
    AVMetadataCaller metadataCaller_ = AVMetadataCaller::AV_META_DATA_DEFAULT;
};
}  // namespace Media
}  // namespace OHOS
#endif  // AVMETADATAHELPER_HST_IMPL_H