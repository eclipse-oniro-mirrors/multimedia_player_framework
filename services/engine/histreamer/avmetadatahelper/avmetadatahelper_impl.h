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

namespace OHOS {
namespace Media {
class AVMetadataHelperImpl : public IAVMetadataHelperEngine,
                             public std::enable_shared_from_this<AVMetadataHelperImpl>,
                             public NoCopyable {
public:
    AVMetadataHelperImpl();
    ~AVMetadataHelperImpl();

    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    int32_t SetSource(const std::string &uri, int32_t usage) override;
    int32_t SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc) override;
    std::string ResolveMetadata(int32_t key) override;
    std::unordered_map<int32_t, std::string> ResolveMetadata() override;
    std::shared_ptr<Meta> GetAVMetadata() override;
    std::shared_ptr<AVSharedMemory> FetchFrameAtTime(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) override;
    std::shared_ptr<AVBuffer> FetchFrameYuv(
        int64_t timeUs, int32_t option, const OutputConfiguration &param) override;
    std::shared_ptr<AVSharedMemory> FetchArtPicture() override;
    int32_t GetTimeByFrameIndex(uint32_t index, int64_t &time) override;
    int32_t GetFrameIndexByTime(int64_t time, uint32_t &index) override;

private:
    std::shared_ptr<OHOS::Media::MediaDemuxer> mediaDemuxer_;
    std::shared_ptr<AVMetaDataCollector> metadataCollector_;
    std::shared_ptr<AVThumbnailGenerator> thumbnailGenerator_;
    std::unordered_map<int32_t, std::string> collectedMeta_;
    std::shared_ptr<AVSharedMemory> collectedArtPicture_;
    std::shared_ptr<AVSharedMemoryBase> fetchedFrameAtTime_;
    std::atomic_bool stopProcessing_{ false };

    Status SetSourceInternel(const std::string &uri);
    Status SetSourceInternel(const std::shared_ptr<IMediaDataSource> &dataSrc);
    Status InitMetadataCollector();
    Status InitThumbnailGenerator();

    void Reset();
    void Destroy();
    std::string groupId_;
};
}  // namespace Media
}  // namespace OHOS
#endif  // AVMETADATAHELPER_HST_IMPL_H