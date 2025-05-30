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

#ifndef AVDEMUXER_IMPL_H
#define AVDEMUXER_IMPL_H

#include <gmock/gmock.h>
#include <memory>
#include "avsource.h"
#include "avdemuxer.h"
#include "nocopyable.h"
#include "media_demuxer.h"

namespace OHOS {
namespace MediaAVCodec {
using namespace Media;
class AVDemuxerImpl : public AVDemuxer, public NoCopyable {
public:
    AVDemuxerImpl() = default;
    ~AVDemuxerImpl() override = default;
    MOCK_METHOD(int32_t, SelectTrackByID, (uint32_t trackIndex), (override));
    MOCK_METHOD(int32_t, UnselectTrackByID, (uint32_t trackIndex), (override));
    MOCK_METHOD(int32_t, ReadSample, (uint32_t trackIndex, std::shared_ptr<AVSharedMemory> sample,
        AVCodecBufferInfo &info, uint32_t &flag), (override));
    MOCK_METHOD(int32_t, ReadSample, (uint32_t trackIndex, std::shared_ptr<AVSharedMemory> sample,
        AVCodecBufferInfo &info, AVCodecBufferFlag &flag), (override));
    MOCK_METHOD(int32_t, ReadSampleBuffer, (uint32_t trackIndex, std::shared_ptr<AVBuffer> sample), (override));
    MOCK_METHOD(int32_t, SeekToTime, (int64_t millisecond, const SeekMode mode), (override));
    MOCK_METHOD(int32_t, SetCallback, (const std::shared_ptr<AVDemuxerCallback> &callback), (override));
    MOCK_METHOD(int32_t, GetMediaKeySystemInfo,
        ((std::multimap<std::string, std::vector<uint8_t>> &)infos), (override));
    MOCK_METHOD(int32_t, Init, (std::shared_ptr<AVSource> source), ());
    MOCK_METHOD(int32_t, StartReferenceParser, (int64_t startTimeMs), (override));
    MOCK_METHOD(int32_t, GetFrameLayerInfo,
        (std::shared_ptr<AVBuffer> videoSample, FrameLayerInfo &frameLayerInfo), (override));
    MOCK_METHOD(int32_t, GetGopLayerInfo,
        (uint32_t gopId, GopLayerInfo &gopLayerInfo), (override));
    MOCK_METHOD(int32_t, GetIndexByRelativePresentationTimeUs,
        (const uint32_t trackIndex, const uint64_t relativePresentationTimeUs, uint32_t &index), (override));
    MOCK_METHOD(int32_t, GetRelativePresentationTimeUsByIndex,
        (const uint32_t trackIndex, const uint32_t index, uint64_t &relativePresentationTimeUs), (override));
    MOCK_METHOD(int32_t, GetCurrentCacheSize,
        (uint32_t trackIndex, uint32_t& size), (override));
private:
    std::shared_ptr<MediaDemuxer> mediaDemuxer_ = nullptr;
    std::string sourceUri_;
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // AVDEMUXER_IMPL_H