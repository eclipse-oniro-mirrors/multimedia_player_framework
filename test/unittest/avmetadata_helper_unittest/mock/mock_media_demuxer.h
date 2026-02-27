/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
#ifndef MOCK_MEDIA_DEMUXER_H
#define MOCK_MEDIA_DEMUXER_H
 
#include "media_demuxer.h"
#include "gmock/gmock.h"
 
namespace OHOS {
namespace Media {
using MediaSource = OHOS::Media::Plugins::MediaSource;
class BaseStreamDemuxer;
class DemuxerPluginManager;
class Source;
 
class AVBufferQueueProducer;

enum class DemuxerCallerType : int32_t;

class MockMediaDemuxer : public MediaDemuxer {
public:
    MockMediaDemuxer() = default;
    ~MockMediaDemuxer() override {};
    MOCK_METHOD(Status, SetDataSource, (const std::shared_ptr<MediaSource> &source), (override));
    MOCK_METHOD(Status, SetSubtitleSource, (const std::shared_ptr<MediaSource> &source), (override));
    MOCK_METHOD(void, SetBundleName, (const std::string& bundleName), (override));
    MOCK_METHOD(Status, SetOutputBufferQueue, (int32_t trackId, const sptr<AVBufferQueueProducer>& producer),
                (override));
 
    MOCK_METHOD(std::shared_ptr<Meta>, GetGlobalMetaInfo, (), (override));
    MOCK_METHOD(std::vector<std::shared_ptr<Meta>>, GetStreamMetaInfo, (), (override));
    MOCK_METHOD(std::shared_ptr<Meta>, GetUserMeta, (), (override));
 
    MOCK_METHOD(Status, SeekTo, (int64_t seekTime, Plugins::SeekMode mode, int64_t& realSeekTime), (override));
    MOCK_METHOD(Status, SeekToKeyFrame, (int64_t seekTime, Plugins::SeekMode mode,
        int64_t& realSeekTime, DemuxerCallerType callerType), (override));
    MOCK_METHOD(Status, Reset, (), (override));
    MOCK_METHOD(Status, Start, (), (override));
    MOCK_METHOD(Status, Stop, (), (override));
    MOCK_METHOD(Status, Pause, (), (override));
    MOCK_METHOD(Status, PauseDragging, (), (override));
    MOCK_METHOD(Status, PauseAudioAlign, (), (override));
    MOCK_METHOD(Status, Resume, (), (override));
    MOCK_METHOD(Status, ResumeDragging, (), (override));
    MOCK_METHOD(Status, ResumeAudioAlign, (), (override));
    MOCK_METHOD(Status, Flush, (), (override));
    MOCK_METHOD(Status, Preroll, (), (override));
    MOCK_METHOD(Status, PausePreroll, (), (override));
 
    MOCK_METHOD(Status, StartTask, (int32_t trackId), (override));
    MOCK_METHOD(Status, SelectTrack, (int32_t trackId), (override));
    MOCK_METHOD(Status, UnselectTrack, (int32_t trackId), (override));
    MOCK_METHOD(Status, ReadSample, (uint32_t trackId, std::shared_ptr<AVBuffer> sample), (override));
    MOCK_METHOD(Status, GetBitRates, (std::vector<uint32_t> &bitRates), (override));
    MOCK_METHOD(Status, SelectBitRate, (uint32_t bitRate), (override));
    MOCK_METHOD(Status, GetMediaKeySystemInfo, ((std::multimap<std::string, std::vector<uint8_t>>) &infos), (override));
    MOCK_METHOD(void, SetDrmCallback, (const std::shared_ptr<OHOS::MediaAVCodec::AVDemuxerCallback> &callback),
                (override));
    MOCK_METHOD(void, OnEvent, (const Plugins::PluginEvent &event), (override));
 
    MOCK_METHOD((std::map<uint32_t, sptr<AVBufferQueueProducer>>), GetBufferQueueProducerMap, (), (override));
    MOCK_METHOD(Status, PauseTaskByTrackId, (int32_t trackId), (override));
    MOCK_METHOD(bool, IsRenderNextVideoFrameSupported, (), (override));
 
    MOCK_METHOD(void, SetEventReceiver, (const std::shared_ptr<Pipeline::EventReceiver> &receiver), (override));
    MOCK_METHOD(bool, GetDuration, (int64_t& durationMs), (override));
    MOCK_METHOD(void, SetPlayerId, (const std::string &playerId), (override));
    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), (override));
    MOCK_METHOD(void, SetDumpInfo, (bool isDump, uint64_t instanceId), (override));
 
    MOCK_METHOD(Status, OptimizeDecodeSlow, (bool isDecodeOptimizationEnabled), (override));
    MOCK_METHOD(Status, SetDecoderFramerateUpperLimit, (int32_t decoderFramerateUpperLimit, uint32_t trackId),
                (override));
    MOCK_METHOD(Status, SetSpeed, (float speed), (override));
    MOCK_METHOD(Status, SetFrameRate, (double frameRate, uint32_t trackId), (override));
 
    MOCK_METHOD(bool, IsLocalDrmInfosExisted, (), (override));
    MOCK_METHOD(void, OnBufferAvailable, (uint32_t trackId), (override));
    MOCK_METHOD(void, SetSelectBitRateFlag, (bool flag, uint32_t desBitRate), (override));
    MOCK_METHOD(bool, CanAutoSelectBitRate, (), (override));
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), (override));
 
    MOCK_METHOD(Status, StartReferenceParser, (int64_t startTimeMs, bool isForward), (override));
    MOCK_METHOD(Status, GetFrameLayerInfo, (std::shared_ptr<AVBuffer> videoSample,
                FrameLayerInfo &frameLayerInfo), (override));
    MOCK_METHOD(Status, GetFrameLayerInfo, (uint32_t frameId, FrameLayerInfo &frameLayerInfo), (override));
    MOCK_METHOD(Status, GetGopLayerInfo, (uint32_t gopId, GopLayerInfo &gopLayerInfo), (override));
    MOCK_METHOD(bool, IsVideoEos, (), (override));
    MOCK_METHOD(bool, HasEosTrack, (), (override));
    MOCK_METHOD(Status, GetIFramePos, (std::vector<uint32_t> &IFramePos), (override));
    MOCK_METHOD(Status, Dts2FrameId, (int64_t dts, uint32_t &frameId, bool offset), (override));
    MOCK_METHOD(void, RegisterVideoStreamReadyCallback,
                (const std::shared_ptr<VideoStreamReadyCallback> &callback), (override));
    MOCK_METHOD(void, DeregisterVideoStreamReadyCallback, (), (override));
 
    MOCK_METHOD(Status, GetIndexByRelativePresentationTimeUs, (const uint32_t trackIndex,
        const uint64_t relativePresentationTimeUs, uint32_t &index), (override));
    MOCK_METHOD(Status, GetRelativePresentationTimeUsByIndex, (const uint32_t trackIndex,
        const uint32_t index, uint64_t &relativePresentationTimeUs), (override));
 
    MOCK_METHOD(Status, ResumeDemuxerReadLoop, (), (override));
    MOCK_METHOD(Status, PauseDemuxerReadLoop, (), (override));
    MOCK_METHOD(void, SetCacheLimit, (uint32_t limitSize), (override));
    MOCK_METHOD(void, WaitForBufferingEnd, (), (override));
    MOCK_METHOD(void, SetEnableOnlineFdCache, (bool isEnableFdCache), (override));
};
} // namespace Media
} // namespace OHOS
#endif // MOCK_MEDIA_DEMUXER_H