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

#ifndef MEDIA_DEMUXER_H
#define MEDIA_DEMUXER_H

#include <atomic>
#include <limits>
#include <string>
#include <shared_mutex>
#include <unordered_set>
 
#include "avcodec_common.h"
#include "buffer/avbuffer.h"
#include "common/media_source.h"
#include "common/seek_callback.h"
#include "demuxer/type_finder.h"
#include "filter/filter.h"
#include "meta/media_types.h"
#include "osal/task/autolock.h"
#include "osal/task/task.h"
#include "plugin/plugin_base.h"
#include "plugin/plugin_info.h"
#include "plugin/plugin_time.h"
#include "plugin/demuxer_plugin.h"

namespace OHOS {
namespace Media {
using MediaSource = OHOS::Media::Plugins::MediaSource;
class BaseStreamDemuxer;
class DemuxerPluginManager;
class Source;

class AVBufferQueueProducer;

class MediaDemuxer {
public:
    virtual ~MediaDemuxer() = default;
    virtual Status SetDataSource(const std::shared_ptr<MediaSource> &source);
    virtual Status SetSubtitleSource(const std::shared_ptr<MediaSource> &source);
    virtual void SetBundleName(const std::string& bundleName);
    virtual Status SetOutputBufferQueue(int32_t trackId, const sptr<AVBufferQueueProducer>& producer);

    virtual std::shared_ptr<Meta> GetGlobalMetaInfo();
    virtual std::vector<std::shared_ptr<Meta>> GetStreamMetaInfo();
    virtual std::shared_ptr<Meta> GetUserMeta();

    virtual Status SeekTo(int64_t seekTime, Plugins::SeekMode mode, int64_t& realSeekTime);
    virtual Status Reset();
    virtual Status Start();
    virtual Status Stop();
    virtual Status Pause();
    virtual Status PauseDragging();
    virtual Status PauseAudioAlign();
    virtual Status Resume();
    virtual Status ResumeDragging();
    virtual Status ResumeAudioAlign();
    virtual Status Flush();
    virtual Status Preroll();
    virtual Status PausePreroll();

    virtual Status StartTask(int32_t trackId);
    virtual Status SelectTrack(int32_t trackId);
    virtual Status UnselectTrack(int32_t trackId);
    virtual Status ReadSample(uint32_t trackId, std::shared_ptr<AVBuffer> sample);
    virtual Status GetBitRates(std::vector<uint32_t> &bitRates);
    virtual Status SelectBitRate(uint32_t bitRate);
    virtual Status GetMediaKeySystemInfo(std::multimap<std::string, std::vector<uint8_t>> &infos);
    virtual void SetDrmCallback(const std::shared_ptr<OHOS::MediaAVCodec::AVDemuxerCallback> &callback);
    virtual void OnEvent(const Plugins::PluginEvent &event);

    virtual std::map<uint32_t, sptr<AVBufferQueueProducer>> GetBufferQueueProducerMap();
    virtual Status PauseTaskByTrackId(int32_t trackId);
    virtual bool IsRenderNextVideoFrameSupported();

    virtual void SetEventReceiver(const std::shared_ptr<Pipeline::EventReceiver> &receiver);
    virtual bool GetDuration(int64_t& durationMs);
    virtual void SetPlayerId(const std::string &playerId);
    virtual void OnInterrupted(bool isInterruptNeeded);
    virtual void SetDumpInfo(bool isDump, uint64_t instanceId);

    virtual Status OptimizeDecodeSlow(bool isDecodeOptimizationEnabled);
    virtual Status SetDecoderFramerateUpperLimit(int32_t decoderFramerateUpperLimit, uint32_t trackId);
    virtual Status SetSpeed(float speed);
    virtual Status SetFrameRate(double frameRate, uint32_t trackId);

    virtual bool IsLocalDrmInfosExisted();
    virtual void OnBufferAvailable(uint32_t trackId);
    virtual void SetSelectBitRateFlag(bool flag, uint32_t desBitRate);
    virtual bool CanAutoSelectBitRate();
    virtual void OnDumpInfo(int32_t fd);

    virtual Status StartReferenceParser(int64_t startTimeMs, bool isForward = true);
    virtual Status GetFrameLayerInfo(std::shared_ptr<AVBuffer> videoSample, FrameLayerInfo &frameLayerInfo);
    virtual Status GetFrameLayerInfo(uint32_t frameId, FrameLayerInfo &frameLayerInfo);
    virtual Status GetGopLayerInfo(uint32_t gopId, GopLayerInfo &gopLayerInfo);
    virtual bool IsVideoEos();
    virtual bool HasEosTrack();
    virtual Status GetIFramePos(std::vector<uint32_t> &IFramePos);
    virtual Status Dts2FrameId(int64_t dts, uint32_t &frameId, bool offset = true);
    virtual void RegisterVideoStreamReadyCallback(const std::shared_ptr<VideoStreamReadyCallback> &callback);
    virtual void DeregisterVideoStreamReadyCallback();

    virtual Status GetIndexByRelativePresentationTimeUs(const uint32_t trackIndex,
        const uint64_t relativePresentationTimeUs, uint32_t &index);
    virtual Status GetRelativePresentationTimeUsByIndex(const uint32_t trackIndex,
        const uint32_t index, uint64_t &relativePresentationTimeUs);

    virtual Status ResumeDemuxerReadLoop();
    virtual Status PauseDemuxerReadLoop();
    virtual void SetCacheLimit(uint32_t limitSize);
    virtual void SetEnableOnlineFdCache(bool isEnableFdCache);
    virtual void WaitForBufferingEnd();
};
} // namespace Media
} // namespace OHOS
#endif // MEDIA_DEMUXER_H