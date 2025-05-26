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

#ifndef HIPLAYER_IMPL_UNITTEST_H
#define HIPLAYER_IMPL_UNITTEST_H

#include "gtest/gtest.h"
#include <gmock/gmock.h>

#ifdef SUPPORT_VIDEO
#undef SUPPORT_VIDEO
#endif
#define SUPPORT_VIDEO
#include "hiplayer_impl.h"
#undef SUPPORT_VIDEO

namespace OHOS {
namespace Media {
class PlayHiplayerImplUnitTest  : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::shared_ptr<HiPlayerImpl> hiplayer_;
};
class MockFilter : public Filter {
public:
    MockFilter():Filter("TestFilter", FilterType::FILTERTYPE_ADEC) {}
    ~MockFilter() = default;

    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback), ());
    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback, const std::shared_ptr<InterruptMonitor>& monitor), ());
    MOCK_METHOD(Status, DoSetPerfRecEnabled, (bool isPerfRecEnabled), ());
    MOCK_METHOD(Status, DoInitAfterLink, (), (override));
    MOCK_METHOD(Status, DoPrepare, (), ());
    MOCK_METHOD(Status, DoStart, (), ());
    MOCK_METHOD(Status, DoPause, (), ());
    MOCK_METHOD(Status, DoPauseDragging, (), ());
    MOCK_METHOD(Status, DoPauseAudioAlign, (), ());
    MOCK_METHOD(Status, DoResume, (), ());
    MOCK_METHOD(Status, DoResumeDragging, (), ());
    MOCK_METHOD(Status, DoResumeAudioAlign, (), ());
    MOCK_METHOD(Status, DoStop, (), ());
    MOCK_METHOD(Status, DoFlush, (), ());
    MOCK_METHOD(Status, DoRelease, (), ());
    MOCK_METHOD(Status, DoPreroll, (), ());
    MOCK_METHOD(Status, DoWaitPrerollDone, (bool render), ());
    MOCK_METHOD(Status, DoSetPlayRange, (int64_t start, int64_t end), ());
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), ());
    MOCK_METHOD(Status, DoProcessOutputBuffer,
        (int recvArg, bool dropFrame, bool byIdx, uint32_t idx, int64_t renderTime), ());
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, OnUnLinked, (StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, ClearAllNextFilters, (), ());
};
class MockDecoderSurfaceFilter : public DecoderSurfaceFilter {
public:
    MockDecoderSurfaceFilter():DecoderSurfaceFilter("testname", FilterType::FILTERTYPE_ADEC) {}
    ~MockDecoderSurfaceFilter() = default;
    MOCK_METHOD(Status, Configure, (const std::shared_ptr<Meta> &parameter), ());
    MOCK_METHOD(Status, DoInitAfterLink, (), ());
    MOCK_METHOD(Status, DoPrepare, (), ());
    MOCK_METHOD(Status, DoStart, (), ());
    MOCK_METHOD(Status, DoPause, (), ());
    MOCK_METHOD(Status, DoPauseDragging, (), ());
    MOCK_METHOD(Status, DoResume, (), ());
    MOCK_METHOD(Status, DoResumeDragging, (), ());
    MOCK_METHOD(Status, DoStop, (), ());
    MOCK_METHOD(Status, DoFlush, (), ());
    MOCK_METHOD(Status, DoRelease, (), ());
    MOCK_METHOD(Status, DoPreroll, (), ());
    MOCK_METHOD(Status, DoWaitPrerollDone, (bool render), ());
    MOCK_METHOD(Status, DoSetPlayRange, (int64_t start, int64_t end), ());
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), ());
    MOCK_METHOD(Status, DoProcessOutputBuffer,
        (int recvArg, bool dropFrame, bool byIdx, uint32_t idx, int64_t renderTime), ());
    MOCK_METHOD(Status, DoSetPerfRecEnabled, (bool isPerfRecEnabled), ());

    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& parameter), ());
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& parameter), ());
    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), ());

    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(void, OnLinkedResult,
        (const sptr<AVBufferQueueProducer> &outputBufferQueue, std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta> &meta), ());

    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(FilterType, GetFilterType, (), ());
    MOCK_METHOD(void, DrainOutputBuffer, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(void, DecoderDrainOutputBuffer, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(Status, SetVideoSurface, (sptr<Surface> videoSurface), ());

    MOCK_METHOD(Status, SetDecryptConfig,
        (const sptr<DrmStandard::IMediaKeySessionService> &keySessionProxy, bool svp), ());

    MOCK_METHOD(void, OnError, (MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode), ());
    MOCK_METHOD(void, PostProcessorOnError, (int32_t errorCode), ());

    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetInputBufferQueue, (), ());
    MOCK_METHOD(void, SetSyncCenter, (std::shared_ptr<MediaSyncManager> syncCenter), ());
    MOCK_METHOD(void, SetSeekTime, (int64_t seekTimeUs), ());
    MOCK_METHOD(void, ResetSeekInfo, (), ());
    MOCK_METHOD(Status, HandleInputBuffer, (), ());
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), ());

    MOCK_METHOD(void, SetCallingInfo,
        (int32_t appUid, int32_t appPid, std::string bundleName, uint64_t instanceId), ());

    MOCK_METHOD(Status, GetLagInfo, (int32_t& lagTimes, int32_t& maxLagDuration, int32_t& avgLagDuration), ());
    MOCK_METHOD(void, SetBitrateStart, (), ());
    MOCK_METHOD(void, OnOutputFormatChanged, (const MediaAVCodec::Format &format), ());
    MOCK_METHOD(Status, StartSeekContinous, (), ());
    MOCK_METHOD(Status, StopSeekContinous, (), ());
    MOCK_METHOD(void, RegisterVideoFrameReadyCallback, (std::shared_ptr<VideoFrameReadyCallback> &callback), ());
    MOCK_METHOD(void, DeregisterVideoFrameReadyCallback, (), ());
    MOCK_METHOD(int32_t, GetDecRateUpperLimit, (), ());
    MOCK_METHOD(bool, GetIsSupportSeekWithoutFlush, (), ());
    MOCK_METHOD(void, ConsumeVideoFrame, (uint32_t index, bool isRender, int64_t renderTimeNs), ());
    MOCK_METHOD(Status, SetSeiMessageCbStatus, (bool status, const std::vector<int32_t> &payloadTypes), ());

    MOCK_METHOD(Status, InitPostProcessor, (), ());
    MOCK_METHOD(void, SetPostProcessorType, (VideoPostProcessorType type), ());
    MOCK_METHOD(Status, SetPostProcessorOn, (bool isSuperResolutionOn), ());
    MOCK_METHOD(Status, SetVideoWindowSize, (int32_t width, int32_t height), ());
    MOCK_METHOD(void, NotifyAudioComplete, (), ());
    MOCK_METHOD(Status, SetSpeed, (float speed), ());

protected:
    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<FilterLinkCallback> &callback), ());
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<FilterLinkCallback> &callback), ());
    MOCK_METHOD(Status, OnUnLinked,
        (StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback), ());

private:
    MOCK_METHOD(void, RenderLoop, (), ());
    MOCK_METHOD(std::string, GetCodecName, (std::string mimeType), ());
    MOCK_METHOD(int64_t, CalculateNextRender, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(void, ParseDecodeRateLimit, (), ());
    MOCK_METHOD(void, RenderNextOutput, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(Status, ReleaseOutputBuffer,
        (int index, bool render, const std::shared_ptr<AVBuffer> &outBuffer, int64_t renderTime), ());
    MOCK_METHOD(void, DoReleaseOutputBuffer, (uint32_t index, bool render, int64_t pts), ());
    MOCK_METHOD(void, DoRenderOutputBufferAtTime, (uint32_t index, int64_t renderTime, int64_t pts), ());
    MOCK_METHOD(bool, AcquireNextRenderBuffer,
        (bool byIdx, uint32_t &index, std::shared_ptr<AVBuffer> &outBuffer, int64_t renderTime), ());
    MOCK_METHOD(bool, DrainSeekContinuous, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(bool, DrainPreroll, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(bool, DrainSeekClosest, (uint32_t index, std::shared_ptr<AVBuffer> &outputBuffer), ());
    MOCK_METHOD(void, HandleFirstOutput, (), ());
    MOCK_METHOD(void, HandleEosOutput, (int index), ());
    MOCK_METHOD(void, ReportEosEvent, (), ());
    MOCK_METHOD(void, RenderAtTimeDfx, (int64_t renderTimeNs, int64_t currentTimeNs, int64_t lastRenderTimeNs), ());
    MOCK_METHOD(int64_t, GetSystimeTimeNs, (), ());
    MOCK_METHOD(bool, IsPostProcessorSupported, (), ());
};
class MockPipeline : public OHOS::Media::Pipeline::Pipeline {
public:
    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback, const std::string& groupId), ());
    MOCK_METHOD(Status, Prepare, (), ());
    MOCK_METHOD(Status, Start, (), ());
    MOCK_METHOD(Status, Pause, (), ());
    MOCK_METHOD(Status, Resume, (), ());
    MOCK_METHOD(Status, Stop, (), ());
    MOCK_METHOD(Status, Flush, (), ());
    MOCK_METHOD(Status, Release, (), ());
    MOCK_METHOD(Status, Preroll, (bool render), ());
    MOCK_METHOD(Status, SetPlayRange, (int64_t start, int64_t end), ());
    MOCK_METHOD(Status, AddHeadFilters, (std::vector<std::shared_ptr<Filter>> filters), ());
    MOCK_METHOD(Status, RemoveHeadFilter, (const std::shared_ptr<Filter>& filter), ());
    MOCK_METHOD(Status, LinkFilters, (const std::shared_ptr<Filter>& preFilter,
        const std::vector<std::shared_ptr<Filter>>& filters, StreamType type, bool needTurbo), ());
    MOCK_METHOD(Status, UpdateFilters, (const std::shared_ptr<Filter>& preFilter,
        const std::vector<std::shared_ptr<Filter>>& filters, StreamType type), ());
    MOCK_METHOD(Status, UnLinkFilters, (const std::shared_ptr<Filter>& preFilter,
        const std::vector<std::shared_ptr<Filter>>& filters, StreamType type), ());
    MOCK_METHOD(void, OnEvent, (const Event& event), ());
    ~MockPipeline()  = default;
};
class MockMediaSource : public Plugins::MediaSource {
public:
    explicit MockMediaSource(std::string uri) : MediaSource(std::move(uri)) {}
    MockMediaSource(std::string uri, std::map<std::string, std::string> header):
        MediaSource(std::move(uri), std::move(header)) {}
    explicit MockMediaSource(std::shared_ptr<IMediaDataSource> dataSrc):
        MediaSource(std::move(dataSrc)) {}
    ~MockMediaSource() = default;
    MOCK_CONST_METHOD0(GetSourceType, SourceType());
    MOCK_CONST_METHOD0(GetSourceUri, const std::string&());
    MOCK_CONST_METHOD0(GetSourceHeader, const std::map<std::string, std::string>&());
    MOCK_CONST_METHOD0(GetMediaStreamList, MediaStreamList());
    MOCK_CONST_METHOD0(GetPlayStrategy, std::shared_ptr<PlayStrategy>());
    MOCK_CONST_METHOD0(GetMimeType, std::string());
    MOCK_CONST_METHOD0(GetAppUid, int32_t());
    MOCK_CONST_METHOD0(GetSourceLoader, std::shared_ptr<IMediaSourceLoader>());
    MOCK_CONST_METHOD0(GetDataSrc, std::shared_ptr<IMediaDataSource>());
    MOCK_METHOD(void, AddMediaStream, (const std::shared_ptr<PlayMediaStream>& playMediaStream));
    MOCK_METHOD(void, SetPlayStrategy, (const std::shared_ptr<PlayStrategy>& playStrategy));
    MOCK_METHOD(void, SetMimeType, (const std::string& mimeType));
    MOCK_METHOD(void, SetAppUid, (int32_t appUid));
    MOCK_METHOD(void, SetSourceLoader, (std::shared_ptr<IMediaSourceLoader> mediaSourceLoader));
};
class MockDemuxerFilter : public DemuxerFilter {
public:
    explicit MockDemuxerFilter(std::string name, FilterType type):DemuxerFilter(name, type){}
    ~MockDemuxerFilter() = default;

    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver> &receiver,
        const std::shared_ptr<FilterCallback> &callback), ());
    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver> &receiver,
        const std::shared_ptr<FilterCallback> &callback, const std::shared_ptr<InterruptMonitor>& monitor), ());
    MOCK_METHOD(Status, DoPrepare, (), ());
    MOCK_METHOD(Status, DoStart, (), ());
    MOCK_METHOD(Status, DoStop, (), ());
    MOCK_METHOD(Status, DoPause, (), ());
    MOCK_METHOD(Status, DoPauseDragging, (), ());
    MOCK_METHOD(Status, DoPauseAudioAlign, (), ());
    MOCK_METHOD(Status, DoResume, (), ());
    MOCK_METHOD(Status, DoResumeDragging, (), ());
    MOCK_METHOD(Status, DoResumeAudioAlign, (), ());
    MOCK_METHOD(Status, DoFlush, (), ());
    MOCK_METHOD(Status, DoPreroll, (), ());
    MOCK_METHOD(Status, DoWaitPrerollDone, (bool render), ());
    MOCK_METHOD(Status, DoSetPerfRecEnabled, (bool isPerfRecEnabled), ());
    MOCK_METHOD(Status, Reset, (), ());
    MOCK_METHOD(Status, PauseForSeek, (), ());
    MOCK_METHOD(Status, ResumeForSeek, (), ());
    MOCK_METHOD(Status, PrepareBeforeStart, (), ());
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta> &parameter), ());
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta> &parameter), ());
    MOCK_METHOD(Status, SetTranscoderMode, (), ());
    MOCK_METHOD(Status, SetDataSource, (const std::shared_ptr<MediaSource> source), ());
    MOCK_METHOD(Status, SetSubtitleSource, (const std::shared_ptr<MediaSource> source), ());
    MOCK_METHOD(void, SetBundleName, (const std::string& bundleName), ());
    MOCK_METHOD(Status, SeekTo, (int64_t seekTime, Plugins::SeekMode mode, int64_t& realSeekTime), ());
    MOCK_METHOD(bool, IsRefParserSupported, (), ());
    MOCK_METHOD(Status, StartReferenceParser, (int64_t startTimeMs, bool isForward), ());
    MOCK_METHOD(Status, GetFrameLayerInfo,
        (std::shared_ptr<AVBuffer> videoSample, FrameLayerInfo &frameLayerInfo), ());
    MOCK_METHOD(Status, GetFrameLayerInfo, (uint32_t frameId, FrameLayerInfo &frameLayerInfo), ());
    MOCK_METHOD(Status, GetGopLayerInfo, (uint32_t gopId, GopLayerInfo &gopLayerInfo), ());
    MOCK_METHOD(Status, GetIFramePos, (std::vector<uint32_t> &IFramePos), ());
    MOCK_METHOD(Status, Dts2FrameId, (int64_t dts, uint32_t &frameId), ());
    MOCK_METHOD(Status, SeekMs2FrameId, (int64_t seekMs, uint32_t &frameId), ());
    MOCK_METHOD(Status, FrameId2SeekMs, (uint32_t frameId, int64_t &seekMs), ());
    MOCK_METHOD(Status, StartTask, (int32_t trackId), ());
    MOCK_METHOD(Status, SelectTrack, (int32_t trackId), ());
    MOCK_METHOD(std::vector<std::shared_ptr<Meta>>, GetStreamMetaInfo, (), (const));
    MOCK_METHOD(std::shared_ptr<Meta>, GetGlobalMetaInfo, (), (const));
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter> &nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, GetBitRates, (std::vector<uint32_t>& bitRates), ());
    MOCK_METHOD(Status, SelectBitRate, (uint32_t bitRate, bool isAutoSelect), ());
    MOCK_METHOD(Status, StopBufferring, (bool flag), ());
    MOCK_METHOD(Status, GetDownloadInfo, (DownloadInfo& downloadInfo), ());
    MOCK_METHOD(Status, GetPlaybackInfo, (PlaybackInfo& playbackInfo), ());
    MOCK_METHOD(FilterType, GetFilterType, (), ());
    MOCK_METHOD(void, OnLinkedResult,
        (const sptr<AVBufferQueueProducer> &outputBufferQueue, std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(Status, PauseTaskByTrackId, (int32_t trackId), ());
    MOCK_METHOD(bool, IsRenderNextVideoFrameSupported, (), ());
    MOCK_METHOD(bool, IsDrmProtected, (), ());
    MOCK_METHOD(void, OnDrmInfoUpdated, ((const std::multimap<std::string, std::vector<uint8_t>>) &drmInfo), ());
    MOCK_METHOD(bool, GetDuration, (int64_t& durationMs), ());
    MOCK_METHOD(Status, OptimizeDecodeSlow, (bool isDecodeOptimizationEnabled), ());
    MOCK_METHOD(Status, SetSpeed, (float speed), ());
    MOCK_METHOD(void, SetDumpFlag, (bool isdump), ());
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), ());
    MOCK_METHOD(void, SetCallerInfo, (uint64_t instanceId, const std::string& appName), ());
    MOCK_METHOD(bool, IsVideoEos, (), ());
    MOCK_METHOD(bool, HasEosTrack, (), ());
    MOCK_METHOD(Status, DisableMediaTrack, (Plugins::MediaType mediaType), ());
    MOCK_METHOD(void, RegisterVideoStreamReadyCallback,
        (const std::shared_ptr<VideoStreamReadyCallback> &callback), ());
    MOCK_METHOD(void, DeregisterVideoStreamReadyCallback, (), ());
    MOCK_METHOD(Status, ResumeDemuxerReadLoop, (), ());
    MOCK_METHOD(Status, PauseDemuxerReadLoop, (), ());
    MOCK_METHOD(void, WaitForBufferingEnd, (), ());
    MOCK_METHOD(int32_t, GetCurrentVideoTrackId, (), ());
    MOCK_METHOD(void, SetSyncCenter, (std::shared_ptr<MediaSyncManager> syncCenter), ());
    MOCK_METHOD(void, SetIsNotPrepareBeforeStart, (bool isNotPrepareBeforeStart), ());
    MOCK_METHOD(void, SetIsEnableReselectVideoTrack, (bool isEnable), ());
    MOCK_METHOD(void, SetApiVersion, (int32_t apiVersion), ());
    MOCK_METHOD(bool, IsLocalFd, (), ());
    MOCK_METHOD(bool, IsFlvLiveStream, (), ());
    MOCK_METHOD(Status, RebootPlugin, (), ());
    MOCK_METHOD(uint64_t, GetCachedDuration, (), ());
    MOCK_METHOD(void, RestartAndClearBuffer, (), ());
    MOCK_METHOD(bool, IsFlvLive, (), ());
    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<FilterLinkCallback> &callback), ());
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta> &meta,
        const std::shared_ptr<FilterLinkCallback> &callback), ());
    MOCK_METHOD(Status, OnUnLinked,
        (StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(bool, FindTrackId, (StreamType outType, int32_t &trackId), ());
    MOCK_METHOD(bool, FindStreamType, (StreamType &streamType, Plugins::MediaType mediaType,
        std::string mime, size_t index, std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(bool, ShouldTrackSkipped, (Plugins::MediaType mediaType, std::string mime, size_t index), ());
    MOCK_METHOD(void, UpdateTrackIdMap, (StreamType streamType, int32_t index), ());
    MOCK_METHOD(Status, FaultDemuxerEventInfoWrite, (StreamType& streamType), ());
    MOCK_METHOD(bool, IsVideoMime, (const std::string& mime), ());
    MOCK_METHOD(bool, IsAudioMime, (const std::string& mime), ());
    MOCK_METHOD(bool, CheckIsBigendian, (std::shared_ptr<Meta> &meta), ());
    MOCK_METHOD(Status, HandleTrackInfos,
        (const std::vector<std::shared_ptr<Meta>> &trackInfos, int32_t &successNodeCount), ());
    MOCK_METHOD(std::string, CollectVideoAndAudioMime, (), ());
};
class MockAudioSinkFilter : public AudioSinkFilter {
public:
    explicit MockAudioSinkFilter(const std::string& name,
        FilterType filterType = FilterType::FILTERTYPE_ASINK):AudioSinkFilter(name, filterType){}
    ~MockAudioSinkFilter() = default;
    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver> &receiver,
        const std::shared_ptr<FilterCallback> &callback), ());
    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver> &receiver,
        const std::shared_ptr<FilterCallback> &callback, const std::shared_ptr<InterruptMonitor> &monitor),
        ());
    MOCK_METHOD(Status, DoInitAfterLink, (), ());
    MOCK_METHOD(Status, DoPrepare, (), ());
    MOCK_METHOD(Status, DoStart, (), ());
    MOCK_METHOD(Status, DoPause, (), ());
    MOCK_METHOD(Status, DoResume, (), ());
    MOCK_METHOD(Status, DoFlush, (), ());
    MOCK_METHOD(Status, DoStop, (), ());
    MOCK_METHOD(Status, DoRelease, (), ());
    MOCK_METHOD(Status, DoSetPlayRange, (int64_t start, int64_t end), ());
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), ());
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, DoSetPerfRecEnabled, (bool isPerfRecEnabled), ());
    MOCK_METHOD(Status, SetVolume, (float volume), ());
    MOCK_METHOD(Status, SetVolumeMode, (int32_t mode), ());
    MOCK_METHOD(void, SetSyncCenter, (std::shared_ptr<MediaSyncManager> syncCenter), ());
    MOCK_METHOD(Status, SetSpeed, (float speed), ());
    MOCK_METHOD(int32_t, SetVolumeWithRamp, (float targetVolume, int32_t duration), ());
    MOCK_METHOD(Status, SetAudioEffectMode, (int32_t effectMode), ());
    MOCK_METHOD(Status, GetAudioEffectMode, (int32_t &effectMode), ());
    MOCK_METHOD(Status, SetIsTransitent, (bool isTransitent), ());
    MOCK_METHOD(Status, ChangeTrack, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(Status, SetMuted, (bool isMuted), ());
    MOCK_METHOD(Status, SetSeekTime, (int64_t seekTime), ());
    MOCK_METHOD(float, GetMaxAmplitude, (), ());
    MOCK_METHOD(int32_t, SetMaxAmplitudeCbStatus, (bool status), ());
    MOCK_METHOD(void, SetIsCancelStart, (bool isCancelStart), ());
    MOCK_METHOD(bool, NeedImmediateRender, (), ());
    MOCK_METHOD(Status, SetIsCalledBySystemApp, (bool isCalledBySystemApp), ());
    MOCK_METHOD(Status, SetLooping, (bool loop), ());
    
    protected:
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, OnUnLinked, (StreamType inType,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
};
class MockAudioDecoderFilter : public AudioDecoderFilter {
public:
    explicit MockAudioDecoderFilter(std::string name, FilterType type):AudioDecoderFilter(name, type){}
    ~MockAudioDecoderFilter() = default;
    MOCK_METHOD(Status, DoPrepare, (), ());
    MOCK_METHOD(Status, DoStart, (), ());
    MOCK_METHOD(Status, DoPause, (), ());
    MOCK_METHOD(Status, DoPauseAudioAlign, (), ());
    MOCK_METHOD(Status, DoResume, (), ());
    MOCK_METHOD(Status, DoResumeAudioAlign, (), ());
    MOCK_METHOD(Status, DoStop, (), ());
    MOCK_METHOD(Status, DoFlush, (), ());
    MOCK_METHOD(Status, DoRelease, (), ());
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& parameter), ());
    MOCK_METHOD(void, SetDumpFlag, (bool isDump), ());
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& parameter), ());
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), ());
    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), ());
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), ());
    MOCK_METHOD(Status, HandleInputBuffer, (bool isTriggeredByOutPort), ());
    MOCK_METHOD(Status, ChangePlugin, (std::shared_ptr<Meta> meta), ());
    MOCK_METHOD(FilterType, GetFilterType, (), ());
    MOCK_METHOD(void, OnLinkedResult,
        (const sptr<AVBufferQueueProducer>& outputBufferQueue, std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(Status, SetDecryptionConfig,
        (const sptr<DrmStandard::IMediaKeySessionService>& keySessionProxy, bool svp), ());
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), ());
    MOCK_METHOD(void, SetCallerInfo, (uint64_t instanceId, const std::string& appName), ());
    MOCK_METHOD(void, OnError, (CodecErrorType errorType, int32_t errorCode), ());
    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, OnUnLinked, (StreamType inType,
        const std::shared_ptr<FilterLinkCallback>& callback), ());
    MOCK_METHOD(Status, SetInputBufferQueueConsumerListener, (), ());
    MOCK_METHOD(Status, SetOutputBufferQueueProducerListener, (), ());
    MOCK_METHOD(void, UpdateTrackInfoSampleFormat, (const std::string& mime, const std::shared_ptr<Meta>& meta), ());
};
} // namespace Media
} // namespace OHOS
#endif // HIPLAYER_IMPL_UNIT_TEST_H
