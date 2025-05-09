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
} // namespace Media
} // namespace OHOS
#endif // HIPLAYER_IMPL_UNIT_TEST_H