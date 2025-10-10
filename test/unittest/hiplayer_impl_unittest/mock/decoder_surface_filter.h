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

#ifndef MEDIA_PIPELINE_VIDEO_SINK_FILTER_H
#define MEDIA_PIPELINE_VIDEO_SINK_FILTER_H

#include <atomic>
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "plugin/plugin_time.h"
#include "avcodec_common.h"
#include "surface/surface.h"
#include "osal/task/condition_variable.h"
#include "osal/task/mutex.h"
#include "osal/task/task.h"
#include "video_sink.h"
#include "sink/media_synchronous_sink.h"
#include "common/status.h"
#include "video_decoder_adapter.h"
#include "meta/meta.h"
#include "meta/format.h"
#include "filter/filter.h"
#include "media_sync_manager.h"
#include "common/media_core.h"
#include "common/seek_callback.h"
#include "drm_i_keysession_service.h"
#include "interrupt_listener.h"
#include "sei_parser_helper.h"
#include "post_processor/base_video_post_processor.h"
#include "post_processor/video_post_processor_factory.h"
#include "common/fdsan_fd.h"

namespace OHOS {
namespace Media {
namespace Pipeline {
class DecoderSurfaceFilter : public Filter, public InterruptListener {
public:
    DecoderSurfaceFilter(const std::string& name, FilterType type)
        : Filter(name, type) {}
    
    ~DecoderSurfaceFilter() override = default;

    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback), (override));
    MOCK_METHOD(Status, Configure, (const std::shared_ptr<Meta>& parameter), ());
    MOCK_METHOD(Status, DoInitAfterLink, (), (override));
    MOCK_METHOD(Status, DoPrepare, (), (override));
    MOCK_METHOD(Status, DoStart, (), (override));
    MOCK_METHOD(Status, DoPause, (), (override));
    MOCK_METHOD(Status, DoFreeze, (), (override));
    MOCK_METHOD(Status, DoUnFreeze, (), (override));
    MOCK_METHOD(Status, DoPauseDragging, (), (override));
    MOCK_METHOD(Status, DoResume, (), (override));
    MOCK_METHOD(Status, DoResumeDragging, (), (override));
    MOCK_METHOD(Status, DoStop, (), (override));
    MOCK_METHOD(Status, DoFlush, (), (override));
    MOCK_METHOD(Status, DoRelease, (), (override));
    MOCK_METHOD(Status, DoPreroll, (), (override));
    MOCK_METHOD(Status, DoWaitPrerollDone, (bool render), (override));
    MOCK_METHOD(Status, DoSetPlayRange, (int64_t start, int64_t end), (override));
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), (override));
    MOCK_METHOD(Status, DoProcessOutputBuffer, (int recvArg,
        bool dropFrame, bool byIdx, uint32_t idx, int64_t renderTime), (override));
    MOCK_METHOD(Status, DoSetPerfRecEnabled, (bool isPerfRecEnabled), (override));
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& parameter), (override));
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& parameter), (override));
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(FilterType, GetFilterType, (), ());

    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), (override));

    MOCK_METHOD(void, OnLinkedResult, (const sptr<AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, DrainOutputBuffer, (uint32_t index, std::shared_ptr<AVBuffer>& outputBuffer), ());
    MOCK_METHOD(void, DecoderDrainOutputBuffer, (uint32_t index, std::shared_ptr<AVBuffer>& outputBuffer), ());
    MOCK_METHOD(Status, SetVideoSurface, (sptr<Surface> videoSurface), ());
    MOCK_METHOD(Status, SetDecryptConfig, (const sptr<DrmStandard::IMediaKeySessionService>& keySessionProxy,
        bool svp), ());
    MOCK_METHOD(void, OnError, (MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode), ());
    MOCK_METHOD(void, PostProcessorOnError, (int32_t errorCode), ());
    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetInputBufferQueue, (), ());
    MOCK_METHOD(void, SetSyncCenter, (std::shared_ptr<MediaSyncManager> syncCenter), ());
    MOCK_METHOD(void, SetSeekTime, (int64_t seekTimeUs, PlayerSeekMode mode), ());
    MOCK_METHOD(void, ResetSeekInfo, (), ());
    MOCK_METHOD(Status, HandleInputBuffer, (), ());
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), ());
    MOCK_METHOD(void, SetCallingInfo, (int32_t appUid, int32_t appPid,
        std::string bundleName, uint64_t instanceId), ());
    MOCK_METHOD(Status, GetLagInfo, (int32_t& lagTimes, int32_t& maxLagDuration, int32_t& avgLagDuration), ());
    MOCK_METHOD(void, SetBitrateStart, (), ());
    MOCK_METHOD(void, OnOutputFormatChanged, (const MediaAVCodec::Format& format), ());
    MOCK_METHOD(Status, StartSeekContinous, (), ());
    MOCK_METHOD(Status, StopSeekContinous, (), ());
    MOCK_METHOD(void, RegisterVideoFrameReadyCallback, (std::shared_ptr<VideoFrameReadyCallback>& callback), ());
    MOCK_METHOD(void, DeregisterVideoFrameReadyCallback, (), ());
    MOCK_METHOD(int32_t, GetDecRateUpperLimit, (), ());
    MOCK_METHOD(bool, GetIsSupportSeekWithoutFlush, (), ());
    MOCK_METHOD(void, ConsumeVideoFrame, (uint32_t index, bool isRender, int64_t renderTimeNs), ());
    MOCK_METHOD(Status, SetSeiMessageCbStatus, (bool status, const std::vector<int32_t>& payloadTypes), ());
    MOCK_METHOD(Status, InitPostProcessor, (), ());
    MOCK_METHOD(void, SetPostProcessorType, (VideoPostProcessorType type), ());
    MOCK_METHOD(Status, SetPostProcessorOn, (bool isSuperResolutionOn), ());
    MOCK_METHOD(Status, SetVideoWindowSize, (int32_t width, int32_t height), ());
    MOCK_METHOD(void, NotifyAudioComplete, (), ());
    MOCK_METHOD(Status, SetSpeed, (float speed), ());
    MOCK_METHOD(Status, SetPostProcessorFd, (int32_t postProcessorFd), ());
    MOCK_METHOD(Status, SetCameraPostprocessing, (bool enable), ());
    MOCK_METHOD(void, NotifyPause, (), ());
    MOCK_METHOD(void, NotifyMemoryExchange, (bool exchangeFlag), ());
    MOCK_METHOD(void, SetBuffering, (bool isBuffering), ());
};
} // namespace Pipeline
} // namespace Media
} // namespace OHOS
#endif // MEDIA_PIPELINE_VIDEO_SINK_FILTER_H
