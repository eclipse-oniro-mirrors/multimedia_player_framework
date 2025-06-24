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

#ifndef FILTERS_CODEC_FILTER_H
#define FILTERS_CODEC_FILTER_H

#include <atomic>
#include <cstring>
#include <mutex>
#include "gtest/gtest.h"
#include <gmock/gmock.h>
#include "media_codec/media_codec.h"
#include "filter/filter.h"
#include "plugin/plugin_time.h"
#include "audio_decoder_adapter.h"
#include "avcodec_common.h"
#ifdef SUPPORT_DRM
#include "drm_i_keysession_service.h"
#endif
#include "interrupt_listener.h"

namespace OHOS {
namespace Media {
namespace Pipeline {
using namespace OHOS::Media::Plugins;
class AudioDecoderFilter : public Filter, public InterruptListener {
public:
    AudioDecoderFilter(const std::string& name, FilterType type)
        : Filter(name, type) {}
    
    AudioDecoderFilter(const std::string& name, FilterType type, bool isAsyncMode)
        : Filter(name, type, isAsyncMode) {}
    
    ~AudioDecoderFilter() override = default;

    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback), (override));
    MOCK_METHOD(Status, DoPrepare, (), (override));
    MOCK_METHOD(Status, DoStart, (), (override));
    MOCK_METHOD(Status, DoPause, (), (override));
    MOCK_METHOD(Status, DoFreeze, (), (override));
    MOCK_METHOD(Status, DoUnFreeze, (), (override));
    MOCK_METHOD(Status, DoPauseAudioAlign, (), (override));
    MOCK_METHOD(Status, DoResume, (), (override));
    MOCK_METHOD(Status, DoResumeAudioAlign, (), (override));
    MOCK_METHOD(Status, DoStop, (), (override));
    MOCK_METHOD(Status, DoFlush, (), (override));
    MOCK_METHOD(Status, DoRelease, (), (override));
    MOCK_METHOD(void, SetParameter, (const std::shared_ptr<Meta>& parameter), (override));
    MOCK_METHOD(void, GetParameter, (std::shared_ptr<Meta>& parameter), (override));
    MOCK_METHOD(Status, LinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(Status, UpdateNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(Status, UnLinkNext, (const std::shared_ptr<Filter>& nextFilter, StreamType outType), (override));
    MOCK_METHOD(FilterType, GetFilterType, (), ());

    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), (override));

    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), (override));
    MOCK_METHOD(Status, HandleInputBuffer, (bool isTriggeredByOutPort), ());
    MOCK_METHOD(Status, ChangePlugin, (std::shared_ptr<Meta> meta), ());
    MOCK_METHOD(void, OnLinkedResult, (const sptr<AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUpdatedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(void, OnUnlinkedResult, (std::shared_ptr<Meta>& meta), ());
    MOCK_METHOD(Status, SetDecryptionConfig, (const sptr<DrmStandard::IMediaKeySessionService>& keySessionProxy,
        bool svp), ());
    MOCK_METHOD(void, OnDumpInfo, (int32_t fd), ());
    MOCK_METHOD(void, SetCallerInfo, (uint64_t instanceId, const std::string& appName), ());
    MOCK_METHOD(void, OnError, (CodecErrorType errorType, int32_t errorCode), ());
    MOCK_METHOD(void, OnOutputFormatChanged, (const Format& format), ());

    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), (override));
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback), (override));
    MOCK_METHOD(Status, OnUnLinked, (StreamType inType,
        const std::shared_ptr<FilterLinkCallback>& callback), (override));
    MOCK_METHOD(void, SetDumpFlag, (bool isDump), ());
};

class AudioDecoderCallback : public MediaAVCodec::MediaCodecCallback {
public:
    ~AudioDecoderCallback() override = default;

    MOCK_METHOD(void, OnError, (MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnOutputFormatChanged, (const Format& format), (override));
    MOCK_METHOD(void, OnInputBufferAvailable, (uint32_t index, std::shared_ptr<AVBuffer> buffer), (override));
    MOCK_METHOD(void, OnOutputBufferAvailable, (uint32_t index, std::shared_ptr<AVBuffer> buffer), (override));
};
} // namespace Pipeline
} // namespace MEDIA
} // namespace OHOS
#endif // FILTERS_CODEC_FILTER_H

