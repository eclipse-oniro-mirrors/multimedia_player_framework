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

#ifndef SEI_PARSER_FILTER_H
#define SEI_PARSER_FILTER_H

#include <atomic>
#include <gmock/gmock.h>
#include "plugin/plugin_info.h"
#include "filter/filter.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_define.h"
#include "sink/media_synchronous_sink.h"
#include "meta/format.h"
#include "sei_parser_helper.h"
#include "media_sync_manager.h"

namespace OHOS {
namespace Media {
namespace Pipeline {
class SeiParserFilter : public Filter, public InterruptListener {
public:
    explicit SeiParserFilter(const std::string &name, FilterType filterType = FilterType::FILTERTYPE_SEI)
        : Filter(name, filterType) {}
    
    ~SeiParserFilter() override = default;

    MOCK_METHOD(void, Init, (const std::shared_ptr<EventReceiver>& receiver,
                            const std::shared_ptr<FilterCallback>& callback), (override));
    MOCK_METHOD(Status, DoInitAfterLink, (), (override));
    MOCK_METHOD(Status, DoPrepare, (), (override));
    MOCK_METHOD(void, OnInterrupted, (bool isInterruptNeeded), (override));
    MOCK_METHOD(Status, DoProcessInputBuffer, (int recvArg, bool dropFrame), (override));

    MOCK_METHOD(sptr<AVBufferQueueProducer>, GetBufferQueueProducer, (), ());
    MOCK_METHOD(sptr<AVBufferQueueConsumer>, GetBufferQueueConsumer, (), ());
    MOCK_METHOD(Status, PrepareState, (), ());
    MOCK_METHOD(Status, ParseSei, (std::shared_ptr<AVBuffer> buffer), ());
    MOCK_METHOD(Status, SetSeiMessageCbStatus, (bool status, const std::vector<int32_t>& payloadTypes), ());
    MOCK_METHOD(void, DrainOutputBuffer, (bool flushed), ());
    MOCK_METHOD(void, SetParseSeiEnabled, (bool needParseSeiInfo), ());
    MOCK_METHOD(void, SetSyncCenter, (std::shared_ptr<IMediaSyncCenter> syncCenter), ());

    MOCK_METHOD(Status, OnLinked, (StreamType inType, const std::shared_ptr<Meta>& meta,
                                  const std::shared_ptr<FilterLinkCallback>& callback), (override));
    MOCK_METHOD(Status, OnUpdated, (StreamType inType, const std::shared_ptr<Meta>& meta,
                                  const std::shared_ptr<FilterLinkCallback>& callback), (override));
    MOCK_METHOD(Status, OnUnLinked, (StreamType inType,
        const std::shared_ptr<FilterLinkCallback>& callback), (override));
    sptr<SeiParserListener> producerListener_ {};
};
}  // namespace Pipeline
}  // namespace Media
}  // namespace OHOS
#endif  // SEI_PARSER_FILTER_H
