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
#ifndef LPP_VIDEO_DATA_MANAGER_H
#define LPP_VIDEO_DATA_MANAGER_H

#include <gmock/gmock.h>
#include <string>
#include "refbase.h"
#include "pipeline/pipeline.h"
#include "lpp_common.h"
#include "lpp_vdec_adapter.h"
#include "meta/format.h"

namespace OHOS {
namespace Media {
class LppVideoDataManager : public std::enable_shared_from_this<LppVideoDataManager> {
public:
    explicit LppVideoDataManager(const std::string &streamerId, bool isLpp)
    {
        (void)streamerId;
        (void)isLpp;
    }
    ~LppVideoDataManager() {};
    MOCK_METHOD(void, OnDataNeeded, (const int32_t maxBufferSize, const int32_t maxFrameNum));
    MOCK_METHOD(int32_t, ProcessNewData, (sptr<LppDataPacket> framePacket));
    MOCK_METHOD(int32_t, Configure, (const Format &params));
    MOCK_METHOD(int32_t, Prepare, ());
    MOCK_METHOD(int32_t, StartDecode, ());
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Resume, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, SetDecoderInputProducer, (sptr<Media::AVBufferQueueProducer> producer));
    MOCK_METHOD(void, OnBufferAvailable, ());
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver));
};
}
}
#endif