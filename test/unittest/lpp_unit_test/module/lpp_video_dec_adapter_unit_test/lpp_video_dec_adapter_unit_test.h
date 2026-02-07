/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LPP_VIDEO_DEC_ADAPTER_UNIT_TEST_H
#define LPP_VIDEO_DEC_ADAPTER_UNIT_TEST_H

#include <gmock/gmock.h>
#include "gtest/gtest.h"
#include "lpp_vdec_adapter.h"
#include "lpp_vdec_adapter.cpp"
#include "lpp_sync_manager.h"
#include "avcodec_common.h"
#include "mock_event_receiver.h"
#include "avbuffer_consumer_mock.h"

namespace OHOS {
namespace Media {
class LppVideoDecAdapterUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
protected:
    std::shared_ptr<LppVideoDecoderAdapter> videoDecAdapter_ {nullptr};
    std::shared_ptr<MediaAVCodec::AVCodecVideoDecoder> videoDecoder_ {nullptr};
    sptr<Media::MockAVBufferQueueConsumer> inputBufferQueueConsumer_;
    std::string streamerId_ = "Lpp_V";
    bool isLpp_ = true;
};
} // namespace Media
} // namespace OHOS
#endif // LPP_VIDEO_DEC_ADAPTER_UNIT_TEST_H
