/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "transcoder_callback_unit_test.h"
#include <utility>
#include "common/log.h"
#include "osal/task/autolock.h"
#include "osal/utils/steady_clock.h"
#include "hitranscoder_callback_looper.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
    constexpr int32_t WHAT_NONE = 0;
    constexpr int32_t WHAT_INFO = 2;
    constexpr int32_t DEFAULT_EVENT = -1;
}
void TranscoderCallbackUnitTest::SetUpTestCase(void) {}

void TranscoderCallbackUnitTest::TearDownTestCase(void) {}

void TranscoderCallbackUnitTest::SetUp(void)
{
    callback_ = std::make_shared<HiTransCoderCallbackLooper>();
    mockTranscoderEngine_ = new MockITransCoderEngine();
    callback_->transCoderEngine_ = mockTranscoderEngine_;
    testObs_ = std::make_shared<MockITransCoderEngineObs>();
    callback_->task_ = std::make_unique<Task>("callbackTestThread");
    callback_->StartWithTransCoderEngineObs(testObs_);
}

void TranscoderCallbackUnitTest::TearDown(void)
{
    if (mockTranscoderEngine_) {
        delete mockTranscoderEngine_;
        mockTranscoderEngine_ = nullptr;
    }
    if (testObs_) {
        testObs_ = nullptr;
    }
    callback_ = nullptr;
}

/**
 * @tc.name: DoReportMediaProgress_01
 * @tc.desc: DoReportMediaProgress_01
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, DoReportMediaProgress_01, TestSize.Level0)
{
    callback_->reportMediaProgress_ = true;
    testObs_ = nullptr;
    callback_->DoReportMediaProgress();
    EXPECT_FALSE(callback_->isDropMediaProgress_);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name: DoReportMediaProgress_02
 * @tc.desc: DoReportMediaProgress_02
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, DoReportMediaProgress_02, TestSize.Level0)
{
    callback_->reportMediaProgress_ = true;
    callback_->isDropMediaProgress_ = true;
    callback_->DoReportMediaProgress();
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name: DoReportCompletedTime_01
 * @tc.desc: DoReportCompletedTime_01
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, DoReportCompletedTime_01, TestSize.Level0)
{
    callback_->DoReportCompletedTime();
    EXPECT_TRUE(testObs_->onInfoFlag);
}

/**
 * @tc.name: Enqueue
 * @tc.desc: Enqueue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, Enqueue, TestSize.Level0)
{
    std::shared_ptr<HiTransCoderCallbackLooper::Event> event =
        std::make_shared<HiTransCoderCallbackLooper::Event>(WHAT_NONE,
        SteadyClock::GetCurrentTimeMs(), Any());
    callback_->Enqueue(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
    callback_->reportMediaProgress_ = false;
}

/**
 * @tc.name: LoopOnce
 * @tc.desc: LoopOnce
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, LoopOnce, TestSize.Level0)
{
    std::shared_ptr<HiTransCoderCallbackLooper::Event> event =
        std::make_shared<HiTransCoderCallbackLooper::Event>(DEFAULT_EVENT,
        SteadyClock::GetCurrentTimeMs(), Any());
    callback_->LoopOnce(event);
    event = std::make_shared<HiTransCoderCallbackLooper::Event>(WHAT_INFO,
        SteadyClock::GetCurrentTimeMs() + 100, Any());
    callback_->LoopOnce(event);
    EXPECT_FALSE(testObs_->onInfoFlag);
}

/**
 * @tc.name: DoReportErrorAndInfo_001
 * @tc.desc: DoReportErrorAndInfo_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TranscoderCallbackUnitTest, DoReportErrorAndInfo_001, TestSize.Level0)
{
    Any error = nullptr;
    callback_->DoReportError(error);
    EXPECT_FALSE(testObs_->onErrorFlag);

    TransCoderOnInfoType infoType = TransCoderOnInfoType::INFO_TYPE_TRANSCODER_COMPLETED;
    int32_t infoCode = 0;
    std::shared_ptr<HiTransCoderCallbackLooper::Event> event = std::make_shared<HiTransCoderCallbackLooper::Event>(
        WHAT_INFO, SteadyClock::GetCurrentTimeMs(), std::make_tuple(infoType, infoCode));
    callback_->DoReportInfo(event->detail);
    EXPECT_TRUE(testObs_->onInfoFlag);
}
} // namespace Media
} // namespace OHOS