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

#include <iostream>
#include "lpp_astreamer_impl_unit_test.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void LppAStreamImplrUnitTest::SetUpTestCase(void)
{
}

void LppAStreamImplrUnitTest::TearDownTestCase(void)
{
}

void LppAStreamImplrUnitTest::SetUp(void)
{
    hiLppAudioStreamerImpl_ = std::make_shared<HiLppAudioStreamerImpl>();
}

void LppAStreamImplrUnitTest::TearDown(void)
{
    hiLppAudioStreamerImpl_ = nullptr;
}


/**
* @tc.name    : Test OnEvent API
* @tc.number  : OnEvent_001
* @tc.desc    : Test OnEvent
*/
HWTEST_F(LppAStreamImplrUnitTest, OnEvent_001, TestSize.Level0)
{
    string streamerId = std::string("LppA_");
    hiLppAudioStreamerImpl_->callbackLooper_ = std::make_shared<LppAudioCallbackLooper>(streamerId);
    hiLppAudioStreamerImpl_->syncMgr_ = std::make_shared<ILppSyncManager>();
    EXPECT_CALL(*(hiLppAudioStreamerImpl_->callbackLooper_), OnDataNeeded(_)).Times(1);
    Event event;
    event.type = EventType::EVENT_DATA_NEEDED;
    event.param = 0;
    hiLppAudioStreamerImpl_->OnEvent(event);

    event.type = EventType::EVENT_ANCHOR_UPDATE;
    event.param = std::make_pair<int64_t, int64_t>(0, 0);
    EXPECT_CALL(*(hiLppAudioStreamerImpl_->syncMgr_), UpdateTimeAnchor(_, _))
        .WillOnce(Return(0));
    hiLppAudioStreamerImpl_->OnEvent(event);

    event.type = EventType::EVENT_COMPLETE;
    EXPECT_CALL(*(hiLppAudioStreamerImpl_->callbackLooper_), StopPositionUpdate()).Times(1);
    hiLppAudioStreamerImpl_->OnEvent(event);

    event.type = EventType::EVENT_AUDIO_DEVICE_CHANGE;
    int64_t reason = 0;
    event.param = reason;
    EXPECT_CALL(*(hiLppAudioStreamerImpl_->callbackLooper_), OnDeviceChanged(_)).Times(1);
    hiLppAudioStreamerImpl_->OnEvent(event);

    event.type = EventType::EVENT_AUDIO_INTERRUPT;
    event.param = std::make_pair<int64_t, int64_t>(0, 0);
    EXPECT_CALL(*(hiLppAudioStreamerImpl_->callbackLooper_), OnInterrupted(_, _)).Times(1);
    hiLppAudioStreamerImpl_->OnEvent(event);

    event.type = EventType::EVENT_READY;
    hiLppAudioStreamerImpl_->OnEvent(event);
}

} // namespace Media
} // namespace OHOS