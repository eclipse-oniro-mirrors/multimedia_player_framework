/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "dragging_player_agent_unittest.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing;
using namespace testing::ext;

const static int64_t TEST_SEEK_MS = 1000;
const static int32_t TEST_TIMES_ONE = 1;

namespace OHOS {
namespace Media {
void DraggingPlayerAgentUnitTest::SetUpTestCase(void) {}

void DraggingPlayerAgentUnitTest::TearDownTestCase(void) {}

void DraggingPlayerAgentUnitTest::SetUp(void)
{
    mockDraggingPlayer_ = new MockDraggingPlayer();
}

void DraggingPlayerAgentUnitTest::TearDown(void)
{
    if (mockDraggingPlayer_) {
        delete mockDraggingPlayer_;
        mockDraggingPlayer_ = nullptr;
    }
    seekClosestDelegator_ = nullptr;
    seekContinuousDelegator_ = nullptr;
}

/**
 * @tc.name  : Test Create
 * @tc.number: Create_001
 * @tc.desc  : Test SeekContinuousDelegator delegator->Init() != Status::OK
 *             Test SeekContinuousDelegator DraggingPlayerAgent::createFunc_ = nullptr
 */
HWTEST_F(DraggingPlayerAgentUnitTest, Create_001, TestSize.Level1)
{
    seekContinuousDelegator_ = SeekContinuousDelegator::Create(nullptr, nullptr, nullptr, "");
    EXPECT_EQ(seekContinuousDelegator_, nullptr);

    seekContinuousDelegator_ = std::make_shared<SeekContinuousDelegator>(nullptr, nullptr, nullptr, "");
    EXPECT_EQ(seekContinuousDelegator_->draggingPlayer_, nullptr);
}

/**
 * @tc.name  : Test Create
 * @tc.number: Create_002
 * @tc.desc  : Test SeekClosestDelegator delegator->Init() == Status::OK
 */
HWTEST_F(DraggingPlayerAgentUnitTest, Create_002, TestSize.Level1)
{
    seekClosestDelegator_ = SeekClosestDelegator::Create(nullptr, nullptr, nullptr, "");
    EXPECT_TRUE(seekClosestDelegator_);
}

/**
 * @tc.name  : Test Release
 * @tc.number: Release_001
 * @tc.desc  : Test SeekContinuousDelegator monitorTask_ == nullptr
 *             Test SeekContinuousDelegator draggingPlayer_ == nullptr
 *             Test SeekContinuousDelegator demuxer_ == nullptr
 *             Test SeekContinuousDelegator decoder_ == nullptr
 *             Test ~SeekContinuousDelegator isReleased_ == false
 *             Test ~SeekContinuousDelegator draggingPlayer_ == nullptr
 */
HWTEST_F(DraggingPlayerAgentUnitTest, Release_001, TestSize.Level1)
{
    seekContinuousDelegator_ = std::make_shared<SeekContinuousDelegator>(nullptr, nullptr, nullptr, "");
    seekContinuousDelegator_->Release();
    EXPECT_TRUE(seekContinuousDelegator_->isReleased_);

    seekContinuousDelegator_->isReleased_ = false;
    seekContinuousDelegator_->draggingPlayer_ = nullptr;
}

/**
 * @tc.name  : Test Release
 * @tc.number: Release_002
 * @tc.desc  : Test SeekClosestDelegator seekTask_ == nullptr
 *             Test ~SeekClosestDelegator isReleased_ == false
 *             Test ~DraggingPlayerAgent isReleased_ == true
 *             Test ~DraggingPlayerAgent delegator_ == nullptr
 */
HWTEST_F(DraggingPlayerAgentUnitTest, Release_002, TestSize.Level1)
{
    seekClosestDelegator_ = std::make_shared<SeekClosestDelegator>(nullptr, nullptr, nullptr, "");
    seekClosestDelegator_->Release();
    EXPECT_TRUE(seekClosestDelegator_->isReleased_);

    seekClosestDelegator_->isReleased_ = false;

    auto draggingPlayerAgent = std::make_shared<DraggingPlayerAgent>();
    draggingPlayerAgent->isReleased_ = true;
    draggingPlayerAgent->delegator_ = nullptr;
}

/**
 * @tc.name  : Test UpdateSeekPos
 * @tc.number: UpdateSeekPos_001
 * @tc.desc  : Test SeekContinuousDelegator monitorTask_ == nullptr
 */
HWTEST_F(DraggingPlayerAgentUnitTest, UpdateSeekPos_001, TestSize.Level1)
{
    seekContinuousDelegator_ = std::make_shared<SeekContinuousDelegator>(nullptr, nullptr, nullptr, "");
    seekContinuousDelegator_->draggingPlayer_ = mockDraggingPlayer_;
    EXPECT_CALL(*mockDraggingPlayer_, UpdateSeekPos(_)).Times(TEST_TIMES_ONE);
    seekContinuousDelegator_->UpdateSeekPos(TEST_SEEK_MS);
    EXPECT_TRUE(!seekContinuousDelegator_->monitorTask_);
    seekContinuousDelegator_->draggingPlayer_ = nullptr;
}
}  // namespace Media
}  // namespace OHOS