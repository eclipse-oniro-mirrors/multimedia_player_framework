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

#include "lpp_sync_manager_unit_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

void LppSyncManagerUnitTest::SetUpTestCase(void)
{
}

void LppSyncManagerUnitTest::TearDownTestCase(void)
{
}

void LppSyncManagerUnitTest::SetUp(void)
{
    std::string streamerId = "lppVideo";
    syncManager_ = std::make_shared<LppSyncManager>(streamerId, true);
    mockAdapter_ = std::make_shared<LppSyncManagerAdapter>();
    syncManager_->adapter_ = mockAdapter_;
}

void LppSyncManagerUnitTest::TearDown(void)
{
    syncManager_.reset();
    mockAdapter_.reset();
}

/**
* @tc.name    : Test Init API
* @tc.number  : Init_001
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Init_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Init()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Init();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test GetTimeAnchor API
* @tc.number  : GetTimeAnchor_001
* @tc.desc    : Test GetTimeAnchor interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, GetTimeAnchor_001, TestSize.Level1)
{
    syncManager_->localAnchorPts_ = 1000;
    syncManager_->localAnchorClk_ = 20000;
    int64_t anchorPts;
    int64_t anchorClock;
    int32_t res = syncManager_->GetTimeAnchor(anchorPts, anchorClock);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(anchorPts, 1000);
    EXPECT_EQ(anchorClock, 20000);
}

/**
* @tc.name    : Test GetTimeAnchor API
* @tc.number  : GetTimeAnchor_002
* @tc.desc    : Test GetTimeAnchor interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, GetTimeAnchor_002, TestSize.Level1)
{
    syncManager_->localAnchorPts_ = 1000;
    syncManager_->localAnchorClk_ = 0;
    int64_t anchorPts;
    int64_t anchorClock;
    int32_t res = syncManager_->GetTimeAnchor(anchorPts, anchorClock);
    EXPECT_NE(res, 0);
}

/**
* @tc.name    : Test SetVideoChannelId API
* @tc.number  : SetVideoChannelId_001
* @tc.desc    : Test SetVideoChannelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetVideoChannelId_001, TestSize.Level1)
{
    uint32_t targetChannelId = 0;
    EXPECT_CALL(*mockAdapter_, SetVideoChannelId(_)).WillOnce(
        DoAll(
            Invoke([&targetChannelId](const uint32_t channelId) { targetChannelId = channelId; }),
            Return(MSERR_OK)
        )
    );
    int32_t res = syncManager_->SetVideoChannelId(20);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetChannelId, 20);
}

/**
* @tc.name    : Test SetAudioChannelId API
* @tc.number  : SetAudioChannelId_001
* @tc.desc    : Test SetAudioChannelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetAudioChannelId_001, TestSize.Level1)
{
    uint32_t targetChannelId = 0;
    EXPECT_CALL(*mockAdapter_, SetAudioChannelId(_)).WillOnce(
        DoAll(
            Invoke([&targetChannelId](const uint32_t channelId) { targetChannelId = channelId; }),
            Return(MSERR_OK)
        )
    );
    int32_t res = syncManager_->SetAudioChannelId(25);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetChannelId, 25);
}

/**
* @tc.name    : Test Prepare API
* @tc.number  : Prepare_001
* @tc.desc    : Test Prepare interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Prepare_001, TestSize.Level1)
{
    int32_t res = syncManager_->Prepare();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_001
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, StartRender_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, StartRender()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->StartRender();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test RenderNextFrame API
* @tc.number  : RenderNextFrame_001
* @tc.desc    : Test RenderNextFrame interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, RenderNextFrame_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, RenderNextFrame()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->RenderNextFrame();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_001
* @tc.desc    : Test Pause interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Pause_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Pause()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Pause();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_001
* @tc.desc    : Test Resume interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Resume_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Resume()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Resume();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_001
* @tc.desc    : Test Flush interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Flush_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Flush()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Flush();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Stop API
* @tc.number  : Stop_001
* @tc.desc    : Test Stop interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Stop_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Stop()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Stop();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Reset API
* @tc.number  : Reset_001
* @tc.desc    : Test Reset interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, Reset_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, Reset()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->Reset();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetTargetStartFrame API
* @tc.number  : SetTargetStartFrame_001
* @tc.desc    : Test SetTargetStartFrame interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetTargetStartFrame_001, TestSize.Level1)
{
    uint64_t targetTargetPts = 0;
    uint32_t targetTimeoutMs = 0;
    EXPECT_CALL(*mockAdapter_, SetTargetStartFrame(_, _)).WillOnce(
        DoAll(
            Invoke([&targetTargetPts, &targetTimeoutMs](const uint64_t targetPts, uint32_t timeoutMs) {
                targetTargetPts = targetPts;
                targetTimeoutMs = timeoutMs;
            }),
            Return(MSERR_OK)
        )
    );
    int32_t res = syncManager_->SetTargetStartFrame(1000, 20000);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetTargetPts, 1000);
    EXPECT_EQ(targetTimeoutMs, 20000);
}

/**
* @tc.name    : Test SetPlaybackSpeed API
* @tc.number  : SetPlaybackSpeed_001
* @tc.desc    : Test SetPlaybackSpeed interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetPlaybackSpeed_001, TestSize.Level1)
{
    float targetSpeed = 1.0f;
    EXPECT_CALL(*mockAdapter_, SetPlaybackSpeed(_)).WillOnce(
        DoAll(
            Invoke([&targetSpeed](float speed) { targetSpeed = speed; }),
            Return(MSERR_OK)
        )
    );
    int32_t res = syncManager_->SetPlaybackSpeed(2.0f);
    EXPECT_EQ(res, 0);
    EXPECT_LE(targetSpeed - 2.0f, 0.001f);
    EXPECT_GE(targetSpeed - 2.0f, -0.001f);
}

/**
* @tc.name    : Test SetParameter API
* @tc.number  : SetParameter_001
* @tc.desc    : Test SetParameter interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetParameter_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, SetParameter(_)).WillOnce(Return(MSERR_OK));
    std::map<std::string, std::string> parameters = { {"hello", "world"} };
    int32_t res = syncManager_->SetParameter(parameters);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test GetParameter API
* @tc.number  : GetParameter_001
* @tc.desc    : Test GetParameter interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, GetParameter_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, GetParameter(_)).WillOnce(Return(MSERR_OK));
    std::map<std::string, std::string> parameters = {};
    int32_t res = syncManager_->GetParameter(parameters);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test UpdateTimeAnchor API
* @tc.number  : UpdateTimeAnchor_001
* @tc.desc    : Test UpdateTimeAnchor interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, UpdateTimeAnchor_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, UpdateTimeAnchor(_, _)).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->UpdateTimeAnchor(1000, 20000);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test BindOutputBuffers API
* @tc.number  : BindOutputBuffers_001
* @tc.desc    : Test BindOutputBuffers interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, BindOutputBuffers_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, BindOutputBuffers(_)).WillOnce(Return(MSERR_OK));
    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap = {};
    bufferMap[1] = SurfaceBuffer::Create();
    int32_t res = syncManager_->BindOutputBuffers(bufferMap);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test UnbindOutputBuffers API
* @tc.number  : UnbindOutputBuffers_001
* @tc.desc    : Test UnbindOutputBuffers interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, UnbindOutputBuffers_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, UnbindOutputBuffers()).WillOnce(Return(MSERR_OK));
    int32_t res = syncManager_->UnbindOutputBuffers();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test GetShareBuffer API
* @tc.number  : GetShareBuffer_001
* @tc.desc    : Test GetShareBuffer interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, GetShareBuffer_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, GetShareBuffer(_)).WillOnce(Return(MSERR_OK));
    int32_t fd = 0;
    int32_t res = syncManager_->GetShareBuffer(fd);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetTunnelId API
* @tc.number  : SetTunnelId_001
* @tc.desc    : Test SetTunnelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetTunnelId_001, TestSize.Level1)
{
    EXPECT_CALL(*mockAdapter_, SetTunnelId(_)).WillOnce(Return(MSERR_OK));
    uint64_t tunnelId = 0;
    int32_t res = syncManager_->SetTunnelId(tunnelId);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetEventReceiver API
* @tc.number  : SetEventReceiver_001
* @tc.desc    : Test SetEventReceiver interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerUnitTest, SetEventReceiver_001, TestSize.Level1)
{
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> targetEventReceiver = nullptr;
    EXPECT_CALL(*mockAdapter_, SetEventReceiver(_)).WillOnce(
        Invoke([&targetEventReceiver](std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver) {
            targetEventReceiver = eventReceiver;
        })
    );
    std::shared_ptr<OHOS::Media::Pipeline::EventReceiver> eventReceiver
        = std::make_shared<OHOS::Media::MockEventReceiver>();
    syncManager_->SetEventReceiver(eventReceiver);
    EXPECT_NE(syncManager_->eventReceiver_, nullptr);
    EXPECT_NE(targetEventReceiver, nullptr);
}
}
}
