/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "lpp_sync_manager_adapter_unit_test.h"
#include "surface_buffer.h"
#include "lpp_sync_manager.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::HDI::LowPowerPlayer::V1_0;

void LppSyncManagerAdapterUnitTest::SetUpTestCase(void)
{
}

void LppSyncManagerAdapterUnitTest::TearDownTestCase(void)
{
}

void LppSyncManagerAdapterUnitTest::SetUp(void)
{
    syncAdapter_ = std::make_shared<LppSyncManagerAdapter>();
    mockSyncAdapter_ = OHOS::sptr<HDI::LowPowerPlayer::V1_0::ILppSyncManagerAdapter>::MakeSptr();
    syncAdapter_->syncMgrAdapter_ = mockSyncAdapter_;
    mockFactory_ = OHOS::sptr<HDI::LowPowerPlayer::V1_0::ILowPowerPlayerFactory>::MakeSptr();
    syncAdapter_->factory_ = mockFactory_;
}

void LppSyncManagerAdapterUnitTest::TearDown(void)
{
    syncAdapter_ = nullptr;
    mockFactory_ = nullptr;
    mockSyncAdapter_ = nullptr;
}

/**
* @tc.name    : Test CreateLppSyncManagerAdapter API
* @tc.number  : CreateLppSyncManagerAdapter_001
* @tc.desc    : Test CreateLppSyncManagerAdapter interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, CreateLppSyncManagerAdapter_001, TestSize.Level0)
{
    std::shared_ptr<LppSyncManagerAdapter> instance = nullptr;
    int32_t res = LowPowerPlayerFactory::CreateLppSyncManagerAdapter(instance);
    EXPECT_EQ(res, 0);
    EXPECT_NE(instance, nullptr);
    res = LowPowerPlayerFactory::DestroyLppSyncManagerAdapter(instance);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetVideoChannelId API
* @tc.number  : SetVideoChannelId_001
* @tc.desc    : Test SetVideoChannelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetVideoChannelId_001, TestSize.Level0)
{
    uint32_t targetChannelId = 0;
    EXPECT_CALL(*mockSyncAdapter_, SetVideoChannelId(_))
        .WillOnce(
            DoAll(
                Invoke([&targetChannelId](uint32_t channelId) { targetChannelId = channelId; }),
                Return(HDF_SUCCESS)
            )
        );
    int32_t res = syncAdapter_->SetVideoChannelId(1);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetChannelId, 1);
}

/**
* @tc.name    : Test SetAudioChannelId API
* @tc.number  : SetAudioChannelId_001
* @tc.desc    : Test SetAudioChannelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetAudioChannelId_001, TestSize.Level0)
{
    uint32_t targetChannelId = 0;
    EXPECT_CALL(*mockSyncAdapter_, SetAudioChannelId(_))
        .WillOnce(
            DoAll(
                Invoke([&targetChannelId](uint32_t channelId) { targetChannelId = channelId; }),
                Return(HDF_SUCCESS)
            )
        );
    int32_t res = syncAdapter_->SetAudioChannelId(1);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetChannelId, 1);
}

/**
* @tc.name    : Test Init API
* @tc.number  : Init_001
* @tc.desc    : Test Init interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Init_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, RegisterCallback(_)).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->Init();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test StartRender API
* @tc.number  : StartRender_001
* @tc.desc    : Test StartRender interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, StartRender_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, StartRender()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->StartRender();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test RenderNextFrame API
* @tc.number  : RenderNextFrame_001
* @tc.desc    : Test RenderNextFrame interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, RenderNextFrame_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, RenderNextFrame()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->RenderNextFrame();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Pause API
* @tc.number  : Pause_001
* @tc.desc    : Test Pause interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Pause_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, Pause()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->Pause();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Resume API
* @tc.number  : Resume_001
* @tc.desc    : Test Resume interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Resume_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, Resume()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->Resume();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Flush API
* @tc.number  : Flush_001
* @tc.desc    : Test Flush interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Flush_001, TestSize.Level0)
{
    int32_t res = syncAdapter_->Flush();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test Reset API
* @tc.number  : Reset_001
* @tc.desc    : Test Reset interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Reset_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, Reset()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->Reset();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test SetPlaybackSpeed API
* @tc.number  : SetPlaybackSpeed_001
* @tc.desc    : Test SetPlaybackSpeed interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetPlaybackSpeed_001, TestSize.Level0)
{
    float targetSpeed = 1.0f;
    EXPECT_CALL(*mockSyncAdapter_, SetPlaybackSpeed(_))
        .WillOnce(
            DoAll(
                Invoke([&targetSpeed](float speed) { targetSpeed = speed; }),
                Return(HDF_SUCCESS)
            )
        );
    int32_t res = syncAdapter_->SetPlaybackSpeed(2.0f);
    EXPECT_EQ(res, 0);
    EXPECT_LE(targetSpeed - 2.0f, 0.001f);
    EXPECT_GE(targetSpeed - 2.0f, -0.001f);
}

/**
* @tc.name    : Test SetTargetStartFrame API
* @tc.number  : SetTargetStartFrame_001
* @tc.desc    : Test SetTargetStartFrame interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetTargetStartFrame_001, TestSize.Level0)
{
    uint64_t tagerFramePts = 0;
    uint32_t targetTimeoutMs = 0;
    EXPECT_CALL(*mockSyncAdapter_, SetTargetStartFrame(_, _)).WillOnce(
        Invoke([&tagerFramePts, &targetTimeoutMs](uint64_t framePts, uint32_t timeoutMs) {
            tagerFramePts = framePts;
            targetTimeoutMs = timeoutMs;
            return HDF_SUCCESS;
        }));
    int32_t res = syncAdapter_->SetTargetStartFrame(2000, 200);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(tagerFramePts, 2000);
    EXPECT_EQ(targetTimeoutMs, 200);
}

/**
* @tc.name    : Test SetParameter API
* @tc.number  : SetParameter_001
* @tc.desc    : Test SetParameter interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetParameter_001, TestSize.Level0)
{
    std::string key = "hello";
    std::string targetVal = "";
    EXPECT_CALL(*mockSyncAdapter_, SetParameter(_)).WillOnce(
        Invoke([&targetVal, &key](const std::map<std::string, std::string> &parameters) {
            if (parameters.find(key) != parameters.end()) {
                targetVal = parameters.find(key)->second;
                return HDF_SUCCESS;
            }
            return HDF_FAILURE;
        }));
    std::map<std::string, std::string> parameters = {{key, "world"}};
    int32_t res = syncAdapter_->SetParameter(parameters);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetVal, "world");
}

/**
* @tc.name    : Test GetParameter API
* @tc.number  : GetParameter_001
* @tc.desc    : Test GetParameter interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, GetParameter_001, TestSize.Level0)
{
    std::string key = "hello";
    std::string targetVal = "";
    EXPECT_CALL(*mockSyncAdapter_, GetParameter(_)).WillOnce(
        Invoke([&key](std::map<std::string, std::string> &parameters) {
            parameters[key] = "world";
            return HDF_SUCCESS;
        }));
    std::map<std::string, std::string> parameters = {};
    int32_t res = syncAdapter_->GetParameter(parameters);
    if (parameters.find(key) != parameters.end()) {
        targetVal = parameters[key];
    }
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetVal, "world");
}

/**
* @tc.name    : Test UpdateTimeAnchor API
* @tc.number  : UpdateTimeAnchor_001
* @tc.desc    : Test UpdateTimeAnchor interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, UpdateTimeAnchor_001, TestSize.Level0)
{
    int64_t targetAnchorPts = 0;
    int64_t targetAnchorClk = 0;
    EXPECT_CALL(*mockSyncAdapter_, UpdateTimeAnchor(_, _)).WillOnce(
        Invoke([&targetAnchorPts, &targetAnchorClk](const int64_t anchorPts, const int64_t anchorClk) {
            targetAnchorPts = anchorPts;
            targetAnchorClk = anchorClk;
            return HDF_SUCCESS;
        }));
    int32_t res = syncAdapter_->UpdateTimeAnchor(2000, 300000);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetAnchorPts, 2000);
    EXPECT_EQ(targetAnchorClk, 300000);
}

/**
* @tc.name    : Test BindOutputBuffers API
* @tc.number  : BindOutputBuffers_001
* @tc.desc    : Test BindOutputBuffers interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, BindOutputBuffers_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, BindOutputBuffers(_)).WillOnce(Return(HDF_SUCCESS));
    std::map<uint32_t, sptr<SurfaceBuffer>> bufferMap = {};
    bufferMap[1] = SurfaceBuffer::Create();
    int32_t res = syncAdapter_->BindOutputBuffers(bufferMap);
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test UnbindOutputBuffers API
* @tc.number  : UnbindOutputBuffers_001
* @tc.desc    : Test UnbindOutputBuffers interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, UnbindOutputBuffers_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, UnbindOutputBuffers()).WillOnce(Return(HDF_SUCCESS));
    int32_t res = syncAdapter_->UnbindOutputBuffers();
    EXPECT_EQ(res, 0);
}

/**
* @tc.name    : Test GetShareBuffer API
* @tc.number  : GetShareBuffer_001
* @tc.desc    : Test GetShareBuffer interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, GetShareBuffer_001, TestSize.Level0)
{
    EXPECT_CALL(*mockSyncAdapter_, GetShareBuffer(_)).WillOnce(
        DoAll(
            Invoke([](int32_t &fd) { fd = 1; }),
            Return(HDF_SUCCESS)
        )
    );
    int32_t fd = 0;
    int32_t res = syncAdapter_->GetShareBuffer(fd);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(fd, 1);
}

/**
* @tc.name    : Test SetTunnelId API
* @tc.number  : SetTunnelId_001
* @tc.desc    : Test SetTunnelId interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, SetTunnelId_001, TestSize.Level0)
{
    uint64_t targetTunnelId = 0;
    EXPECT_CALL(*mockSyncAdapter_, SetTunnelId(_)).WillOnce(
        DoAll(
            Invoke([&targetTunnelId](uint64_t tunnelId) { targetTunnelId = tunnelId; }),
            Return(HDF_SUCCESS)
        )
    );
    int32_t res = syncAdapter_->SetTunnelId(3);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(targetTunnelId, 3);
}

/**
* @tc.name    : Test Callback API
* @tc.number  : Callback_001
* @tc.desc    : Test Callback interface
* @tc.require : issueI5NZAQ
*/
HWTEST_F(LppSyncManagerAdapterUnitTest, Callback_001, TestSize.Level0)
{
    std::shared_ptr<MockEventReceiver> eventReceiver
        = std::make_shared<MockEventReceiver>();
    syncAdapter_->SetEventReceiver(eventReceiver);
    EXPECT_NE(syncAdapter_->eventReceiver_, nullptr);
    int32_t onInfoCnt = 0;
    EXPECT_CALL(*eventReceiver, OnEvent(_)).WillRepeatedly(
        Invoke([&onInfoCnt](const Event& event) { onInfoCnt++; })
    );
    sptr<ILppSyncManagerCallback> callback = nullptr;
    EXPECT_CALL(*mockSyncAdapter_, RegisterCallback(_)).WillOnce(
        DoAll(
            Invoke([&callback](const sptr<ILppSyncManagerCallback>& syncCallback) { callback = syncCallback; }),
            Return(HDF_SUCCESS)
        )
    );
    int32_t res = syncAdapter_->Init();
    EXPECT_EQ(res, 0);
    EXPECT_NE(callback, nullptr);
    EXPECT_EQ(callback->OnError(1, "error"), 0);
    EXPECT_EQ(callback->OnTargetArrived(1, 2), 0);
    EXPECT_EQ(callback->OnRenderStarted(), 0);
    EXPECT_EQ(callback->OnEos(), 0);
    EXPECT_EQ(callback->OnInfo(1, "info"), 0);
    EXPECT_EQ(callback->OnFirstFrameReady(), 0);
    EXPECT_GE(onInfoCnt, 0);
}
} // namespace Media
} // namespace OHOS