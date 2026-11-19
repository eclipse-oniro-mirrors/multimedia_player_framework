/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "player_service_stub_test.h"
#include "media_errors.h"
#include "media_parcel.h"
#include "message_parcel.h"
#include "message_option.h"
#include <fcntl.h>
#include <unistd.h>
#include <vector>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
constexpr int32_t TEST_FD_OFFSET = 0;
constexpr int64_t TEST_FD_SIZE = 1024;
constexpr int32_t TEST_CURRENT_TIME = 5000;
constexpr int32_t TEST_DURATION = 120000;
constexpr int32_t TEST_VIDEO_WIDTH = 1920;
constexpr int32_t TEST_VIDEO_HEIGHT = 1080;
constexpr int32_t TEST_TRACK_INDEX = 1;
constexpr int64_t TEST_SEEK_TIME = 1000;

sptr<PlayerServiceStub> CreateStub(const std::shared_ptr<NiceMock<MockIPlayerService>> &mockService)
{
    sptr<PlayerServiceStub> stub = new (std::nothrow) PlayerServiceStub();
    if (stub == nullptr) {
        return nullptr;
    }
    stub->playerServer_ = mockService;
    stub->SetPlayerFuncs();
    return stub;
}

void PrepareParcel(MessageParcel &data)
{
    (void)data.WriteInterfaceToken(PlayerServiceStub::GetDescriptor());
}
} // namespace

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备url源消息
测试步骤: 通过OnRemoteRequest下发SET_SOURCE消息
预期结果: Stub解析url并调度playerServer_->SetSource，reply返回MSERR_OK
*/
/**
 * @tc.name: SetSource_Url_001
 * @tc.number: PlayerServiceStub_001
 * @tc.desc: OnRemoteRequest SET_SOURCE dispatches url to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSource_Url_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备url源消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("http://example.com/test.mp4");
    EXPECT_CALL(*mockService, SetSource(std::string("http://example.com/test.mp4"))).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带player server返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备fd源消息
测试步骤: 通过OnRemoteRequest下发SET_FD_SOURCE消息
预期结果: Stub解析fd/offset/size并调度playerServer_->SetSource，reply返回MSERR_OK
*/
/**
 * @tc.name: SetSource_Fd_001
 * @tc.number: PlayerServiceStub_002
 * @tc.desc: OnRemoteRequest SET_FD_SOURCE parses fd and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSource_Fd_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备fd源消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(TEST_FD_OFFSET);
    (void)data.WriteInt64(TEST_FD_SIZE);
    int32_t capturedFd = -1;
    EXPECT_CALL(*mockService, SetSource(_, static_cast<int64_t>(TEST_FD_OFFSET), TEST_FD_SIZE))
        .WillOnce(DoAll(SaveArg<0>(&capturedFd), Return(0)));

    // When: 通过IPC消息调度fd源
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_FD_SOURCE, data, reply, option);

    // Then: 调度成功、fd被解析且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_GE(capturedFd, 0);
    close(fd);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发PLAY消息
预期结果: Stub调度playerServer_->Play，reply返回MSERR_OK
*/
/**
 * @tc.name: Play_001
 * @tc.number: PlayerServiceStub_003
 * @tc.desc: OnRemoteRequest PLAY dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Play_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Play()).WillOnce(Return(0));

    // When: 通过IPC消息调度Play
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发PREPARE消息
预期结果: Stub调度playerServer_->Prepare，reply返回MSERR_OK
*/
/**
 * @tc.name: Prepare_001
 * @tc.number: PlayerServiceStub_004
 * @tc.desc: OnRemoteRequest PREPARE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Prepare_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Prepare()).WillOnce(Return(0));

    // When: 通过IPC消息调度Prepare
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PREPARE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发PREPAREASYNC消息
预期结果: Stub调度playerServer_->PrepareAsync，reply返回MSERR_OK
*/
/**
 * @tc.name: PrepareAsync_001
 * @tc.number: PlayerServiceStub_005
 * @tc.desc: OnRemoteRequest PREPAREASYNC dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, PrepareAsync_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, PrepareAsync()).WillOnce(Return(0));

    // When: 通过IPC消息调度PrepareAsync
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PREPAREASYNC, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发PAUSE消息
预期结果: Stub调度playerServer_->Pause，reply返回MSERR_OK
*/
/**
 * @tc.name: Pause_001
 * @tc.number: PlayerServiceStub_006
 * @tc.desc: OnRemoteRequest PAUSE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Pause_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Pause()).WillOnce(Return(0));

    // When: 通过IPC消息调度Pause
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PAUSE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发STOP消息
预期结果: Stub调度playerServer_->Stop，reply返回MSERR_OK
*/
/**
 * @tc.name: Stop_001
 * @tc.number: PlayerServiceStub_007
 * @tc.desc: OnRemoteRequest STOP dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Stop_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Stop()).WillOnce(Return(0));

    // When: 通过IPC消息调度Stop
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::STOP, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发RESET消息
预期结果: Stub调度playerServer_->Reset，reply返回MSERR_OK
*/
/**
 * @tc.name: Reset_001
 * @tc.number: PlayerServiceStub_008
 * @tc.desc: OnRemoteRequest RESET dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Reset_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Reset()).WillOnce(Return(0));

    // When: 通过IPC消息调度Reset
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::RESET, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发RELEASE消息
预期结果: Stub调度playerServer_->Release，reply返回MSERR_OK
*/
/**
 * @tc.name: Release_001
 * @tc.number: PlayerServiceStub_009
 * @tc.desc: OnRemoteRequest RELEASE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Release_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Release()).WillRepeatedly(Return(0));

    // When: 通过IPC消息调度Release
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::RELEASE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备音量消息
测试步骤: 通过OnRemoteRequest下发SET_VOLUME消息
预期结果: Stub解析左右声道音量并调度playerServer_->SetVolume，reply返回MSERR_OK
*/
/**
 * @tc.name: SetVolume_001
 * @tc.number: PlayerServiceStub_010
 * @tc.desc: OnRemoteRequest SET_VOLUME parses volumes and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVolume_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备音量消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFloat(0.5f);
    (void)data.WriteFloat(0.5f);
    EXPECT_CALL(*mockService, SetVolume(0.5f, 0.5f)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetVolume
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VOLUME, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备Seek消息
测试步骤: 通过OnRemoteRequest下发SEEK消息
预期结果: Stub解析时间与模式并调度playerServer_->Seek，reply返回MSERR_OK
*/
/**
 * @tc.name: Seek_001
 * @tc.number: PlayerServiceStub_011
 * @tc.desc: OnRemoteRequest SEEK parses time and mode and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Seek_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备Seek消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(TEST_SEEK_TIME);
    (void)data.WriteInt32(static_cast<int32_t>(PlayerSeekMode::SEEK_PREVIOUS_SYNC));
    EXPECT_CALL(*mockService, Seek(TEST_SEEK_TIME, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(0));

    // When: 通过IPC消息调度Seek
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SEEK, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备循环消息
测试步骤: 通过OnRemoteRequest下发SET_LOOPING消息
预期结果: Stub解析loop并调度playerServer_->SetLooping，reply返回MSERR_OK
*/
/**
 * @tc.name: SetLooping_001
 * @tc.number: PlayerServiceStub_012
 * @tc.desc: OnRemoteRequest SET_LOOPING parses loop and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetLooping_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备循环消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetLooping(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetLooping
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_LOOPING, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回播放中
测试步骤: 通过OnRemoteRequest下发IS_PLAYING消息
预期结果: Stub调度playerServer_->IsPlaying并写入reply
*/
/**
 * @tc.name: IsPlaying_001
 * @tc.number: PlayerServiceStub_013
 * @tc.desc: OnRemoteRequest IS_PLAYING writes player server result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, IsPlaying_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回播放中
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, IsPlaying()).WillOnce(Return(true));

    // When: 通过IPC消息查询播放状态
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::IS_PLAYING, data, reply, option);

    // Then: 调度成功且reply携带true
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回循环中
测试步骤: 通过OnRemoteRequest下发IS_LOOPING消息
预期结果: Stub调度playerServer_->IsLooping并写入reply
*/
/**
 * @tc.name: IsLooping_001
 * @tc.number: PlayerServiceStub_014
 * @tc.desc: OnRemoteRequest IS_LOOPING writes player server result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, IsLooping_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回循环中
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, IsLooping()).WillOnce(Return(true));

    // When: 通过IPC消息查询循环状态
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::IS_LOOPING, data, reply, option);

    // Then: 调度成功且reply携带true
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回当前时间
测试步骤: 通过OnRemoteRequest下发GET_CURRENT_TIME消息
预期结果: Stub调度playerServer_->GetCurrentTime并把时间与返回码写入reply
*/
/**
 * @tc.name: GetCurrentTime_001
 * @tc.number: PlayerServiceStub_015
 * @tc.desc: OnRemoteRequest GET_CURRENT_TIME writes time and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetCurrentTime_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回当前时间
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetCurrentTime(_))
        .WillOnce(DoAll(SetArgReferee<0>(TEST_CURRENT_TIME), Return(0)));

    // When: 通过IPC消息查询当前时间
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_CURRENT_TIME, data, reply, option);

    // Then: 调度成功且reply携带时间与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), TEST_CURRENT_TIME);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回时长
测试步骤: 通过OnRemoteRequest下发GET_DURATION消息
预期结果: Stub调度playerServer_->GetDuration并把时长与返回码写入reply
*/
/**
 * @tc.name: GetDuration_001
 * @tc.number: PlayerServiceStub_016
 * @tc.desc: OnRemoteRequest GET_DURATION writes duration and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetDuration_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回时长
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetDuration(_))
        .WillOnce(DoAll(SetArgReferee<0>(TEST_DURATION), Return(0)));

    // When: 通过IPC消息查询时长
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_DURATION, data, reply, option);

    // Then: 调度成功且reply携带时长与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), TEST_DURATION);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回视频宽度
测试步骤: 通过OnRemoteRequest下发GET_VIDEO_WIDTH消息
预期结果: Stub调度playerServer_->GetVideoWidth并写入reply
*/
/**
 * @tc.name: GetVideoWidth_001
 * @tc.number: PlayerServiceStub_017
 * @tc.desc: OnRemoteRequest GET_VIDEO_WIDTH writes width to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetVideoWidth_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回视频宽度
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetVideoWidth()).WillOnce(Return(TEST_VIDEO_WIDTH));

    // When: 通过IPC消息查询视频宽度
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_VIDEO_WIDTH, data, reply, option);

    // Then: 调度成功且reply携带宽度
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), TEST_VIDEO_WIDTH);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回视频高度
测试步骤: 通过OnRemoteRequest下发GET_VIDEO_HEIGHT消息
预期结果: Stub调度playerServer_->GetVideoHeight并写入reply
*/
/**
 * @tc.name: GetVideoHeight_001
 * @tc.number: PlayerServiceStub_018
 * @tc.desc: OnRemoteRequest GET_VIDEO_HEIGHT writes height to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetVideoHeight_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回视频高度
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetVideoHeight()).WillOnce(Return(TEST_VIDEO_HEIGHT));

    // When: 通过IPC消息查询视频高度
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_VIDEO_HEIGHT, data, reply, option);

    // Then: 调度成功且reply携带高度
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), TEST_VIDEO_HEIGHT);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备选轨消息
测试步骤: 通过OnRemoteRequest下发SELECT_TRACK消息
预期结果: Stub解析index与mode并调度playerServer_->SelectTrack，reply返回MSERR_OK
*/
/**
 * @tc.name: SelectTrack_001
 * @tc.number: PlayerServiceStub_019
 * @tc.desc: OnRemoteRequest SELECT_TRACK parses args and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SelectTrack_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备选轨消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(TEST_TRACK_INDEX);
    (void)data.WriteInt32(static_cast<int32_t>(PlayerSwitchMode::SWITCH_SMOOTH));
    EXPECT_CALL(*mockService, SelectTrack(TEST_TRACK_INDEX, PlayerSwitchMode::SWITCH_SMOOTH)).WillOnce(Return(0));

    // When: 通过IPC消息调度SelectTrack
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SELECT_TRACK, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备取消选轨消息
测试步骤: 通过OnRemoteRequest下发DESELECT_TRACK消息
预期结果: Stub解析index并调度playerServer_->DeselectTrack，reply返回MSERR_OK
*/
/**
 * @tc.name: DeselectTrack_001
 * @tc.number: PlayerServiceStub_020
 * @tc.desc: OnRemoteRequest DESELECT_TRACK parses index and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, DeselectTrack_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备取消选轨消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(TEST_TRACK_INDEX);
    EXPECT_CALL(*mockService, DeselectTrack(TEST_TRACK_INDEX)).WillOnce(Return(0));

    // When: 通过IPC消息调度DeselectTrack
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::DESELECT_TRACK, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备倍速消息
测试步骤: 通过OnRemoteRequest下发SET_PLAYERBACK_SPEED消息
预期结果: Stub解析倍速模式并调度playerServer_->SetPlaybackSpeed，reply返回MSERR_OK
*/
/**
 * @tc.name: SetPlaybackSpeed_001
 * @tc.number: PlayerServiceStub_021
 * @tc.desc: OnRemoteRequest SET_PLAYERBACK_SPEED parses mode and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlaybackSpeed_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备倍速消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_2_00_X));
    EXPECT_CALL(*mockService, SetPlaybackSpeed(PlaybackRateMode::SPEED_FORWARD_2_00_X)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlaybackSpeed
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAYERBACK_SPEED, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回倍速模式
测试步骤: 通过OnRemoteRequest下发GET_PLAYERBACK_SPEED消息
预期结果: Stub调度playerServer_->GetPlaybackSpeed并把模式与返回码写入reply
*/
/**
 * @tc.name: GetPlaybackSpeed_001
 * @tc.number: PlayerServiceStub_022
 * @tc.desc: OnRemoteRequest GET_PLAYERBACK_SPEED writes mode and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetPlaybackSpeed_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回倍速模式
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetPlaybackSpeed(_))
        .WillOnce(DoAll(SetArgReferee<0>(PlaybackRateMode::SPEED_FORWARD_2_00_X), Return(0)));

    // When: 通过IPC消息查询倍速模式
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_PLAYERBACK_SPEED, data, reply, option);

    // Then: 调度成功且reply携带模式与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), static_cast<int32_t>(PlaybackRateMode::SPEED_FORWARD_2_00_X));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，写入错误接口令牌
测试步骤: 通过OnRemoteRequest下发PLAY消息
预期结果: 接口令牌校验失败，返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: OnRemoteRequest_InvalidDescriptor_001
 * @tc.number: PlayerServiceStub_023
 * @tc.desc: OnRemoteRequest invalid interface descriptor returns MSERR_INVALID_OPERATION test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_InvalidDescriptor_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，写入错误接口令牌
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    (void)data.WriteInterfaceToken(std::u16string(u"Wrong.Descriptor"));

    // When: 通过IPC消息下发请求
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 令牌校验失败
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回错误码
测试步骤: 通过OnRemoteRequest下发PLAY消息
预期结果: Stub调度成功，reply透传playerServer_的错误码
*/
/**
 * @tc.name: OnRemoteRequest_ErrorPassthrough_001
 * @tc.number: PlayerServiceStub_024
 * @tc.desc: OnRemoteRequest passes player server error code to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_ErrorPassthrough_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回错误码
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Play()).WillOnce(Return(MSERR_INVALID_OPERATION));

    // When: 通过IPC消息调度Play
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 调度成功且错误码透传到reply
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，设置冻结态
测试步骤: 通过OnRemoteRequest下发PLAY消息
预期结果: Stub自动解冻并复位isFrozen_，随后调度Play
*/
/**
 * @tc.name: OnRemoteRequest_FrozenAutoUnfreeze_001
 * @tc.number: PlayerServiceStub_025
 * @tc.desc: OnRemoteRequest auto unfreezes frozen stub before dispatch test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_FrozenAutoUnfreeze_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，设置冻结态
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->isFrozen_ = true;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, UnFreeze()).WillOnce(Return(0));
    EXPECT_CALL(*mockService, Play()).WillOnce(Return(0));

    // When: 通过IPC消息调度Play
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 自动解冻成功且冻结态复位
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_FALSE(stub->isFrozen_);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备生产者消息
测试步骤: 通过OnRemoteRequest下发SET_PLAYER_PRODUCER消息
预期结果: Stub解析producer并调度playerServer_->SetPlayerProducer
*/
/**
 * @tc.name: SetPlayerProducer_001
 * @tc.number: PlayerServiceStub_026
 * @tc.desc: OnRemoteRequest SET_PLAYER_PRODUCER dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlayerProducer_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备生产者消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(static_cast<int32_t>(PlayerProducer::NAPI));
    EXPECT_CALL(*mockService, SetPlayerProducer(PlayerProducer::NAPI)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlayerProducer
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAYER_PRODUCER, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备字幕源url
测试步骤: 通过OnRemoteRequest下发ADD_SUB_SOURCE消息
预期结果: Stub解析url并调度playerServer_->AddSubSource
*/
/**
 * @tc.name: AddSubSource_001
 * @tc.number: PlayerServiceStub_027
 * @tc.desc: OnRemoteRequest ADD_SUB_SOURCE dispatches subtitle url to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备字幕源url
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("http://example.com/sub.srt");
    EXPECT_CALL(*mockService, AddSubSource(std::string("http://example.com/sub.srt"))).WillOnce(Return(0));

    // When: 通过IPC消息调度AddSubSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备字幕fd源
测试步骤: 通过OnRemoteRequest下发ADD_SUB_FD_SOURCE消息
预期结果: Stub解析fd/offset/size并调度playerServer_->AddSubSource
*/
/**
 * @tc.name: AddSubFdSource_001
 * @tc.number: PlayerServiceStub_028
 * @tc.desc: OnRemoteRequest ADD_SUB_FD_SOURCE parses fd and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubFdSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备字幕fd源
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(TEST_FD_OFFSET);
    (void)data.WriteInt64(TEST_FD_SIZE);
    EXPECT_CALL(*mockService, AddSubSource(_, static_cast<int64_t>(TEST_FD_OFFSET), TEST_FD_SIZE))
        .WillOnce(Return(0));

    // When: 通过IPC消息调度AddSubSource(fd)
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_FD_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    close(fd);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备首帧显示消息
测试步骤: 通过OnRemoteRequest下发SET_RENDER_FIRST_FRAME消息
预期结果: Stub解析display并调度playerServer_->SetRenderFirstFrame
*/
/**
 * @tc.name: SetRenderFirstFrame_001
 * @tc.number: PlayerServiceStub_029
 * @tc.desc: OnRemoteRequest SET_RENDER_FIRST_FRAME dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetRenderFirstFrame_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备首帧显示消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetRenderFirstFrame(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetRenderFirstFrame
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_RENDER_FIRST_FRAME, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备播放区间消息
测试步骤: 通过OnRemoteRequest下发SET_PLAY_RANGE消息
预期结果: Stub解析start/end并调度playerServer_->SetPlayRange
*/
/**
 * @tc.name: SetPlayRange_001
 * @tc.number: PlayerServiceStub_030
 * @tc.desc: OnRemoteRequest SET_PLAY_RANGE parses range and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlayRange_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备播放区间消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(100);
    (void)data.WriteInt64(200);
    EXPECT_CALL(*mockService, SetPlayRange(100, 200)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlayRange
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAY_RANGE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备带模式播放区间消息
测试步骤: 通过OnRemoteRequest下发SET_PLAY_RANGE_WITH_MODE消息
预期结果: Stub解析start/end/mode并调度playerServer_->SetPlayRangeWithMode
*/
/**
 * @tc.name: SetPlayRangeWithMode_001
 * @tc.number: PlayerServiceStub_031
 * @tc.desc: OnRemoteRequest SET_PLAY_RANGE_WITH_MODE parses args and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlayRangeWithMode_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备带模式播放区间消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(100);
    (void)data.WriteInt64(200);
    (void)data.WriteInt32(static_cast<int32_t>(PlayerSeekMode::SEEK_PREVIOUS_SYNC));
    EXPECT_CALL(*mockService, SetPlayRangeWithMode(100, 200, PlayerSeekMode::SEEK_PREVIOUS_SYNC))
        .WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlayRangeWithMode
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAY_RANGE_WITH_MODE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备音量模式消息
测试步骤: 通过OnRemoteRequest下发SET_VOLUME_MODE消息
预期结果: Stub解析mode并调度playerServer_->SetVolumeMode
*/
/**
 * @tc.name: SetVolumeMode_001
 * @tc.number: PlayerServiceStub_032
 * @tc.desc: OnRemoteRequest SET_VOLUME_MODE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVolumeMode_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备音量模式消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(1);
    EXPECT_CALL(*mockService, SetVolumeMode(1)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetVolumeMode
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VOLUME_MODE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备起始帧率优化消息
测试步骤: 通过OnRemoteRequest下发SET_START_FRAME_RATE_OPT_ENABLED消息
预期结果: Stub解析enabled并调度playerServer_->SetStartFrameRateOptEnabled
*/
/**
 * @tc.name: SetStartFrameRateOptEnabled_001
 * @tc.number: PlayerServiceStub_033
 * @tc.desc: OnRemoteRequest SET_START_FRAME_RATE_OPT_ENABLED dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetStartFrameRateOptEnabled_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备起始帧率优化消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetStartFrameRateOptEnabled(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetStartFrameRateOptEnabled
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_START_FRAME_RATE_OPT_ENABLED, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发SEEK_TO_DEFAULT_POSITION消息
预期结果: Stub调度playerServer_->SeekToDefaultPosition
*/
/**
 * @tc.name: SeekToDefaultPosition_001
 * @tc.number: PlayerServiceStub_034
 * @tc.desc: OnRemoteRequest SEEK_TO_DEFAULT_POSITION dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SeekToDefaultPosition_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, SeekToDefaultPosition()).WillOnce(Return(0));

    // When: 通过IPC消息调度SeekToDefaultPosition
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SEEK_TO_DEFAULT_POSITION, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回时间戳
测试步骤: 通过OnRemoteRequest下发GET_CURRENT_PRESENTATION_TIMESTAMP消息
预期结果: Stub调度playerServer_并把时间戳与返回码写入reply
*/
/**
 * @tc.name: GetCurrentPresentationTimestamp_001
 * @tc.number: PlayerServiceStub_035
 * @tc.desc: OnRemoteRequest GET_CURRENT_PRESENTATION_TIMESTAMP writes timestamp to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetCurrentPresentationTimestamp_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回时间戳
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetCurrentPresentationTimestamp(_))
        .WillOnce(DoAll(SetArgReferee<0>(static_cast<int64_t>(123456)), Return(0)));

    // When: 通过IPC消息查询时间戳
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_CURRENT_PRESENTATION_TIMESTAMP, data,
        reply, option);

    // Then: 调度成功且reply携带时间戳与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt64(), 123456);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回播放位置
测试步骤: 通过OnRemoteRequest下发GET_PLAY_BACK_POSITION消息
预期结果: Stub调度playerServer_并把位置与返回码写入reply
*/
/**
 * @tc.name: GetPlaybackPosition_001
 * @tc.number: PlayerServiceStub_036
 * @tc.desc: OnRemoteRequest GET_PLAY_BACK_POSITION writes position to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetPlaybackPosition_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回播放位置
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetPlaybackPosition(_))
        .WillOnce(DoAll(SetArgReferee<0>(3000), Return(0)));

    // When: 通过IPC消息查询播放位置
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_PLAY_BACK_POSITION, data, reply, option);

    // Then: 调度成功且reply携带位置与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 3000);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回API版本
测试步骤: 通过OnRemoteRequest下发GET_API_VERSION消息
预期结果: Stub调度playerServer_并把版本与返回码写入reply
*/
/**
 * @tc.name: GetApiVersion_001
 * @tc.number: PlayerServiceStub_037
 * @tc.desc: OnRemoteRequest GET_API_VERSION writes version to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetApiVersion_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回API版本
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetApiVersion(_)).WillOnce(DoAll(SetArgReferee<0>(12), Return(0)));

    // When: 通过IPC消息查询API版本
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_API_VERSION, data, reply, option);

    // Then: 调度成功且reply携带版本与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 12);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备播放速率消息
测试步骤: 通过OnRemoteRequest下发SET_PLAYERBACK_RATE消息
预期结果: Stub解析rate并调度playerServer_->SetPlaybackRate
*/
/**
 * @tc.name: SetPlaybackRate_001
 * @tc.number: PlayerServiceStub_038
 * @tc.desc: OnRemoteRequest SET_PLAYERBACK_RATE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlaybackRate_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备播放速率消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFloat(1.5f);
    EXPECT_CALL(*mockService, SetPlaybackRate(1.5f)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlaybackRate
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAYERBACK_RATE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回播放速率
测试步骤: 通过OnRemoteRequest下发GET_PLAYERBACK_RATE消息
预期结果: Stub调度playerServer_并把速率与返回码写入reply
*/
/**
 * @tc.name: GetPlaybackRate_001
 * @tc.number: PlayerServiceStub_039
 * @tc.desc: OnRemoteRequest GET_PLAYERBACK_RATE writes rate to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetPlaybackRate_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回播放速率
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetPlaybackRate(_)).WillOnce(DoAll(SetArgReferee<0>(2.0f), Return(0)));

    // When: 通过IPC消息查询播放速率
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_PLAYERBACK_RATE, data, reply, option);

    // Then: 调度成功且reply携带速率与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadFloat(), 2.0f);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备码率消息
测试步骤: 通过OnRemoteRequest下发SELECT_BIT_RATE消息
预期结果: Stub解析bitrate并调度playerServer_->SelectBitRate
*/
/**
 * @tc.name: SelectBitRate_001
 * @tc.number: PlayerServiceStub_040
 * @tc.desc: OnRemoteRequest SELECT_BIT_RATE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SelectBitRate_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备码率消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(320000);
    EXPECT_CALL(*mockService, SelectBitRate(static_cast<uint32_t>(320000))).WillOnce(Return(0));

    // When: 通过IPC消息调度SelectBitRate
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SELECT_BIT_RATE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回支持连续Seek
测试步骤: 通过OnRemoteRequest下发IS_SEEK_CONTINUOUS_SUPPORTED消息
预期结果: Stub调度playerServer_并把结果写入reply
*/
/**
 * @tc.name: IsSeekContinuousSupported_001
 * @tc.number: PlayerServiceStub_041
 * @tc.desc: OnRemoteRequest IS_SEEK_CONTINUOUS_SUPPORTED writes result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, IsSeekContinuousSupported_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回支持连续Seek
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, IsSeekContinuousSupported()).WillOnce(Return(true));

    // When: 通过IPC消息查询连续Seek能力
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::IS_SEEK_CONTINUOUS_SUPPORTED, data, reply, option);

    // Then: 调度成功且reply携带true
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回当前轨道
测试步骤: 通过OnRemoteRequest下发GET_CURRENT_TRACK消息
预期结果: Stub解析trackType并把轨道索引与返回码写入reply
*/
/**
 * @tc.name: GetCurrentTrack_001
 * @tc.number: PlayerServiceStub_042
 * @tc.desc: OnRemoteRequest GET_CURRENT_TRACK writes index and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetCurrentTrack_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回当前轨道
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, GetCurrentTrack(0, _)).WillOnce(DoAll(SetArgReferee<1>(2), Return(0)));

    // When: 通过IPC消息查询当前轨道
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_CURRENT_TRACK, data, reply, option);

    // Then: 调度成功且reply携带索引与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 2);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备静音消息
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_MUTED消息
预期结果: Stub解析媒体类型与静音标志并调度playerServer_->SetMediaMuted
*/
/**
 * @tc.name: SetMediaMuted_001
 * @tc.number: PlayerServiceStub_043
 * @tc.desc: OnRemoteRequest SET_MEDIA_MUTED dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaMuted_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备静音消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetMediaMuted(_, true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetMediaMuted
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_MUTED, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备超分消息
测试步骤: 通过OnRemoteRequest下发SET_SUPER_RESOLUTION消息
预期结果: Stub解析enabled并调度playerServer_->SetSuperResolution
*/
/**
 * @tc.name: SetSuperResolution_001
 * @tc.number: PlayerServiceStub_044
 * @tc.desc: OnRemoteRequest SET_SUPER_RESOLUTION dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSuperResolution_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备超分消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetSuperResolution(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSuperResolution
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SUPER_RESOLUTION, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备视频窗口尺寸消息
测试步骤: 通过OnRemoteRequest下发SET_VIDEO_WINDOW_SIZE消息
预期结果: Stub解析宽高并调度playerServer_->SetVideoWindowSize
*/
/**
 * @tc.name: SetVideoWindowSize_001
 * @tc.number: PlayerServiceStub_045
 * @tc.desc: OnRemoteRequest SET_VIDEO_WINDOW_SIZE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVideoWindowSize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备视频窗口尺寸消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(1280);
    (void)data.WriteInt32(720);
    EXPECT_CALL(*mockService, SetVideoWindowSize(1280, 720)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetVideoWindowSize
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VIDEO_WINDOW_SIZE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备最大振幅回调状态消息
测试步骤: 通过OnRemoteRequest下发SET_MAX_AMPLITUDE_CB_STATUS消息
预期结果: Stub解析status并调度playerServer_->SetMaxAmplitudeCbStatus
*/
/**
 * @tc.name: SetMaxAmplitudeCbStatus_001
 * @tc.number: PlayerServiceStub_046
 * @tc.desc: OnRemoteRequest SET_MAX_AMPLITUDE_CB_STATUS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMaxAmplitudeCbStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备最大振幅回调状态消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(1);
    EXPECT_CALL(*mockService, SetMaxAmplitudeCbStatus(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetMaxAmplitudeCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MAX_AMPLITUDE_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备设备变化回调状态消息
测试步骤: 通过OnRemoteRequest下发SET_DEVICE_CHANGE_CB_STATUS消息
预期结果: Stub解析status并调度playerServer_->SetDeviceChangeCbStatus
*/
/**
 * @tc.name: SetDeviceChangeCbStatus_001
 * @tc.number: PlayerServiceStub_047
 * @tc.desc: OnRemoteRequest SET_DEVICE_CHANGE_CB_STATUS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetDeviceChangeCbStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备设备变化回调状态消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(1);
    EXPECT_CALL(*mockService, SetDeviceChangeCbStatus(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetDeviceChangeCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_DEVICE_CHANGE_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备字幕回调DFX状态消息
测试步骤: 通过OnRemoteRequest下发SET_SUBTITLE_CB_DFX_STATUS消息
预期结果: Stub解析isRegistered并调度playerServer_->SetSubtitleCbDfxStatus
*/
/**
 * @tc.name: SetSubtitleCbDfxStatus_001
 * @tc.number: PlayerServiceStub_048
 * @tc.desc: OnRemoteRequest SET_SUBTITLE_CB_DFX_STATUS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSubtitleCbDfxStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备字幕回调DFX状态消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetSubtitleCbDfxStatus(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSubtitleCbDfxStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SUBTITLE_CB_DFX_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备SEI消息回调状态
测试步骤: 通过OnRemoteRequest下发SET_SEI_MESSAGE_CB_STATUS消息
预期结果: Stub解析status与payloadTypes并调度playerServer_->SetSeiMessageCbStatus
*/
/**
 * @tc.name: SetSeiMessageCbStatus_001
 * @tc.number: PlayerServiceStub_049
 * @tc.desc: OnRemoteRequest SET_SEI_MESSAGE_CB_STATUS parses payload types and dispatches test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSeiMessageCbStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备SEI消息回调状态
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    (void)data.WriteInt32(2);
    (void)data.WriteInt32(1);
    (void)data.WriteInt32(2);
    EXPECT_CALL(*mockService, SetSeiMessageCbStatus(true, _)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSeiMessageCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备重开fd消息
测试步骤: 通过OnRemoteRequest下发SET_REOPEN_FD消息
预期结果: Stub解析两个fd并调度playerServer_->SetReopenFd
*/
/**
 * @tc.name: SetReopenFd_001
 * @tc.number: PlayerServiceStub_050
 * @tc.desc: OnRemoteRequest SET_REOPEN_FD parses fds and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetReopenFd_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备重开fd消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    int32_t fdCinema = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    ASSERT_GE(fdCinema, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteFileDescriptor(fdCinema);
    EXPECT_CALL(*mockService, SetReopenFd(_, _)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetReopenFd
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_REOPEN_FD, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发ENABLE_CAMERA_POSTPROCESSING消息
预期结果: Stub调度playerServer_->EnableCameraPostprocessing
*/
/**
 * @tc.name: EnableCameraPostprocessing_001
 * @tc.number: PlayerServiceStub_051
 * @tc.desc: OnRemoteRequest ENABLE_CAMERA_POSTPROCESSING dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, EnableCameraPostprocessing_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, EnableCameraPostprocessing()).WillOnce(Return(0));

    // When: 通过IPC消息调度EnableCameraPostprocessing
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ENABLE_CAMERA_POSTPROCESSING, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备相机后处理消息
测试步骤: 通过OnRemoteRequest下发SET_CAMERA_POST_POSTPROCESSING消息
预期结果: Stub解析isOpen并调度playerServer_->SetCameraPostprocessing
*/
/**
 * @tc.name: SetCameraPostprocessing_001
 * @tc.number: PlayerServiceStub_052
 * @tc.desc: OnRemoteRequest SET_CAMERA_POST_POSTPROCESSING dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetCameraPostprocessing_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备相机后处理消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetCameraPostprocessing(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetCameraPostprocessing
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_CAMERA_POST_POSTPROCESSING, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备媒体进度上报消息
测试步骤: 通过OnRemoteRequest下发ENABLE_REPORT_MEDIA_PROGRESS消息
预期结果: Stub解析enable并调度playerServer_->EnableReportMediaProgress
*/
/**
 * @tc.name: EnableReportMediaProgress_001
 * @tc.number: PlayerServiceStub_053
 * @tc.desc: OnRemoteRequest ENABLE_REPORT_MEDIA_PROGRESS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, EnableReportMediaProgress_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备媒体进度上报消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, EnableReportMediaProgress(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度EnableReportMediaProgress
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ENABLE_REPORT_MEDIA_PROGRESS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备音频中断上报消息
测试步骤: 通过OnRemoteRequest下发ENABLE_REPORT_AUDIO_INTERRUPT消息
预期结果: Stub解析enable并调度playerServer_->EnableReportAudioInterrupt
*/
/**
 * @tc.name: EnableReportAudioInterrupt_001
 * @tc.number: PlayerServiceStub_054
 * @tc.desc: OnRemoteRequest ENABLE_REPORT_AUDIO_INTERRUPT dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, EnableReportAudioInterrupt_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备音频中断上报消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, EnableReportAudioInterrupt(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度EnableReportAudioInterrupt
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ENABLE_REPORT_AUDIO_INTERRUPT, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备强制加载视频消息
测试步骤: 通过OnRemoteRequest下发FORCE_LOAD_VIDEO消息
预期结果: Stub解析status并调度playerServer_->ForceLoadVideo
*/
/**
 * @tc.name: ForceLoadVideo_001
 * @tc.number: PlayerServiceStub_055
 * @tc.desc: OnRemoteRequest FORCE_LOAD_VIDEO dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, ForceLoadVideo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备强制加载视频消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, ForceLoadVideo(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度ForceLoadVideo
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::FORCE_LOAD_VIDEO, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备响度增益消息
测试步骤: 通过OnRemoteRequest下发SET_LOUDNESSGAIN消息
预期结果: Stub解析gain并调度playerServer_->SetLoudnessGain
*/
/**
 * @tc.name: SetLoudnessGain_001
 * @tc.number: PlayerServiceStub_056
 * @tc.desc: OnRemoteRequest SET_LOUDNESSGAIN dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetLoudnessGain_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备响度增益消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFloat(0.5f);
    EXPECT_CALL(*mockService, SetLoudnessGain(0.5f)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetLoudnessGain
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_LOUDNESSGAIN, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回直播Seek能力
测试步骤: 通过OnRemoteRequest下发IS_LIVE_SEEK消息
预期结果: Stub调度playerServer_并把结果写入reply
*/
/**
 * @tc.name: IsLiveSeek_001
 * @tc.number: PlayerServiceStub_057
 * @tc.desc: OnRemoteRequest IS_LIVE_SEEK writes result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, IsLiveSeek_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回直播Seek能力
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, IsLiveSeek()).WillOnce(Return(true));

    // When: 通过IPC消息查询直播Seek能力
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::IS_LIVE_SEEK, data, reply, option);

    // Then: 调度成功且reply携带true
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(reply.ReadBool());
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回视频采样结果
测试步骤: 通过OnRemoteRequest下发GET_VIDEO_SAMPLE消息
预期结果: Stub调度playerServer_并把采样结果与返回码写入reply
*/
/**
 * @tc.name: GetVideoSample_001
 * @tc.number: PlayerServiceStub_058
 * @tc.desc: OnRemoteRequest GET_VIDEO_SAMPLE writes sample result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetVideoSample_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回视频采样结果
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetVideoSample(_)).WillOnce(DoAll(SetArgReferee<0>(1), Return(0)));

    // When: 通过IPC消息查询视频采样
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_VIDEO_SAMPLE, data, reply, option);

    // Then: 调度成功且reply携带采样结果与返回码
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(reply.ReadInt32(), 1);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备PCM输出状态消息
测试步骤: 通过OnRemoteRequest下发SET_PCM_OUTPUT_CB_STATUS消息
预期结果: Stub解析isEnable并调度playerServer_->SetPCMOutputStatus
*/
/**
 * @tc.name: SetPCMOutputStatus_001
 * @tc.number: PlayerServiceStub_059
 * @tc.desc: OnRemoteRequest SET_PCM_OUTPUT_CB_STATUS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMOutputStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备PCM输出状态消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetPCMOutputStatus(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPCMOutputStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_OUTPUT_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备PCM处理状态消息
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_CB_STATUS消息
预期结果: Stub解析isEnable并调度playerServer_->SetPCMProcessorStatus
*/
/**
 * @tc.name: SetPCMProcessorStatus_001
 * @tc.number: PlayerServiceStub_060
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_CB_STATUS dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorStatus_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备PCM处理状态消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    EXPECT_CALL(*mockService, SetPCMProcessorStatus(true)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPCMProcessorStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备PCM最大长度消息
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_MAX_LEN消息
预期结果: Stub解析长度并调度playerServer_->SetPCMProcessorMaxLen
*/
/**
 * @tc.name: SetPCMProcessorMaxLen_001
 * @tc.number: PlayerServiceStub_061
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_MAX_LEN dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorMaxLen_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备PCM最大长度消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(1024);
    EXPECT_CALL(*mockService, SetPCMProcessorMaxLen(1024)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPCMProcessorMaxLen
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_MAX_LEN, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备移除广告源消息
测试步骤: 通过OnRemoteRequest下发REMOVE_ADS_MEDIA_SOURCE消息
预期结果: Stub解析id并调度playerServer_->RemoveAdsMediaSource
*/
/**
 * @tc.name: RemoveAdsMediaSource_001
 * @tc.number: PlayerServiceStub_062
 * @tc.desc: OnRemoteRequest REMOVE_ADS_MEDIA_SOURCE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, RemoveAdsMediaSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备移除广告源消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("ads1");
    EXPECT_CALL(*mockService, RemoveAdsMediaSource(std::string("ads1"))).WillOnce(Return(0));

    // When: 通过IPC消息调度RemoveAdsMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::REMOVE_ADS_MEDIA_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发SKIP_CURRENT_ADS_MEDIA_SOURCE消息
预期结果: Stub调度playerServer_->SkipCurrentAdsMediaSource
*/
/**
 * @tc.name: SkipCurrentAdsMediaSource_001
 * @tc.number: PlayerServiceStub_063
 * @tc.desc: OnRemoteRequest SKIP_CURRENT_ADS_MEDIA_SOURCE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SkipCurrentAdsMediaSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, SkipCurrentAdsMediaSource()).WillOnce(Return(0));

    // When: 通过IPC消息调度SkipCurrentAdsMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SKIP_CURRENT_ADS_MEDIA_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发DISABLE_ALL_ADS_MEDIA_SOURCE消息
预期结果: Stub调度playerServer_->DisableAllAdsMediaSource
*/
/**
 * @tc.name: DisableAllAdsMediaSource_001
 * @tc.number: PlayerServiceStub_064
 * @tc.desc: OnRemoteRequest DISABLE_ALL_ADS_MEDIA_SOURCE dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, DisableAllAdsMediaSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, DisableAllAdsMediaSource()).WillOnce(Return(0));

    // When: 通过IPC消息调度DisableAllAdsMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::DISABLE_ALL_ADS_MEDIA_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回支持命令
测试步骤: 通过OnRemoteRequest下发CHECK_SUPPORT_PLAYBACK_COMMAND消息
预期结果: Stub解析命令并把支持标志与返回码写入reply
*/
/**
 * @tc.name: CheckSupportPlaybackCommand_001
 * @tc.number: PlayerServiceStub_065
 * @tc.desc: OnRemoteRequest CHECK_SUPPORT_PLAYBACK_COMMAND writes support and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, CheckSupportPlaybackCommand_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回支持命令
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, CheckSupportPlaybackCommand(_, _))
        .WillOnce(DoAll(SetArgReferee<1>(true), Return(0)));

    // When: 通过IPC消息查询命令支持情况
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::CHECK_SUPPORT_PLAYBACK_COMMAND, data, reply, option);

    // Then: 调度成功且reply携带支持标志与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(reply.ReadBool());
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备文件路径消息
测试步骤: 通过OnRemoteRequest下发SET_FILE_PATH消息
预期结果: Stub解析fd与路径并调度playerServer_->SetFilePath
*/
/**
 * @tc.name: SetFilePath_001
 * @tc.number: PlayerServiceStub_066
 * @tc.desc: OnRemoteRequest SET_FILE_PATH parses fd and path and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetFilePath_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备文件路径消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteString("test.mp4");
    EXPECT_CALL(*mockService, SetFilePath(_, std::string("test.mp4"))).WillOnce(Return(0));

    // When: 通过IPC消息调度SetFilePath
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_FILE_PATH, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空视频轨道
测试步骤: 通过OnRemoteRequest下发GET_VIDEO_TRACK_INFO消息
预期结果: Stub调度playerServer_并把轨道数量与返回码写入reply
*/
/**
 * @tc.name: GetVideoTrackInfo_001
 * @tc.number: PlayerServiceStub_067
 * @tc.desc: OnRemoteRequest GET_VIDEO_TRACK_INFO writes track size and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetVideoTrackInfo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空视频轨道
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetVideoTrackInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<Format>()), Return(0)));

    // When: 通过IPC消息查询视频轨道
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_VIDEO_TRACK_INFO, data, reply, option);

    // Then: 调度成功且reply携带轨道数量与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空音频轨道
测试步骤: 通过OnRemoteRequest下发GET_AUDIO_TRACK_INFO消息
预期结果: Stub调度playerServer_并把轨道数量与返回码写入reply
*/
/**
 * @tc.name: GetAudioTrackInfo_001
 * @tc.number: PlayerServiceStub_068
 * @tc.desc: OnRemoteRequest GET_AUDIO_TRACK_INFO writes track size and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetAudioTrackInfo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空音频轨道
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetAudioTrackInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<Format>()), Return(0)));

    // When: 通过IPC消息查询音频轨道
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_AUDIO_TRACK_INFO, data, reply, option);

    // Then: 调度成功且reply携带轨道数量与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空字幕轨道
测试步骤: 通过OnRemoteRequest下发GET_SUBTITLE_TRACK_INFO消息
预期结果: Stub调度playerServer_并把轨道数量与返回码写入reply
*/
/**
 * @tc.name: GetSubtitleTrackInfo_001
 * @tc.number: PlayerServiceStub_069
 * @tc.desc: OnRemoteRequest GET_SUBTITLE_TRACK_INFO writes track size and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetSubtitleTrackInfo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空字幕轨道
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetSubtitleTrackInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<Format>()), Return(0)));

    // When: 通过IPC消息查询字幕轨道
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_SUBTITLE_TRACK_INFO, data, reply, option);

    // Then: 调度成功且reply携带轨道数量与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空播放信息
测试步骤: 通过OnRemoteRequest下发GET_PLAYBACK_INFO消息
预期结果: Stub调度playerServer_并把播放信息与返回码写入reply
*/
/**
 * @tc.name: GetPlaybackInfo_001
 * @tc.number: PlayerServiceStub_070
 * @tc.desc: OnRemoteRequest GET_PLAYBACK_INFO writes playback info and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetPlaybackInfo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空播放信息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetPlaybackInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(Format()), Return(0)));

    // When: 通过IPC消息查询播放信息
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_PLAYBACK_INFO, data, reply, option);

    // Then: 调度成功且reply携带播放信息与返回码
    EXPECT_EQ(ret, MSERR_OK);
    Format playbackInfo;
    EXPECT_TRUE(MediaParcel::Unmarshalling(reply, playbackInfo));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空统计信息
测试步骤: 通过OnRemoteRequest下发GET_PLAYBACK_STATISTIC_METRICS消息
预期结果: Stub调度playerServer_并把统计信息与返回码写入reply
*/
/**
 * @tc.name: GetPlaybackStatisticMetrics_001
 * @tc.number: PlayerServiceStub_071
 * @tc.desc: OnRemoteRequest GET_PLAYBACK_STATISTIC_METRICS writes metrics and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetPlaybackStatisticMetrics_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空统计信息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetPlaybackStatisticMetrics(_))
        .WillOnce(DoAll(SetArgReferee<0>(Format()), Return(0)));

    // When: 通过IPC消息查询播放统计信息
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_PLAYBACK_STATISTIC_METRICS, data, reply, option);

    // Then: 调度成功且reply携带统计信息与返回码
    EXPECT_EQ(ret, MSERR_OK);
    Format metrics;
    EXPECT_TRUE(MediaParcel::Unmarshalling(reply, metrics));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备参数消息
测试步骤: 通过OnRemoteRequest下发SET_RENDERER_DESC消息
预期结果: Stub解析Format并调度playerServer_->SetParameter
*/
/**
 * @tc.name: SetParameter_001
 * @tc.number: PlayerServiceStub_072
 * @tc.desc: OnRemoteRequest SET_RENDERER_DESC parses format and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetParameter_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备参数消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    Format param;
    EXPECT_TRUE(MediaParcel::Marshalling(data, param));
    EXPECT_CALL(*mockService, SetParameter(_)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetParameter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_RENDERER_DESC, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备媒体描述消息
测试步骤: 通过OnRemoteRequest下发GET_MEDIA_DESCRIPTION消息
预期结果: Stub调度playerServer_并把媒体描述与返回码写入reply
*/
/**
 * @tc.name: GetMediaDescription_001
 * @tc.number: PlayerServiceStub_073
 * @tc.desc: OnRemoteRequest GET_MEDIA_DESCRIPTION writes description and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetMediaDescription_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备媒体描述消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    Format inFormat;
    EXPECT_TRUE(MediaParcel::Marshalling(data, inFormat));
    EXPECT_CALL(*mockService, GetMediaDescription(_))
        .WillOnce(DoAll(SetArgReferee<0>(Format()), Return(0)));

    // When: 通过IPC消息查询媒体描述
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_MEDIA_DESCRIPTION, data, reply, option);

    // Then: 调度成功且reply携带媒体描述与返回码
    EXPECT_EQ(ret, MSERR_OK);
    Format outFormat;
    EXPECT_TRUE(MediaParcel::Unmarshalling(reply, outFormat));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备轨道描述消息
测试步骤: 通过OnRemoteRequest下发GET_TRACK_DESCRIPTION消息
预期结果: Stub解析trackIndex并调度playerServer_->GetTrackDescription
*/
/**
 * @tc.name: GetTrackDescription_001
 * @tc.number: PlayerServiceStub_074
 * @tc.desc: OnRemoteRequest GET_TRACK_DESCRIPTION parses index and writes description to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetTrackDescription_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备轨道描述消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    Format inFormat;
    EXPECT_TRUE(MediaParcel::Marshalling(data, inFormat));
    (void)data.WriteUint32(0);
    EXPECT_CALL(*mockService, GetTrackDescription(_, 0u))
        .WillOnce(DoAll(SetArgReferee<0>(Format()), Return(0)));

    // When: 通过IPC消息查询轨道描述
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_TRACK_DESCRIPTION, data, reply, option);

    // Then: 调度成功且reply携带轨道描述与返回码
    EXPECT_EQ(ret, MSERR_OK);
    Format outFormat;
    EXPECT_TRUE(MediaParcel::Unmarshalling(reply, outFormat));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空可Seek区间
测试步骤: 通过OnRemoteRequest下发GET_SEEKABLE_RANGES消息
预期结果: Stub调度playerServer_并把区间数量与返回码写入reply
*/
/**
 * @tc.name: GetSeekableRanges_001
 * @tc.number: PlayerServiceStub_075
 * @tc.desc: OnRemoteRequest GET_SEEKABLE_RANGES writes range size and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetSeekableRanges_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空可Seek区间
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetSeekableRanges(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<Plugins::SeekRange>()), Return(0)));

    // When: 通过IPC消息查询可Seek区间
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_SEEKABLE_RANGES, data, reply, option);

    // Then: 调度成功且reply携带区间数量与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空已加载区间
测试步骤: 通过OnRemoteRequest下发GET_LOADED_RANGES消息
预期结果: Stub调度playerServer_并把区间数量与返回码写入reply
*/
/**
 * @tc.name: GetLoadedRanges_001
 * @tc.number: PlayerServiceStub_076
 * @tc.desc: OnRemoteRequest GET_LOADED_RANGES writes range size and result to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetLoadedRanges_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空已加载区间
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetLoadedRanges(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<Plugins::SeekRange>()), Return(0)));

    // When: 通过IPC消息查询已加载区间
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_LOADED_RANGES, data, reply, option);

    // Then: 调度成功且reply携带区间数量与返回码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发SET_CALLBACK消息
预期结果: Stub调度playerServer_->SetPlayerCallback
*/
/**
 * @tc.name: SetPlayerCallback_001
 * @tc.number: PlayerServiceStub_077
 * @tc.desc: OnRemoteRequest SET_CALLBACK dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlayerCallback_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, SetPlayerCallback(_)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlayerCallback
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_CALLBACK, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备播放策略消息
测试步骤: 通过OnRemoteRequest下发SET_PLAYBACK_STRATEGY消息
预期结果: Stub解析14个字段并调度playerServer_->SetPlaybackStrategy
*/
/**
 * @tc.name: SetPlaybackStrategy_001
 * @tc.number: PlayerServiceStub_078
 * @tc.desc: OnRemoteRequest SET_PLAYBACK_STRATEGY parses fields and dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlaybackStrategy_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备播放策略消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint32(1920);
    (void)data.WriteUint32(1080);
    (void)data.WriteUint32(500);
    (void)data.WriteDouble(1.0);
    (void)data.WriteDouble(0.5);
    (void)data.WriteBool(true);
    (void)data.WriteBool(true);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("en");
    (void)data.WriteString("zh");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SetPlaybackStrategy(_)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPlaybackStrategy
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAYBACK_STRATEGY, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造PlayerServiceStub并将playerServer_置空
测试步骤: 通过OnRemoteRequest下发PLAY消息
预期结果: Stub返回MSERR_NO_MEMORY并写入reply
*/
/**
 * @tc.name: OnRemoteRequest_NullServer_001
 * @tc.number: PlayerServiceStub_079
 * @tc.desc: OnRemoteRequest with null player server returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub并将playerServer_置空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度Play
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 调度成功且reply携带空服务错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备file协议url
测试步骤: 通过OnRemoteRequest下发SET_SOURCE消息
预期结果: Stub拒绝file url，reply返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetSource_FileUrlRejected_001
 * @tc.number: PlayerServiceStub_080
 * @tc.desc: OnRemoteRequest SET_SOURCE rejects file url test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSource_FileUrlRejected_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备file协议url
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("file:///data/test.mp4");

    // When: 通过IPC消息调度SetSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带参数非法错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备file协议字幕url
测试步骤: 通过OnRemoteRequest下发ADD_SUB_SOURCE消息
预期结果: Stub拒绝file url，reply返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: AddSubSource_FileUrlRejected_001
 * @tc.number: PlayerServiceStub_081
 * @tc.desc: OnRemoteRequest ADD_SUB_SOURCE rejects file url test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubSource_FileUrlRejected_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备file协议字幕url
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("file:///data/sub.srt");

    // When: 通过IPC消息调度AddSubSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_SOURCE, data, reply, option);

    // Then: 调度成功且reply携带参数非法错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备超限payloadTypes
测试步骤: 通过OnRemoteRequest下发SET_SEI_MESSAGE_CB_STATUS消息（size=101）
预期结果: Stub拒绝超限，返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetSeiMessageCbStatus_Oversize_001
 * @tc.number: PlayerServiceStub_082
 * @tc.desc: OnRemoteRequest SET_SEI_MESSAGE_CB_STATUS rejects oversized payload types test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSeiMessageCbStatus_Oversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备超限payloadTypes
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    (void)data.WriteInt32(101);

    // When: 通过IPC消息调度SetSeiMessageCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, data, reply, option);

    // Then: 超限被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备0长度PCM上限
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_MAX_LEN消息（0）
预期结果: Stub拒绝非法长度，返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetPCMProcessorMaxLen_Zero_001
 * @tc.number: PlayerServiceStub_083
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_MAX_LEN rejects zero length test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorMaxLen_Zero_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备0长度PCM上限
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);

    // When: 通过IPC消息调度SetPCMProcessorMaxLen
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_MAX_LEN, data, reply, option);

    // Then: 非法长度被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备超上限PCM长度
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_MAX_LEN消息（5MB+1）
预期结果: Stub拒绝超限长度，返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetPCMProcessorMaxLen_OverLimit_001
 * @tc.number: PlayerServiceStub_084
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_MAX_LEN rejects over limit length test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorMaxLen_OverLimit_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备超上限PCM长度
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(5 * 1024 * 1024 + 1);

    // When: 通过IPC消息调度SetPCMProcessorMaxLen
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_MAX_LEN, data, reply, option);

    // Then: 超限长度被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备最小音量消息
测试步骤: 通过OnRemoteRequest下发SET_VOLUME消息（0.0/0.0）
预期结果: Stub解析并调度playerServer_->SetVolume
*/
/**
 * @tc.name: SetVolume_Zero_001
 * @tc.number: PlayerServiceStub_085
 * @tc.desc: OnRemoteRequest SET_VOLUME zero boundary dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVolume_Zero_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备最小音量消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFloat(0.0f);
    (void)data.WriteFloat(0.0f);
    EXPECT_CALL(*mockService, SetVolume(0.0f, 0.0f)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetVolume
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VOLUME, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备最大音量消息
测试步骤: 通过OnRemoteRequest下发SET_VOLUME消息（1.0/1.0）
预期结果: Stub解析并调度playerServer_->SetVolume
*/
/**
 * @tc.name: SetVolume_Max_001
 * @tc.number: PlayerServiceStub_086
 * @tc.desc: OnRemoteRequest SET_VOLUME max boundary dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVolume_Max_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备最大音量消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFloat(1.0f);
    (void)data.WriteFloat(1.0f);
    EXPECT_CALL(*mockService, SetVolume(1.0f, 1.0f)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetVolume
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VOLUME, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备0位置Seek消息
测试步骤: 通过OnRemoteRequest下发SEEK消息（0）
预期结果: Stub解析并调度playerServer_->Seek
*/
/**
 * @tc.name: Seek_Zero_001
 * @tc.number: PlayerServiceStub_087
 * @tc.desc: OnRemoteRequest SEEK zero boundary dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Seek_Zero_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备0位置Seek消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(0);
    (void)data.WriteInt32(static_cast<int32_t>(PlayerSeekMode::SEEK_PREVIOUS_SYNC));
    EXPECT_CALL(*mockService, Seek(0, PlayerSeekMode::SEEK_PREVIOUS_SYNC)).WillOnce(Return(0));

    // When: 通过IPC消息调度Seek
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SEEK, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备0码率消息
测试步骤: 通过OnRemoteRequest下发SELECT_BIT_RATE消息（0）
预期结果: Stub解析并调度playerServer_->SelectBitRate
*/
/**
 * @tc.name: SelectBitRate_Zero_001
 * @tc.number: PlayerServiceStub_088
 * @tc.desc: OnRemoteRequest SELECT_BIT_RATE zero boundary dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SelectBitRate_Zero_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备0码率消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SelectBitRate(0u)).WillOnce(Return(0));

    // When: 通过IPC消息调度SelectBitRate
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SELECT_BIT_RATE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备最大码率消息
测试步骤: 通过OnRemoteRequest下发SELECT_BIT_RATE消息（UINT32_MAX）
预期结果: Stub解析并调度playerServer_->SelectBitRate
*/
/**
 * @tc.name: SelectBitRate_Max_001
 * @tc.number: PlayerServiceStub_089
 * @tc.desc: OnRemoteRequest SELECT_BIT_RATE max boundary dispatches to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SelectBitRate_Max_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备最大码率消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(-1);
    EXPECT_CALL(*mockService, SelectBitRate(static_cast<uint32_t>(-1))).WillOnce(Return(0));

    // When: 通过IPC消息调度SelectBitRate
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SELECT_BIT_RATE, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备静音消息
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_MUTED消息并捕获媒体类型
预期结果: Stub解析媒体类型为0并调度playerServer_->SetMediaMuted
*/
/**
 * @tc.name: SetMediaMuted_ParamCheck_001
 * @tc.number: PlayerServiceStub_090
 * @tc.desc: OnRemoteRequest SET_MEDIA_MUTED parses media type test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaMuted_ParamCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备静音消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(true);
    MediaType capturedType = static_cast<MediaType>(1);
    EXPECT_CALL(*mockService, SetMediaMuted(_, true))
        .WillOnce(DoAll(SaveArg<0>(&capturedType), Return(0)));

    // When: 通过IPC消息调度SetMediaMuted
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_MUTED, data, reply, option);

    // Then: 调度成功且媒体类型解析正确
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(capturedType, static_cast<MediaType>(0));
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备SEI消息回调状态
测试步骤: 通过OnRemoteRequest下发SET_SEI_MESSAGE_CB_STATUS消息并校验payloadTypes
预期结果: Stub解析payloadTypes为{1,2}并调度playerServer_->SetSeiMessageCbStatus
*/
/**
 * @tc.name: SetSeiMessageCbStatus_ParamCheck_001
 * @tc.number: PlayerServiceStub_091
 * @tc.desc: OnRemoteRequest SET_SEI_MESSAGE_CB_STATUS parses payload types test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSeiMessageCbStatus_ParamCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备SEI消息回调状态
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    (void)data.WriteInt32(2);
    (void)data.WriteInt32(1);
    (void)data.WriteInt32(2);
    EXPECT_CALL(*mockService, SetSeiMessageCbStatus(true, ElementsAre(1, 2))).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSeiMessageCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, data, reply, option);

    // Then: 调度成功且reply携带返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，准备重开fd消息
测试步骤: 通过OnRemoteRequest下发SET_REOPEN_FD消息并捕获两个fd
预期结果: Stub解析出合法fd并调度playerServer_->SetReopenFd
*/
/**
 * @tc.name: SetReopenFd_ParamCheck_001
 * @tc.number: PlayerServiceStub_092
 * @tc.desc: OnRemoteRequest SET_REOPEN_FD parses both fds test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetReopenFd_ParamCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，准备重开fd消息
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    int32_t fdCinema = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    ASSERT_GE(fdCinema, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteFileDescriptor(fdCinema);
    int32_t capturedFd = -1;
    int32_t capturedFdCinema = -1;
    EXPECT_CALL(*mockService, SetReopenFd(_, _))
        .WillOnce(DoAll(SaveArg<0>(&capturedFd), SaveArg<1>(&capturedFdCinema), Return(0)));

    // When: 通过IPC消息调度SetReopenFd
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_REOPEN_FD, data, reply, option);

    // Then: 调度成功且两个fd均被解析
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_GE(capturedFd, 0);
    EXPECT_GE(capturedFdCinema, 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_LISTENER_OBJ消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_LISTENER_OBJ
预期结果: Stub检测到object为空，reply返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetListenerObject_NullObject_001
 * @tc.number: PlayerServiceStub_093
 * @tc.desc: OnRemoteRequest SET_LISTENER_OBJ with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetListenerObject_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_LISTENER_OBJ消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetListenerObject
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_LISTENER_OBJ, data, reply, option);

    // Then: 调度成功且reply携带空对象错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_DATA_SRC_OBJ消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_DATA_SRC_OBJ
预期结果: Stub检测到object为空，reply返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetMediaDataSource_NullObject_001
 * @tc.number: PlayerServiceStub_094
 * @tc.desc: OnRemoteRequest SET_MEDIA_DATA_SRC_OBJ with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaDataSource_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_MEDIA_DATA_SRC_OBJ消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetMediaDataSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_DATA_SRC_OBJ, data, reply, option);

    // Then: 调度成功且reply携带空对象错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_SOURCE_LOADER消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_SOURCE_LOADER
预期结果: Stub检测到object为空，reply返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetSourceLoader_NullObject_001
 * @tc.number: PlayerServiceStub_095
 * @tc.desc: OnRemoteRequest SET_SOURCE_LOADER with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSourceLoader_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_SOURCE_LOADER消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetSourceLoader
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SOURCE_LOADER, data, reply, option);

    // Then: 调度成功且reply携带空对象错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_PCM_CALLBACK消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_PCM_CALLBACK
预期结果: Stub检测到object为空，reply返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetPCMCallback_NullObject_001
 * @tc.number: PlayerServiceStub_096
 * @tc.desc: OnRemoteRequest SET_PCM_CALLBACK with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMCallback_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_PCM_CALLBACK消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetPCMCallback
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_CALLBACK, data, reply, option);

    // Then: 调度成功且reply携带空对象错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，REGISTER_DEVICE_CAPABILITY消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发REGISTER_DEVICE_CAPABILITY
预期结果: Stub检测到object为空，reply返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: RegisterDeviceCapability_NullObject_001
 * @tc.number: PlayerServiceStub_097
 * @tc.desc: OnRemoteRequest REGISTER_DEVICE_CAPABILITY with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, RegisterDeviceCapability_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，REGISTER_DEVICE_CAPABILITY消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度RegisterDeviceCapability
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::REGISTER_DEVICE_CAPABILITY, data, reply, option);

    // Then: 调度成功且reply携带空对象错误码
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_VIDEO_OUTPUT消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_VIDEO_OUTPUT
预期结果: Stub检测到object为空并返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetVideoOutput_NullObject_001
 * @tc.number: PlayerServiceStub_098
 * @tc.desc: OnRemoteRequest SET_VIDEO_OUTPUT with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVideoOutput_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_VIDEO_OUTPUT消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetVideoOutput
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VIDEO_OUTPUT, data, reply, option);

    // Then: 空对象被拒绝
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_VIDEO_SURFACE消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_VIDEO_SURFACE
预期结果: Stub检测到object为空并返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetVideoSurface_NullObject_001
 * @tc.number: PlayerServiceStub_099
 * @tc.desc: OnRemoteRequest SET_VIDEO_SURFACE with null object returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetVideoSurface_NullObject_001, TestSize.Level0)
{
#ifdef SUPPORT_VIDEO
    // Given: 构造Stub与Mock，SET_VIDEO_SURFACE消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetVideoSurface
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VIDEO_SURFACE, data, reply, option);

    // Then: 空对象被拒绝
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
#else
    // Given: 本构建未启用 SUPPORT_VIDEO，SET_VIDEO_SURFACE 未注册
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 下发未注册的 SET_VIDEO_SURFACE
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_VIDEO_SURFACE, data, reply, option);

    // Then: 回落到默认处理
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
#endif
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_DECRYPT_CONFIG消息未携带远程对象
测试步骤: 通过OnRemoteRequest下发SET_DECRYPT_CONFIG
预期结果: DRM开启时返回MSERR_NO_MEMORY，未开启时返回0
*/
/**
 * @tc.name: SetDecryptConfig_NullObject_001
 * @tc.number: PlayerServiceStub_100
 * @tc.desc: OnRemoteRequest SET_DECRYPT_CONFIG with null object returns expected code test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetDecryptConfig_NullObject_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，SET_DECRYPT_CONFIG消息不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息调度SetDecryptConfig
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_DECRYPT_CONFIG, data, reply, option);

    // Then: 空对象在DRM分支被拒绝
#ifdef SUPPORT_AVPLAYER_DRM
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
#else
    EXPECT_EQ(ret, 0);
#endif
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub
测试步骤: 通过OnRemoteRequest下发DESTROY
预期结果: Stub调度Release并清空playerServer_，reply返回MSERR_OK
*/
/**
 * @tc.name: Destroy_001
 * @tc.number: PlayerServiceStub_101
 * @tc.desc: OnRemoteRequest DESTROY releases player server and clears it test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Destroy_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, Release()).WillOnce(Return(0));

    // When: 通过IPC消息调度Destroy
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::DESTROY, data, reply, option);

    // Then: 调度成功且playerServer_被清空
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    EXPECT_EQ(stub->playerServer_, nullptr);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回成功但不填充Meta
测试步骤: 通过OnRemoteRequest下发GET_GLOBAL_INFO
预期结果: Stub检测到globalInfo为空并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: GetGlobalInfo_NullInfo_001
 * @tc.number: PlayerServiceStub_102
 * @tc.desc: OnRemoteRequest GET_GLOBAL_INFO with null Meta returns MSERR_INVALID_VAL test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetGlobalInfo_NullInfo_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，GetGlobalInfo返回成功但不设置输出参数
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetGlobalInfo(_)).WillOnce(Return(MSERR_OK));

    // When: 通过IPC消息调度GetGlobalInfo
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_GLOBAL_INFO, data, reply, option);

    // Then: 空Meta被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为空源
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub解析出空url源并调度playerServer_->SetMediaSource，reply返回MSERR_OK
*/
/**
 * @tc.name: SetMediaSource_EmptyParcel_001
 * @tc.number: PlayerServiceStub_103
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE dispatches parsed source to player server test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_EmptyParcel_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，消息体为全零源类型
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).Times(0);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 空url被安全校验拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，ADD_ADS_MEDIA_SOURCE消息为合法http url源
测试步骤: 通过OnRemoteRequest下发ADD_ADS_MEDIA_SOURCE
预期结果: Stub解析源并调度AddAdsMediaSource，成功时回写outId
*/
/**
 * @tc.name: AddAdsMediaSource_UrlSource_001
 * @tc.number: PlayerServiceStub_104
 * @tc.desc: OnRemoteRequest ADD_ADS_MEDIA_SOURCE dispatches url source and writes outId test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddAdsMediaSource_UrlSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，消息体为合法http url源
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(0);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("http://example.com/ads.mp4");
    (void)data.WriteUint32(0);
    (void)data.WriteString("");
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, AddAdsMediaSource(_, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(std::string("ads_001")), Return(0)));

    // When: 通过IPC消息调度AddAdsMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_ADS_MEDIA_SOURCE, data, reply, option);

    // Then: 调度成功且outId被回写
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(reply.ReadString(), "ads_001");
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_TRACK_SELECTION_FILTER消息为空过滤条件
测试步骤: 通过OnRemoteRequest下发SET_TRACK_SELECTION_FILTER
预期结果: Stub解析12个整型字段与4组空列表并调度playerServer_
*/
/**
 * @tc.name: SetTrackSelectionFilter_Empty_001
 * @tc.number: PlayerServiceStub_105
 * @tc.desc: OnRemoteRequest SET_TRACK_SELECTION_FILTER parses empty filter and dispatches test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_Empty_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，写入12个整型字段与4组空列表
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    for (int32_t i = 0; i < 11; ++i) {
        (void)data.WriteInt32(0);
    }
    for (int32_t i = 0; i < 4; ++i) {
        (void)data.WriteUint32(0);
    }
    EXPECT_CALL(*mockService, SetTrackSelectionFilter(_)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 调度成功且reply携带player server返回值
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，videoMimeTypes列表长度101
测试步骤: 通过OnRemoteRequest下发SET_TRACK_SELECTION_FILTER
预期结果: Stub检测到列表超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetTrackSelectionFilter_Oversize_001
 * @tc.number: PlayerServiceStub_106
 * @tc.desc: OnRemoteRequest SET_TRACK_SELECTION_FILTER rejects oversize mime list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_Oversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，videoMimeTypes长度为101
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    for (int32_t i = 0; i < 11; ++i) {
        (void)data.WriteInt32(0);
    }
    (void)data.WriteUint32(101);

    // When: 通过IPC消息调度SetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 超限列表被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回空过滤条件
测试步骤: 通过OnRemoteRequest下发GET_TRACK_SELECTION_FILTER
预期结果: Stub调度GetTrackSelectionFilter并序列化12个整型字段与4组空列表
*/
/**
 * @tc.name: GetTrackSelectionFilter_001
 * @tc.number: PlayerServiceStub_107
 * @tc.desc: OnRemoteRequest GET_TRACK_SELECTION_FILTER serializes filter to reply test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetTrackSelectionFilter_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回空过滤条件
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, GetTrackSelectionFilter(_))
        .WillOnce(DoAll(SetArgReferee<0>(AVPlayTrackSelectionFilter{}), Return(0)));

    // When: 通过IPC消息调度GetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 调度成功且reply按协议序列化
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    for (int32_t i = 0; i < 11; ++i) {
        EXPECT_EQ(reply.ReadInt32(), -1);
    }
    for (int32_t i = 0; i < 4; ++i) {
        EXPECT_EQ(reply.ReadUint32(), 0U);
    }
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，isFrozen_为true且UnFreeze返回错误
测试步骤: 通过OnRemoteRequest下发PLAY
预期结果: 自动解冻失败，OnRemoteRequest透传UnFreeze错误码
*/
/**
 * @tc.name: OnRemoteRequest_UnFreezeFailed_001
 * @tc.number: PlayerServiceStub_108
 * @tc.desc: OnRemoteRequest propagates UnFreeze failure before dispatching member func test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_UnFreezeFailed_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Stub处于冻结态且解冻失败
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->isFrozen_ = true;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    EXPECT_CALL(*mockService, UnFreeze()).WillOnce(Return(MSERR_INVALID_OPERATION));
    EXPECT_CALL(*mockService, Play()).Times(0);

    // When: 通过IPC消息调度Play
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::PLAY, data, reply, option);

    // Then: 解冻失败错误码被透传且未调度Play
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，处于未冻结态
测试步骤: 直接调用Freeze并等待任务队列执行
预期结果: Freeze成功且isFrozen_置为true
*/
/**
 * @tc.name: Freeze_001
 * @tc.number: PlayerServiceStub_109
 * @tc.desc: Freeze enqueues task and sets frozen state test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Freeze_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，未冻结
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    EXPECT_CALL(*mockService, Freeze()).WillOnce(Return(MSERR_OK));

    // When: 直接调用Freeze
    int32_t ret = stub->Freeze();

    // Then: 调度成功且状态被置为冻结
    EXPECT_EQ(ret, MSERR_OK);
    for (int32_t i = 0; i < 500 && !stub->isFrozen_; ++i) {
        usleep(1000);
    }
    EXPECT_TRUE(stub->isFrozen_);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，已处于冻结态
测试步骤: 再次调用Freeze
预期结果: 幂等返回MSERR_OK且不重复调度playerServer_->Freeze
*/
/**
 * @tc.name: Freeze_AlreadyFrozen_001
 * @tc.number: PlayerServiceStub_110
 * @tc.desc: Freeze on already frozen stub is idempotent test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Freeze_AlreadyFrozen_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，记录委托调用次数
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t freezeCount = 0;
    EXPECT_CALL(*mockService, Freeze())
        .WillRepeatedly(DoAll(InvokeWithoutArgs([&freezeCount]() { ++freezeCount; }), Return(MSERR_OK)));

    // When: 首次冻结成功后再调用一次Freeze
    EXPECT_EQ(stub->Freeze(), MSERR_OK);
    for (int32_t i = 0; i < 500 && !stub->isFrozen_; ++i) {
        usleep(1000);
    }
    ASSERT_EQ(freezeCount, 1);
    int32_t ret = stub->Freeze();
    usleep(20000);

    // Then: 幂等返回、状态保持冻结且委托未被二次调用
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_TRUE(stub->isFrozen_);
    EXPECT_EQ(freezeCount, 1);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，处于未冻结态
测试步骤: 调用UnFreeze
预期结果: 幂等返回MSERR_OK且不调度playerServer_->UnFreeze
*/
/**
 * @tc.name: UnFreeze_NotFrozen_001
 * @tc.number: PlayerServiceStub_111
 * @tc.desc: UnFreeze on not frozen stub is idempotent test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, UnFreeze_NotFrozen_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，记录委托调用次数
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t unfreezeCount = 0;
    EXPECT_CALL(*mockService, UnFreeze())
        .WillRepeatedly(DoAll(InvokeWithoutArgs([&unfreezeCount]() { ++unfreezeCount; }), Return(MSERR_OK)));

    // When: 先解冻成功，再对未冻结态调用一次UnFreeze
    stub->isFrozen_ = true;
    EXPECT_EQ(stub->UnFreeze(), MSERR_OK);
    for (int32_t i = 0; i < 500 && stub->isFrozen_; ++i) {
        usleep(1000);
    }
    ASSERT_EQ(unfreezeCount, 1);
    int32_t ret = stub->UnFreeze();
    usleep(20000);

    // Then: 幂等返回、状态保持未冻结且委托未被二次调用
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_FALSE(stub->isFrozen_);
    EXPECT_EQ(unfreezeCount, 1);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，处于冻结态
测试步骤: 调用UnFreeze并等待任务队列执行
预期结果: UnFreeze成功且isFrozen_复位为false
*/
/**
 * @tc.name: UnFreeze_Success_001
 * @tc.number: PlayerServiceStub_112
 * @tc.desc: UnFreeze enqueues task and clears frozen state test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, UnFreeze_Success_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，已冻结
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->isFrozen_ = true;
    EXPECT_CALL(*mockService, UnFreeze()).WillOnce(Return(MSERR_OK));

    // When: 调用UnFreeze
    int32_t ret = stub->UnFreeze();

    // Then: 调度成功且状态被复位
    EXPECT_EQ(ret, MSERR_OK);
    for (int32_t i = 0; i < 500 && stub->isFrozen_; ++i) {
        usleep(1000);
    }
    EXPECT_FALSE(stub->isFrozen_);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为fd源且fd非法
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到非法fd并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_FdInvalid_001
 * @tc.number: PlayerServiceStub_113
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects invalid fd test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FdInvalid_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，fd源且fd为0
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x02);
    (void)data.WriteString("");
    (void)data.WriteInt32(0);
    (void)data.WriteInt64(0);
    (void)data.WriteInt64(TEST_FD_SIZE);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).Times(0);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 非法fd被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为fd源且offset为负
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到负offset并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_FdOffsetNegative_001
 * @tc.number: PlayerServiceStub_114
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects negative fd offset test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FdOffsetNegative_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，fd源且offset为-1
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x02);
    (void)data.WriteString("");
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(-1);
    (void)data.WriteInt64(TEST_FD_SIZE);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 负offset被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为fd源且size为0
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到非正size并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_FdSizeZero_001
 * @tc.number: PlayerServiceStub_115
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects zero fd size test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FdSizeZero_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，fd源且size为0
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x02);
    (void)data.WriteString("");
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(0);
    (void)data.WriteInt64(0);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 非正size被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为fd源且offset+size溢出
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到溢出并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_FdOverflow_001
 * @tc.number: PlayerServiceStub_116
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects fd offset+size overflow test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FdOverflow_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，fd源且offset=INT64_MAX、size=1
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x02);
    (void)data.WriteString("");
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(INT64_MAX);
    (void)data.WriteInt64(1);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 溢出被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为file URL源
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub的安全校验拒绝file URL并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetMediaSource_FileUrlRejected_001
 * @tc.number: PlayerServiceStub_117
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects file url test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FileUrlRejected_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，URL源为file://
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("file:///data/test.mp4");
    (void)data.WriteUint32(0);
    (void)data.WriteString("");
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).Times(0);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: file URL被安全校验拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息header map数量为100
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到map超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_HeaderMapOversize_001
 * @tc.number: PlayerServiceStub_118
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects oversize header map test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_HeaderMapOversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，header map数量为100
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("http://example.com/test.mp4");
    (void)data.WriteUint32(100);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 超限map被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息媒体流列表长度为11
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到媒体流列表超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetMediaSource_StreamListOversize_001
 * @tc.number: PlayerServiceStub_119
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects oversize media stream list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_StreamListOversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，媒体流列表长度为11
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x00);
    (void)data.WriteString("");
    (void)data.WriteUint32(11);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 超限列表被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，audioMimeTypes列表长度101
测试步骤: 通过OnRemoteRequest下发SET_TRACK_SELECTION_FILTER
预期结果: Stub检测到第二组列表超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetTrackSelectionFilter_AudioMimeOversize_001
 * @tc.number: PlayerServiceStub_120
 * @tc.desc: OnRemoteRequest SET_TRACK_SELECTION_FILTER rejects oversize audio mime list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_AudioMimeOversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，audioMimeTypes长度为101
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    for (int32_t i = 0; i < 11; ++i) {
        (void)data.WriteInt32(0);
    }
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(101);

    // When: 通过IPC消息调度SetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 超限列表被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，audioLanguages列表长度101
测试步骤: 通过OnRemoteRequest下发SET_TRACK_SELECTION_FILTER
预期结果: Stub检测到第三组列表超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetTrackSelectionFilter_AudioLangOversize_001
 * @tc.number: PlayerServiceStub_121
 * @tc.desc: OnRemoteRequest SET_TRACK_SELECTION_FILTER rejects oversize audio language list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_AudioLangOversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，audioLanguages长度为101
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    for (int32_t i = 0; i < 11; ++i) {
        (void)data.WriteInt32(0);
    }
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(101);

    // When: 通过IPC消息调度SetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 超限列表被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，subtitleLanguages列表长度101
测试步骤: 通过OnRemoteRequest下发SET_TRACK_SELECTION_FILTER
预期结果: Stub检测到第四组列表超限并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetTrackSelectionFilter_SubtitleLangOversize_001
 * @tc.number: PlayerServiceStub_122
 * @tc.desc: OnRemoteRequest SET_TRACK_SELECTION_FILTER rejects oversize subtitle language list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_SubtitleLangOversize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，subtitleLanguages长度为101
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    for (int32_t i = 0; i < 11; ++i) {
        (void)data.WriteInt32(0);
    }
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(101);

    // When: 通过IPC消息调度SetTrackSelectionFilter
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_TRACK_SELECTION_FILTER, data, reply, option);

    // Then: 超限列表被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_SEI_MESSAGE_CB_STATUS消息payloadTypes数量为负
测试步骤: 通过OnRemoteRequest下发SET_SEI_MESSAGE_CB_STATUS
预期结果: Stub检测到非法数量并返回MSERR_INVALID_OPERATION
*/
/**
 * @tc.name: SetSeiMessageCbStatus_NegativeSize_001
 * @tc.number: PlayerServiceStub_123
 * @tc.desc: OnRemoteRequest SET_SEI_MESSAGE_CB_STATUS rejects negative payload size test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSeiMessageCbStatus_NegativeSize_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，payloadTypes数量为-1
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    (void)data.WriteInt32(-1);

    // When: 通过IPC消息调度SetSeiMessageCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, data, reply, option);

    // Then: 非法数量被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_SEI_MESSAGE_CB_STATUS消息payloadTypes数量为100
测试步骤: 通过OnRemoteRequest下发SET_SEI_MESSAGE_CB_STATUS
预期结果: 边界数量被接受并调度playerServer_
*/
/**
 * @tc.name: SetSeiMessageCbStatus_Boundary100_001
 * @tc.number: PlayerServiceStub_124
 * @tc.desc: OnRemoteRequest SET_SEI_MESSAGE_CB_STATUS accepts boundary payload size test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSeiMessageCbStatus_Boundary100_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，payloadTypes数量为100
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteBool(true);
    (void)data.WriteInt32(100);
    for (int32_t i = 0; i < 100; ++i) {
        (void)data.WriteInt32(i);
    }
    EXPECT_CALL(*mockService, SetSeiMessageCbStatus(true, _)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetSeiMessageCbStatus
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SEI_MESSAGE_CB_STATUS, data, reply, option);

    // Then: 边界数量被接受
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_PCM_PROCESSOR_MAX_LEN消息为5MB
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_MAX_LEN
预期结果: 边界值被接受并调度playerServer_
*/
/**
 * @tc.name: SetPCMProcessorMaxLen_MaxBoundary_001
 * @tc.number: PlayerServiceStub_125
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_MAX_LEN accepts 5MB boundary test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorMaxLen_MaxBoundary_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，长度为5MB
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(5 * 1024 * 1024);
    EXPECT_CALL(*mockService, SetPCMProcessorMaxLen(5 * 1024 * 1024)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetPCMProcessorMaxLen
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_MAX_LEN, data, reply, option);

    // Then: 边界值被接受
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_PCM_PROCESSOR_MAX_LEN消息为-1
测试步骤: 通过OnRemoteRequest下发SET_PCM_PROCESSOR_MAX_LEN
预期结果: Stub检测到非正长度并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetPCMProcessorMaxLen_Negative_001
 * @tc.number: PlayerServiceStub_126
 * @tc.desc: OnRemoteRequest SET_PCM_PROCESSOR_MAX_LEN rejects negative length test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPCMProcessorMaxLen_Negative_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，长度为-1
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt32(-1);

    // When: 通过IPC消息调度SetPCMProcessorMaxLen
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PCM_PROCESSOR_MAX_LEN, data, reply, option);

    // Then: 非正长度被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，下发未注册的消息码
测试步骤: 通过OnRemoteRequest下发未注册code
预期结果: 回落到IPCObjectStub默认处理并返回IPC_STUB_UNKNOW_TRANS_ERR
*/
/**
 * @tc.name: OnRemoteRequest_UnknownCode_001
 * @tc.number: PlayerServiceStub_127
 * @tc.desc: OnRemoteRequest unknown code falls back to IPCObjectStub default process test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, OnRemoteRequest_UnknownCode_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，使用未注册的消息码
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);

    // When: 通过IPC消息下发未注册code
    int32_t ret = stub->OnRemoteRequest(9999, data, reply, option);

    // Then: 回落到默认处理
    EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_SOURCE消息为fd:// URL
测试步骤: 通过OnRemoteRequest下发SET_SOURCE
预期结果: Stub拒绝fd URL并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetSource_FdUrlRejected_001
 * @tc.number: PlayerServiceStub_128
 * @tc.desc: OnRemoteRequest SET_SOURCE rejects fd url test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSource_FdUrlRejected_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，url为fd://
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("fd://1234?offset=0&size=100");
    EXPECT_CALL(*mockService, SetSource(::testing::A<const std::string &>())).Times(0);

    // When: 通过IPC消息调度SetSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SOURCE, data, reply, option);

    // Then: fd URL被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，ADD_SUB_SOURCE消息为fd:// URL
测试步骤: 通过OnRemoteRequest下发ADD_SUB_SOURCE
预期结果: Stub拒绝fd URL并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: AddSubSource_FdUrlRejected_001
 * @tc.number: PlayerServiceStub_129
 * @tc.desc: OnRemoteRequest ADD_SUB_SOURCE rejects fd url test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubSource_FdUrlRejected_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，url为fd://
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("fd://1234?offset=0&size=100");
    EXPECT_CALL(*mockService, AddSubSource(::testing::A<const std::string &>())).Times(0);

    // When: 通过IPC消息调度AddSubSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_SOURCE, data, reply, option);

    // Then: fd URL被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
}

/*
前置条件: 构造PlayerServiceStub且playerServer_为空，SET_SOURCE消息为普通url
测试步骤: 通过OnRemoteRequest下发SET_SOURCE
预期结果: Stub检测到服务为空并返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetSource_NullServer_001
 * @tc.number: PlayerServiceStub_130
 * @tc.desc: OnRemoteRequest SET_SOURCE with null player server returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetSource_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub且playerServer_为空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("http://example.com/test.mp4");

    // When: 通过IPC消息调度SetSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_SOURCE, data, reply, option);

    // Then: 空服务被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造PlayerServiceStub且playerServer_为空，ADD_SUB_SOURCE消息为普通url
测试步骤: 通过OnRemoteRequest下发ADD_SUB_SOURCE
预期结果: Stub检测到服务为空并返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: AddSubSource_NullServer_001
 * @tc.number: PlayerServiceStub_131
 * @tc.desc: OnRemoteRequest ADD_SUB_SOURCE with null player server returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubSource_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub且playerServer_为空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteString("http://example.com/test.mp4");

    // When: 通过IPC消息调度AddSubSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_SOURCE, data, reply, option);

    // Then: 空服务被拒绝
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
}

/*
前置条件: 构造PlayerServiceStub且playerServer_为空
测试步骤: 直接调用Freeze
预期结果: 返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: Freeze_NullServer_001
 * @tc.number: PlayerServiceStub_132
 * @tc.desc: Freeze with null player server returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, Freeze_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub且playerServer_为空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;

    // When: 调用Freeze
    int32_t ret = stub->Freeze();

    // Then: 空服务被拒绝
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/*
前置条件: 构造PlayerServiceStub且playerServer_为空
测试步骤: 直接调用UnFreeze
预期结果: 返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: UnFreeze_NullServer_001
 * @tc.number: PlayerServiceStub_133
 * @tc.desc: UnFreeze with null player server returns MSERR_NO_MEMORY test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, UnFreeze_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub且playerServer_为空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;

    // When: 调用UnFreeze
    int32_t ret = stub->UnFreeze();

    // Then: 空服务被拒绝
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回内存占用值
测试步骤: 直接调用GetMemoryUsage
预期结果: 返回Mock设定的内存占用值
*/
/**
 * @tc.name: GetMemoryUsage_Success_001
 * @tc.number: PlayerServiceStub_134
 * @tc.desc: GetMemoryUsage returns player server memory usage test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetMemoryUsage_Success_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回1234
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    EXPECT_CALL(*mockService, GetMemoryUsage()).WillOnce(Return(1234U));

    // When: 调用GetMemoryUsage
    uint32_t usage = stub->GetMemoryUsage();

    // Then: 返回Mock设定值
    EXPECT_EQ(usage, 1234U);
}

/*
前置条件: 构造PlayerServiceStub且playerServer_为空
测试步骤: 直接调用GetMemoryUsage
预期结果: 返回0
*/
/**
 * @tc.name: GetMemoryUsage_NullServer_001
 * @tc.number: PlayerServiceStub_135
 * @tc.desc: GetMemoryUsage with null player server returns 0 test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetMemoryUsage_NullServer_001, TestSize.Level0)
{
    // Given: 构造Stub且playerServer_为空
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    stub->playerServer_ = nullptr;

    // When: 调用GetMemoryUsage
    uint32_t usage = stub->GetMemoryUsage();

    // Then: 返回0
    EXPECT_EQ(usage, 0U);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock填充非空Meta
测试步骤: 通过OnRemoteRequest下发GET_GLOBAL_INFO
预期结果: Stub序列化Meta并返回MSERR_OK
*/
/**
 * @tc.name: GetGlobalInfo_Success_001
 * @tc.number: PlayerServiceStub_136
 * @tc.desc: OnRemoteRequest GET_GLOBAL_INFO serializes non-null Meta test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetGlobalInfo_Success_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock填充非空Meta
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    auto globalInfo = std::make_shared<Meta>();
    EXPECT_CALL(*mockService, GetGlobalInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(globalInfo), Return(MSERR_OK)));

    // When: 通过IPC消息调度GetGlobalInfo
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_GLOBAL_INFO, data, reply, option);

    // Then: 调度成功且reply写入Meta序列化数据
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_GT(reply.GetReadableBytes(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，ADD_ADS_MEDIA_SOURCE消息为空源且Mock返回失败
测试步骤: 通过OnRemoteRequest下发ADD_ADS_MEDIA_SOURCE
预期结果: reply返回失败码且不回写outId
*/
/**
 * @tc.name: AddAdsMediaSource_Fail_001
 * @tc.number: PlayerServiceStub_137
 * @tc.desc: OnRemoteRequest ADD_ADS_MEDIA_SOURCE failure does not write outId test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddAdsMediaSource_Fail_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回失败
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteInt64(0);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("http://example.com/ads.mp4");
    (void)data.WriteUint32(0);
    (void)data.WriteString("");
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, AddAdsMediaSource(_, _, _)).WillOnce(Return(MSERR_INVALID_OPERATION));

    // When: 通过IPC消息调度AddAdsMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_ADS_MEDIA_SOURCE, data, reply, option);

    // Then: 失败码被回写且无outId
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_OPERATION);
    EXPECT_EQ(reply.GetReadableBytes(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为离线目录源
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: 目录路径无协议头，被安全校验拒绝并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetMediaSource_DirectorySource_001
 * @tc.number: PlayerServiceStub_138
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects directory path without scheme test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_DirectorySource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，sourceType为离线目录
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x08);
    (void)data.WriteString("");
    (void)data.WriteString("/data/test/cache");
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).Times(0);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 目录路径无协议头，被安全校验拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为数据源且远程对象为空
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到数据源对象为空并返回MSERR_NO_MEMORY
*/
/**
 * @tc.name: SetMediaSource_DataSourceNull_001
 * @tc.number: PlayerServiceStub_139
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects null data source object test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_DataSourceNull_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，sourceType为数据源且不写远程对象
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x04);
    (void)data.WriteString("");

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 空数据源被拒绝
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为M3U8 fd URL但未传fd
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到fd缺失并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetMediaSource_M3U8FdMissing_001
 * @tc.number: PlayerServiceStub_140
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects m3u8 fd url without fd test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_M3U8FdMissing_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，M3U8 fd URL但fd为-1
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("fd://1234?offset=0&size=100");
    (void)data.WriteUint32(0);
    (void)data.WriteString("application/m3u8");
    (void)data.WriteInt32(-1);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 缺失fd被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为M3U8 fd URL但缺少查询参数
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub检测到查询参数缺失并返回MSERR_INVALID_VAL
*/
/**
 * @tc.name: SetMediaSource_M3U8QueryMissing_001
 * @tc.number: PlayerServiceStub_141
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE rejects m3u8 fd url without query params test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_M3U8QueryMissing_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，M3U8 fd URL缺少查询参数
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("fd://1234");
    (void)data.WriteUint32(0);
    (void)data.WriteString("application/m3u8");
    (void)data.WriteFileDescriptor(fd);

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 缺失查询参数被拒绝
    EXPECT_EQ(ret, MSERR_INVALID_VAL);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为合法http url源
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub解析url源并调度playerServer_->SetMediaSource，reply返回MSERR_OK
*/
/**
 * @tc.name: SetMediaSource_UrlSource_001
 * @tc.number: PlayerServiceStub_142
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE dispatches valid url source test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_UrlSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，url源为http
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x01);
    (void)data.WriteString("http://example.com/test.mp4");
    (void)data.WriteUint32(0);
    (void)data.WriteString("");
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 合法url源被调度
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_MEDIA_SOURCE消息为合法fd源
测试步骤: 通过OnRemoteRequest下发SET_MEDIA_SOURCE
预期结果: Stub解析fd源并调度playerServer_->SetMediaSource，reply返回MSERR_OK
*/
/**
 * @tc.name: SetMediaSource_FdSource_001
 * @tc.number: PlayerServiceStub_143
 * @tc.desc: OnRemoteRequest SET_MEDIA_SOURCE dispatches valid fd source test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_FdSource_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，fd源且fd合法
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint8(0x02);
    (void)data.WriteString("");
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(0);
    (void)data.WriteInt64(TEST_FD_SIZE);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteUint32(0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteDouble(0.0);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("");
    (void)data.WriteString("");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    EXPECT_CALL(*mockService, SetMediaSource(_, _)).WillOnce(Return(0));

    // When: 通过IPC消息调度SetMediaSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_MEDIA_SOURCE, data, reply, option);

    // Then: 合法fd源被调度
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回单个可seek区间
测试步骤: 通过OnRemoteRequest下发GET_SEEKABLE_RANGES
预期结果: Stub序列化区间start/end并返回MSERR_OK
*/
/**
 * @tc.name: GetSeekableRanges_NonEmpty_001
 * @tc.number: PlayerServiceStub_144
 * @tc.desc: OnRemoteRequest GET_SEEKABLE_RANGES serializes non-empty ranges test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetSeekableRanges_NonEmpty_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回单个区间
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    std::vector<Plugins::SeekRange> ranges;
    ranges.push_back({100, 2000});
    EXPECT_CALL(*mockService, GetSeekableRanges(_))
        .WillOnce(DoAll(SetArgReferee<0>(ranges), Return(0)));

    // When: 通过IPC消息调度GetSeekableRanges
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_SEEKABLE_RANGES, data, reply, option);

    // Then: 区间被正确序列化
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 1);
    EXPECT_EQ(reply.ReadInt64(), 100);
    EXPECT_EQ(reply.ReadInt64(), 2000);
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，Mock返回单个视频轨道
测试步骤: 通过OnRemoteRequest下发GET_VIDEO_TRACK_INFO
预期结果: Stub序列化轨道列表并返回MSERR_OK
*/
/**
 * @tc.name: GetVideoTrackInfo_NonEmpty_001
 * @tc.number: PlayerServiceStub_145
 * @tc.desc: OnRemoteRequest GET_VIDEO_TRACK_INFO serializes non-empty track list test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, GetVideoTrackInfo_NonEmpty_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，Mock返回单个轨道
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    std::vector<Format> tracks;
    tracks.emplace_back();
    EXPECT_CALL(*mockService, GetVideoTrackInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(tracks), Return(0)));

    // When: 通过IPC消息调度GetVideoTrackInfo
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::GET_VIDEO_TRACK_INFO, data, reply, option);

    // Then: 轨道列表被正确序列化
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 1);
    Format outFormat;
    EXPECT_TRUE(MediaParcel::Unmarshalling(reply, outFormat));
    EXPECT_EQ(reply.ReadInt32(), 0);
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，播放策略消息含具体字段值
测试步骤: 通过OnRemoteRequest下发SET_PLAYBACK_STRATEGY
预期结果: Stub解析出各字段并原样传给playerServer_
*/
/**
 * @tc.name: SetPlaybackStrategy_FieldCheck_001
 * @tc.number: PlayerServiceStub_146
 * @tc.desc: OnRemoteRequest SET_PLAYBACK_STRATEGY parses all fields test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetPlaybackStrategy_FieldCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，写入具体策略字段
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteUint32(1920);
    (void)data.WriteUint32(1080);
    (void)data.WriteUint32(500);
    (void)data.WriteDouble(1.0);
    (void)data.WriteDouble(0.5);
    (void)data.WriteBool(true);
    (void)data.WriteBool(true);
    (void)data.WriteBool(false);
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    (void)data.WriteString("en");
    (void)data.WriteString("zh");
    (void)data.WriteBool(false);
    (void)data.WriteInt32(0);
    AVPlayStrategy captured;
    EXPECT_CALL(*mockService, SetPlaybackStrategy(_))
        .WillOnce(DoAll(SaveArg<0>(&captured), Return(0)));

    // When: 通过IPC消息调度SetPlaybackStrategy
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_PLAYBACK_STRATEGY, data, reply, option);

    // Then: 各字段被正确解析
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_EQ(captured.preferredWidth, 1920U);
    EXPECT_EQ(captured.preferredHeight, 1080U);
    EXPECT_EQ(captured.preferredBufferDuration, 500U);
    EXPECT_DOUBLE_EQ(captured.preferredBufferDurationForPlaying, 1.0);
    EXPECT_DOUBLE_EQ(captured.thresholdForAutoQuickPlay, 0.5);
    EXPECT_TRUE(captured.preferredHdr);
    EXPECT_TRUE(captured.showFirstFrameOnPrepare);
    EXPECT_EQ(captured.preferredAudioLanguage, "en");
    EXPECT_EQ(captured.preferredSubtitleLanguage, "zh");
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，SET_FILE_PATH消息含fd与路径
测试步骤: 通过OnRemoteRequest下发SET_FILE_PATH
预期结果: Stub解析fd与路径并原样传给playerServer_
*/
/**
 * @tc.name: SetFilePath_FdCheck_001
 * @tc.number: PlayerServiceStub_147
 * @tc.desc: OnRemoteRequest SET_FILE_PATH parses fd and path test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, SetFilePath_FdCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，写入fd与路径
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteString("/data/test/file.mp4");
    int32_t capturedFd = -1;
    std::string capturedPath;
    EXPECT_CALL(*mockService, SetFilePath(_, _))
        .WillOnce(DoAll(SaveArg<0>(&capturedFd), SaveArg<1>(&capturedPath), Return(0)));

    // When: 通过IPC消息调度SetFilePath
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::SET_FILE_PATH, data, reply, option);

    // Then: fd与路径被正确解析
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_GE(capturedFd, 0);
    EXPECT_EQ(capturedPath, "/data/test/file.mp4");
}

/*
前置条件: 构造带MockIPlayerService的PlayerServiceStub，ADD_SUB_FD_SOURCE消息含fd/offset/size
测试步骤: 通过OnRemoteRequest下发ADD_SUB_FD_SOURCE
预期结果: Stub解析fd/offset/size并原样传给playerServer_
*/
/**
 * @tc.name: AddSubFdSource_FdCheck_001
 * @tc.number: PlayerServiceStub_148
 * @tc.desc: OnRemoteRequest ADD_SUB_FD_SOURCE parses fd/offset/size test.
 * @tc.Co-authored-by Agent
 */
HWTEST_F(PlayerServiceStubTest, AddSubFdSource_FdCheck_001, TestSize.Level0)
{
    // Given: 构造Stub与Mock，写入fd/offset/size
    auto mockService = std::make_shared<NiceMock<MockIPlayerService>>();
    sptr<PlayerServiceStub> stub = CreateStub(mockService);
    ASSERT_NE(stub, nullptr);
    int32_t fd = open("/dev/null", O_RDONLY);
    ASSERT_GE(fd, 0);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    PrepareParcel(data);
    (void)data.WriteFileDescriptor(fd);
    (void)data.WriteInt64(TEST_FD_OFFSET);
    (void)data.WriteInt64(TEST_FD_SIZE);
    int32_t capturedFd = -1;
    EXPECT_CALL(*mockService, AddSubSource(_, static_cast<int64_t>(TEST_FD_OFFSET), TEST_FD_SIZE))
        .WillOnce(DoAll(SaveArg<0>(&capturedFd), Return(0)));

    // When: 通过IPC消息调度AddSubSource
    int32_t ret = stub->OnRemoteRequest(IStandardPlayerService::ADD_SUB_FD_SOURCE, data, reply, option);

    // Then: fd被正确解析
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), 0);
    EXPECT_GE(capturedFd, 0);
}

} // namespace Media
} // namespace OHOS
