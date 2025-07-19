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

#include "player_service_stub_test.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void PlayerServiceStubTest::SetUpTestCase(void)
{
}

void PlayerServiceStubTest::TearDownTestCase(void)
{
}

void PlayerServiceStubTest::SetUp(void)
{
}

void PlayerServiceStubTest::TearDown(void)
{
}

/**
 * @tc.name  : ~PlayerServiceStub
 * @tc.number: ~PlayerServiceStub
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, CreateReleaseStubObject, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);
    playerServiceStub->playerServer_ = nullptr;
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : DestoyServiceStub
 * @tc.number: DestoyServiceStub
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, DestoyServiceStub, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);
    playerServiceStub->playerServer_ = nullptr;
    int ret = playerServiceStub->DestroyStub();
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : DoIpcRecovery
 * @tc.number: DoIpcRecovery
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, DoIpcRecovery, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);
    int ret = playerServiceStub->DoIpcRecovery(true);
    EXPECT_EQ(ret, 0);
    ret = playerServiceStub->DoIpcRecovery(false);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : SetMediaSource_001
 * @tc.number: SetMediaSource_001
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_001, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string url = "fd://abc?d";
    data.WriteString(url);
    auto headerSize = 0;
    data.WriteUint32(headerSize);
    std::string mimeType = "application/m3u8";
    data.WriteString(mimeType);

    int ret = playerServiceStub->SetMediaSource(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : SetMediaSource_002
 * @tc.number: SetMediaSource_002
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_002, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string url = "abc?d";
    data.WriteString(url);
    auto headerSize = 0;
    data.WriteUint32(headerSize);
    std::string mimeType = "application/m3u8";
    data.WriteString(mimeType);

    int ret = playerServiceStub->SetMediaSource(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : SetMediaSource_003
 * @tc.number: SetMediaSource_003
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_003, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string url = "fd://abc";
    data.WriteString(url);
    auto headerSize = 0;
    data.WriteUint32(headerSize);
    std::string mimeType = "application/m3u8";
    data.WriteString(mimeType);

    int ret = playerServiceStub->SetMediaSource(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : SetMediaSource_004
 * @tc.number: SetMediaSource_004
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_004, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    std::string url = "fd://abc";
    data.WriteString(url);
    auto headerSize = 0;
    data.WriteUint32(headerSize);
    std::string mimeType = "application";
    data.WriteString(mimeType);

    int ret = playerServiceStub->SetMediaSource(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : SetMediaSource_005
 * @tc.number: SetMediaSource_005
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, SetMediaSource_005, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    EXPECT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    std::string url = "fd://abc";
    data.WriteString(url);
    auto headerSize = 0;
    data.WriteUint32(headerSize);
    std::string mimeType = "application";
    data.WriteString(mimeType);
    data.WriteUint32(11);

    int ret = playerServiceStub->SetMediaSource(data, reply);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : Freeze_001
 * @tc.number: Freeze_001
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, Freeze_001, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);

    int ret = playerServiceStub->Freeze();
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : UnFreeze_001
 * @tc.number: UnFreeze_001
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, UnFreeze_001, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);

    playerServiceStub->isFrozen_ = true;
    int ret = playerServiceStub->UnFreeze();
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : EnableReportAudioInterrupt_001
 * @tc.number: EnableReportAudioInterrupt_001
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, EnableReportAudioInterrupt_001, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteBool(true);

    int ret = playerServiceStub->EnableReportAudioInterrupt(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : EnableReportAudioInterrupt_002
 * @tc.number: EnableReportAudioInterrupt_002
 * @tc.desc  : FUNC
 */
HWTEST_F(PlayerServiceStubTest, EnableReportAudioInterrupt_002, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteBool(false);

    int ret = playerServiceStub->EnableReportAudioInterrupt(data, reply);
    EXPECT_EQ(ret, 0);
    playerServiceStub = nullptr;
}
}
}