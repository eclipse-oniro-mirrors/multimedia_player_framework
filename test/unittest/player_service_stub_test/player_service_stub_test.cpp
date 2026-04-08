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
#include "player_service_proxy.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t TEST_MAX_VIDEO_BITRATE = 8000;
constexpr int32_t TEST_MIN_VIDEO_BITRATE = 1000;
constexpr int32_t TEST_MAX_VIDEO_FRAME_RATE = 60;
constexpr int32_t TEST_MIN_VIDEO_FRAME_RATE = 24;
constexpr int32_t TEST_MAX_VIDEO_WIDTH = 1920;
constexpr int32_t TEST_MAX_VIDEO_HEIGHT = 1080;
constexpr int32_t TEST_MIN_VIDEO_WIDTH = 640;
constexpr int32_t TEST_MIN_VIDEO_HEIGHT = 360;
constexpr int32_t TEST_MAX_AUDIO_BITRATE = 320;
constexpr int32_t TEST_MIN_AUDIO_BITRATE = 64;
constexpr int32_t TEST_MAX_AUDIO_CHANNELS = 2;

AVPlayTrackSelectionFilter CreateTrackSelectionFilter()
{
    AVPlayTrackSelectionFilter filter;
    filter.maxVideoBitrate = TEST_MAX_VIDEO_BITRATE;
    filter.minVideoBitrate = TEST_MIN_VIDEO_BITRATE;
    filter.maxVideoFrameRate = TEST_MAX_VIDEO_FRAME_RATE;
    filter.minVideoFrameRate = TEST_MIN_VIDEO_FRAME_RATE;
    filter.maxVideoResolution = std::make_pair(TEST_MAX_VIDEO_WIDTH, TEST_MAX_VIDEO_HEIGHT);
    filter.minVideoResolution = std::make_pair(TEST_MIN_VIDEO_WIDTH, TEST_MIN_VIDEO_HEIGHT);
    filter.maxAudioBitrate = TEST_MAX_AUDIO_BITRATE;
    filter.minAudioBitrate = TEST_MIN_AUDIO_BITRATE;
    filter.maxAudioChannels = TEST_MAX_AUDIO_CHANNELS;
    filter.preferredVideoMimeTypes = { "video/avc", "video/hevc" };
    filter.preferredAudioMimeTypes = { "audio/aac", "audio/flac" };
    filter.preferredAudioLanguages = { "zh-CN", "en-US" };
    filter.preferredSubtitleLanguages = { "zh-CN", "en-US" };
    return filter;
}

bool IsSameTrackSelectionFilter(const AVPlayTrackSelectionFilter &lhs, const AVPlayTrackSelectionFilter &rhs)
{
    return lhs.maxVideoBitrate == rhs.maxVideoBitrate && lhs.minVideoBitrate == rhs.minVideoBitrate &&
        lhs.maxVideoFrameRate == rhs.maxVideoFrameRate && lhs.minVideoFrameRate == rhs.minVideoFrameRate &&
        lhs.maxVideoResolution == rhs.maxVideoResolution && lhs.minVideoResolution == rhs.minVideoResolution &&
        lhs.maxAudioBitrate == rhs.maxAudioBitrate && lhs.minAudioBitrate == rhs.minAudioBitrate &&
        lhs.maxAudioChannels == rhs.maxAudioChannels &&
        lhs.preferredVideoMimeTypes == rhs.preferredVideoMimeTypes &&
        lhs.preferredAudioMimeTypes == rhs.preferredAudioMimeTypes &&
        lhs.preferredAudioLanguages == rhs.preferredAudioLanguages &&
        lhs.preferredSubtitleLanguages == rhs.preferredSubtitleLanguages;
}

}

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

/**
 * @tc.name  : SetTrackSelectionFilter_006
 * @tc.number: SetTrackSelectionFilter_006
 * @tc.desc  : Test stub SetTrackSelectionFilter parcel read path.
 */
HWTEST_F(PlayerServiceStubTest, SetTrackSelectionFilter_006, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);
    AVPlayTrackSelectionFilter inputFilter = CreateTrackSelectionFilter();
    MessageParcel data;
    MessageParcel reply;
    playerServiceStub->WriteTrackSelectionFilter(data, inputFilter);
    EXPECT_EQ(playerServiceStub->SetTrackSelectionFilter(data, reply), MSERR_OK);
    AVPlayTrackSelectionFilter outputFilter;
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    EXPECT_EQ(playerServiceStub->GetTrackSelectionFilter(outputFilter), MSERR_OK);
    EXPECT_TRUE(IsSameTrackSelectionFilter(outputFilter, inputFilter));
    playerServiceStub->playerServer_ = nullptr;
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : GetTrackSelectionFilter_002
 * @tc.number: GetTrackSelectionFilter_002
 * @tc.desc  : Test stub GetTrackSelectionFilter parcel write path.
 */
HWTEST_F(PlayerServiceStubTest, GetTrackSelectionFilter_002, TestSize.Level1)
{
    sptr<PlayerServiceStub> playerServiceStub = PlayerServiceStub::Create();
    ASSERT_NE(playerServiceStub, nullptr);
    AVPlayTrackSelectionFilter inputFilter = CreateTrackSelectionFilter();
    EXPECT_EQ(playerServiceStub->SetTrackSelectionFilter(inputFilter), MSERR_OK);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(playerServiceStub->GetTrackSelectionFilter(data, reply), MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    AVPlayTrackSelectionFilter outputFilter;
    playerServiceStub->ReadTrackSelectionFilter(reply, outputFilter);
    EXPECT_TRUE(IsSameTrackSelectionFilter(outputFilter, inputFilter));
    playerServiceStub->playerServer_ = nullptr;
    playerServiceStub = nullptr;
}

/**
 * @tc.name  : TrackSelectionFilterProxy_001
 * @tc.number: TrackSelectionFilterProxy_001
 * @tc.desc  : Test proxy Set/GetTrackSelectionFilter path.
 */
HWTEST_F(PlayerServiceStubTest, TrackSelectionFilterProxy_001, TestSize.Level1)
{
    sptr<PlayerServiceProxy> proxy = new(std::nothrow) PlayerServiceProxy(nullptr);
    ASSERT_NE(proxy, nullptr);
    AVPlayTrackSelectionFilter inputFilter = CreateTrackSelectionFilter();
    EXPECT_EQ(proxy->SetTrackSelectionFilter(inputFilter), MSERR_INVALID_OPERATION);
    AVPlayTrackSelectionFilter outputFilter;
    EXPECT_EQ(proxy->GetTrackSelectionFilter(outputFilter), MSERR_INVALID_OPERATION);
    MessageParcel reply;
    proxy->WriteTrackSelectionFilter(reply, inputFilter);
    proxy->ReadTrackSelectionFilter(reply, outputFilter);
    EXPECT_TRUE(IsSameTrackSelectionFilter(outputFilter, inputFilter));
}
}
}