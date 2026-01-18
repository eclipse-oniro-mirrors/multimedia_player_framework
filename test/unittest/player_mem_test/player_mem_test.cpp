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

#include "player_server_mem_unit_test.h"
#include "media_errors.h"
#include "hiplayer_impl.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
const std::string MEDIA_ROOT = "/data/test/";
const std::string VIDEO_FILE1 = MEDIA_ROOT + "H264_AAC.mp4";


void PlayerServerMemUnitTest::SetUpTestCase(void)
{
}

void PlayerServerMemUnitTest::TearDownTestCase(void)
{
}

void PlayerServerMemUnitTest::SetUp(void)
{
    playerServerMem_ = std::make_shared<PlayerServerMem>();
}

void PlayerServerMemUnitTest::TearDown(void)
{
    playerServerMem_ = nullptr;
}

/**
 * @tc.name  : Test AudioHapticManager RegisterSource API
 * @tc.number: AudioHapticManager_RegisterSource_001
 * @tc.desc  : Test AudioHapticManager RegisterSource interface
 */
HWTEST_F(PlayerServerMemUnitTest, PlayerServerMem_RegisterSource_001, TestSize.Level1)
{
    EXPECT_NE(nullptr, playerServerMem_);
    sleep(1);
}

/**
* @tc.name    : Test SetSourceInternal API
* @tc.number  : SetSourceInternal_004
* @tc.desc    : Test SetSourceInternal interface, set sourceType to invalid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSourceInternal_004, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.sourceType = 100;  // Invalid value

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetSourceInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : AddSubSourceInternal_001
* @tc.number  : AddSubSourceInternal_001
* @tc.desc    : Test AddSubSourceInternal interface, set recoverConfig_.subUrl not empty.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, AddSubSourceInternal_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.subUrl.push_back("http://test.com");

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->AddSubSourceInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : AddSubSourceInternal_002
* @tc.number  : AddSubSourceInternal_002
* @tc.desc    : Test AddSubSourceInternal interface, set recoverConfig_.subFdSrc not empty.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, AddSubSourceInternal_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.subFdSrc.push_back({1, 0, 1024});

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->AddSubSourceInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);;
    sleep(1);
}

/**
* @tc.name    : SetConfigInternal_001
* @tc.number  : SetConfigInternal_001
* @tc.desc    : Test SetConfigInternal interface, set recoverConfig_.leftVolume and recoverConfig_.rightVolume not 1.0f.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetConfigInternal_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.leftVolume = 0.5f;
    playerServerMem_->recoverConfig_.rightVolume = 0.5f;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetConfigInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : SetConfigInternal_003
* @tc.number  : SetConfigInternal_003
* @tc.desc    : Test SetConfigInternal interface, set recoverConfig_.loop not false.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetConfigInternal_003, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.loop = true;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetConfigInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : SetConfigInternal_004
* @tc.number  : SetConfigInternal_004
* @tc.desc    : Test SetConfigInternal interface, set recoverConfig_.bitRate not 0.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetConfigInternal_004, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.bitRate = 1024;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetConfigInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test SetBehaviorInternal API
* @tc.number  : SetBehaviorInternal_001
* @tc.desc    : Test SetBehaviorInternal interface, set speedMode to SPEED_FORWARD_1_00_X.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetBehaviorInternal_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->recoverConfig_.currentTime = 0;
    playerServerMem_->recoverConfig_.audioIndex = 0;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetBehaviorInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetBehaviorInternal API
* @tc.number  : SetBehaviorInternal_002
* @tc.desc    : Test SetBehaviorInternal interface, set currentTime to a non-zero value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetBehaviorInternal_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->recoverConfig_.currentTime = 100;
    playerServerMem_->recoverConfig_.audioIndex = 0;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetBehaviorInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test SetBehaviorInternal API
* @tc.number  : SetBehaviorInternal_003
* @tc.desc    : Test SetBehaviorInternal interface, set audioIndex to a non-zero value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetBehaviorInternal_003, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->recoverConfig_.currentTime = 0;
    playerServerMem_->recoverConfig_.audioIndex = 1;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetBehaviorInternal();

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}

HWTEST_F(PlayerServerMemUnitTest, SetBehaviorInternal_004, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_IDLE;
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_25_X;
    EXPECT_EQ(playerServerMem_->SetBehaviorInternal(), MSERR_INVALID_OPERATION);
}

HWTEST_F(PlayerServerMemUnitTest, SetBehaviorInternal_005, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_IDLE;
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->recoverConfig_.currentTime  = 0;
    playerServerMem_->defaultAudioIndex_ = 1;
    EXPECT_EQ(playerServerMem_->SetBehaviorInternal(), MSERR_INVALID_OPERATION);
}

/**
* @tc.name    : Test NeedSelectAudioTrack API
* @tc.number  : NeedSelectAudioTrack_001
* @tc.desc    : Test NeedSelectAudioTrack interface, set audioIndex to a non-zero value and
*               defaultAudioIndex_ to a different value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, NeedSelectAudioTrack_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.audioIndex = 1;
    playerServerMem_->defaultAudioIndex_ = 0;

    // 2. Call the function to be tested
    bool result = playerServerMem_->NeedSelectAudioTrack();

    // 3. Verify the result
    EXPECT_TRUE(result);
    sleep(1);
}

/**
* @tc.name    : Test NeedSelectAudioTrack API
* @tc.number  : NeedSelectAudioTrack_002
* @tc.desc    : Test NeedSelectAudioTrack interface, set audioIndex to a non-zero value and
*               defaultAudioIndex_ to the same value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, NeedSelectAudioTrack_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.audioIndex = 1;
    playerServerMem_->defaultAudioIndex_ = 1;

    // 2. Call the function to be tested
    bool result = playerServerMem_->NeedSelectAudioTrack();

    // 3. Verify the result
    EXPECT_FALSE(result);
    sleep(1);
}

/**
* @tc.name    : Test NeedSelectAudioTrack API
* @tc.number  : NeedSelectAudioTrack_003
* @tc.desc    : Test NeedSelectAudioTrack interface, set audioIndex to a negative value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, NeedSelectAudioTrack_003, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.audioIndex = -1;
    playerServerMem_->defaultAudioIndex_ = 0;

    // 2. Call the function to be tested
    bool result = playerServerMem_->NeedSelectAudioTrack();

    // 3. Verify the result
    EXPECT_FALSE(result);
    sleep(1);
}


/**
* @tc.name    : Test SetSource API with URL
* @tc.number  : SetSource_001
* @tc.desc    : Test SetSource interface with URL, set url to a valid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSource_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "file://..";

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetSource(url);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test SetSource API with Invalid URL
* @tc.number  : SetSource_003
* @tc.desc    : Test SetSource interface with URL, set url to an invalid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSource_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "invalid_url";

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetSource(url);

    // 3. Verify the result
    EXPECT_NE(ret, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSource API with Empty URL
* @tc.number  : SetSource_004
* @tc.desc    : Test SetSource interface with URL, set url to an empty string.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSource_004, TestSize.Level0)
{
    // 1. Set up the test environment
    std::string url = "";

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->SetSource(url);

    // 3. Verify the result
    EXPECT_NE(ret, MSERR_OK);
    sleep(1);
}


/**
* @tc.name    : Test GetCurrentTime API
* @tc.number  : GetCurrentTime_001
* @tc.desc    : Test GetCurrentTime interface, get current time. isLocalResource_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTime_001, TestSize.Level0)
{
    // 1. Set up the test environment
    int32_t currentTime = 0;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetCurrentTime(currentTime);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test GetCurrentTime API
* @tc.number  : GetCurrentTime_002
* @tc.desc    : Test GetCurrentTime interface, get current time. isReleaseMemByManage_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTime_002, TestSize.Level0)
{
    // 1. Set up the test environment
    int32_t currentTime = 0;
    playerServerMem_->isLocalResource_ = true;
    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetCurrentTime(currentTime);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test GetCurrentTime API
* @tc.number  : GetCurrentTime_003
* @tc.desc    : Test GetCurrentTime interface, get current time.isReleaseMemByManage_ = isLocalResource_ = true
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTime_003, TestSize.Level0)
{
    // 1. Set up the test environment
    int32_t currentTime = 0;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetCurrentTime(currentTime);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoTrackInfo API
* @tc.number  : GetVideoTrackInfo_001
* @tc.desc    : Test GetVideoTrackInfo interface, get video track info. isLocalResource_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoTrackInfo_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> videoTrack;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetVideoTrackInfo(videoTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoTrackInfo API
* @tc.number  : GetVideoTrackInfo_002
* @tc.desc    : Test GetVideoTrackInfo interface, get video track info.isReleaseMemByManage_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoTrackInfo_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> videoTrack;
    playerServerMem_->isLocalResource_ = true;
    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetVideoTrackInfo(videoTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoTrackInfo API
* @tc.number  : GetVideoTrackInfo_003
* @tc.desc    : Test GetVideoTrackInfo interface, get video track info.isReleaseMemByManage_ = isLocalResource_ = true
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoTrackInfo_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> videoTrack;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetVideoTrackInfo(videoTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test GetAudioTrackInfo API
* @tc.number  : GetAudioTrackInfo_001
* @tc.desc    : Test GetAudioTrackInfo interface, get audio track info.isLocalResource_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetAudioTrackInfo_001, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> audioTrack;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetAudioTrackInfo(audioTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
    sleep(1);
}

/**
* @tc.name    : Test GetAudioTrackInfo API
* @tc.number  : GetAudioTrackInfo_002
* @tc.desc    : Test GetAudioTrackInfo interface, get audio track info.isReleaseMemByManage_ is false
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetAudioTrackInfo_002, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> audioTrack;
    playerServerMem_->isLocalResource_ = true;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetAudioTrackInfo(audioTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_NO_MEMORY);
    sleep(1);
}

/**
* @tc.name    : Test GetAudioTrackInfo API
* @tc.number  : GetAudioTrackInfo_003
* @tc.desc    : Test GetAudioTrackInfo interface, get audio track info.isReleaseMemByManage_ = isLocalResource_ = true
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetAudioTrackInfo_003, TestSize.Level0)
{
    // 1. Set up the test environment
    std::vector<Format> audioTrack;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetAudioTrackInfo(audioTrack);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_OK);
    sleep(1);
}


/**
* @tc.name    : Test GetVideoWidth API
* @tc.number  : GetVideoWidth_001
* @tc.desc    : Test GetVideoWidth interface, get video width.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoWidth_001, TestSize.Level0)
{
    // 1. Set up the test environment

    // 2. Call the function to be tested
    int32_t width = playerServerMem_->GetVideoWidth();

    // 3. Verify the result
    EXPECT_GT(width, 0);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoWidth API
* @tc.number  : GetVideoWidth_002
* @tc.desc    : Test GetVideoWidth interface, get video width.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoWidth_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    // 2. Call the function to be tested
    int32_t width = playerServerMem_->GetVideoWidth();

    // 3. Verify the result
    EXPECT_GT(width, 0);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoWidth API
* @tc.number  : GetVideoWidth_003
* @tc.desc    : Test GetVideoWidth interface, get video width.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoWidth_003, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    // 2. Call the function to be tested
    int32_t width = playerServerMem_->GetVideoWidth();

    // 3. Verify the result
    EXPECT_EQ(width, 0);
    sleep(1);
}

/**
* @tc.name    : Test GetVideoHeight API
* @tc.number  : GetVideoHeight_001
* @tc.desc    : Test GetVideoHeight interface, get video height.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetVideoHeight_001, TestSize.Level0)
{
    // 1. Set up the test environment

    // 2. Call the function to be tested
    int32_t height = playerServerMem_->GetVideoHeight();

    // 3. Verify the result
    EXPECT_GT(height, 0);
    sleep(1);
}

/**
* @tc.name    : Test GetDuration API
* @tc.number  : GetDuration_001
* @tc.desc    : Test GetDuration interface, get video duration.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, GetDuration_001, TestSize.Level0)
{
    // 1. Set up the test environment
    int32_t duration = 0;

    // 2. Call the function to be tested
    int32_t ret = playerServerMem_->GetDuration(duration);

    // 3. Verify the result
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    sleep(1);
}

/**
* @tc.name    : Test IsPlaying API
* @tc.number  : IsPlaying_001
* @tc.desc    : Test IsPlaying interface, set isLocalResource_ and isReleaseMemByManage_ to true.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, IsPlaying_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->recoverConfig_.isPlaying = true;

    // 2. Call the function to be tested
    bool result = playerServerMem_->IsPlaying();

    // 3. Verify the result
    EXPECT_TRUE(result);
    sleep(1);
}

/**
* @tc.name    : Test IsPlaying API
* @tc.number  : IsPlaying_002
* @tc.desc    : Test IsPlaying interface, set isLocalResource_ to true and isReleaseMemByManage_ to false.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, IsPlaying_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;

    // 2. Call the function to be tested
    bool result = playerServerMem_->IsPlaying();

    // 3. Verify the result
    EXPECT_FALSE(result);
    sleep(1);
}

/**
* @tc.name    : Test IsLooping API
* @tc.number  : IsLooping_001
* @tc.desc    : Test IsLooping interface, set isLocalResource_ and isReleaseMemByManage_ to true.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, IsLooping_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->recoverConfig_.loop = true;

    // 2. Call the function to be tested
    bool result = playerServerMem_->IsLooping();

    // 3. Verify the result
    EXPECT_TRUE(result);
    sleep(1);
}

/**
* @tc.name    : Test IsLooping API
* @tc.number  : IsLooping_002
* @tc.desc    : Test IsLooping interface, set isLocalResource_ to true and isReleaseMemByManage_ to false.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, IsLooping_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = false;

    // 2. Call the function to be tested
    bool result = playerServerMem_->IsLooping();

    // 3. Verify the result
    EXPECT_FALSE(result);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_001
* @tc.desc    : Test SetSaveParameter interface, set videoScaleType to valid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_001, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.videoScaleType = 1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_002
* @tc.desc    : Test SetSaveParameter interface, set videoScaleType to invalid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_002, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.videoScaleType = -1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_003
* @tc.desc    : Test SetSaveParameter interface, set contentType and streamUsage to valid values.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_003, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.contentType = 1;
    playerServerMem_->recoverConfig_.streamUsage = 1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);
;

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_004
* @tc.desc    : Test SetSaveParameter interface, set contentType or streamUsage to invalid values.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_004, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.contentType = -1;
    playerServerMem_->recoverConfig_.streamUsage = 1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_005
* @tc.desc    : Test SetSaveParameter interface, set interruptMode to valid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_005, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.interruptMode = 1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
}

/**
* @tc.name    : Test SetSaveParameter API
* @tc.number  : SetSaveParameter_006
* @tc.desc    : Test SetSaveParameter interface, set interruptMode to invalid value.
* @tc.require : issueI5NZAQ
*/
HWTEST_F(PlayerServerMemUnitTest, SetSaveParameter_006, TestSize.Level0)
{
    // 1. Set up the test environment
    playerServerMem_->recoverConfig_.interruptMode = -1;
    playerServerMem_->playerEngine_ = std::make_unique<HiPlayerImpl>(0, 0, 0, 0);

    // 2. Call the function to be tested
    int32_t result = playerServerMem_->SetSaveParameter();

    // 3. Verify the result
    EXPECT_EQ(result, MSERR_OK);
    sleep(1);
    sleep(1);
}

HWTEST_F(PlayerServerMemUnitTest, SetPlaybackSpeedInternal_001, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_IDLE;
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_25_X;
    EXPECT_EQ(playerServerMem_->SetPlaybackSpeedInternal(), MSERR_INVALID_OPERATION);
}

HWTEST_F(PlayerServerMemUnitTest, SetPlaybackSpeedInternal_002, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_IDLE;
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->defaultAudioIndex_ = 1;
    EXPECT_EQ(playerServerMem_->SetPlaybackSpeedInternal(), MSERR_INVALID_OPERATION);
}

HWTEST_F(PlayerServerMemUnitTest, SetPlaybackSpeedInternal_003, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_IDLE;
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->defaultAudioIndex_ = -1;
    EXPECT_EQ(playerServerMem_->SetPlaybackSpeedInternal(), MSERR_OK);
}

HWTEST_F(PlayerServerMemUnitTest, SetPlaybackSpeedInternal_004, TestSize.Level0)
{
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_00_X;
    playerServerMem_->defaultAudioIndex_ = 1;
    EXPECT_EQ(playerServerMem_->SetPlaybackSpeedInternal(), MSERR_INVALID_OPERATION);
}

// Scenario1: Test when trackType is MEDIA_TYPE_AUD, isLocalResource_ is true and isReleaseMemByManage_ is true.
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTrack_001, TestSize.Level0)
{
    int32_t trackType = Media::MediaType::MEDIA_TYPE_AUD;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->recoverConfig_.audioIndex = 1;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    ASSERT_EQ(result, MSERR_OK);
    ASSERT_EQ(index, 1);
}

// Scenario2: Test when trackType is MEDIA_TYPE_VID, isLocalResource_ is true and isReleaseMemByManage_ is true.
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTrack_002, TestSize.Level0)
{
    int32_t trackType = Media::MediaType::MEDIA_TYPE_VID;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->recoverConfig_.videoIndex = 2;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    ASSERT_EQ(result, MSERR_OK);
    ASSERT_EQ(index, 2);
}

// Scenario3: Test when trackType is MEDIA_TYPE_SUBTITLE, isLocalResource_ is true and isReleaseMemByManage_ is true.
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTrack_003, TestSize.Level0)
{
    int32_t trackType = Media::MediaType::MEDIA_TYPE_SUBTITLE;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    playerServerMem_->recoverConfig_.textIndex = 3;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    ASSERT_EQ(result, MSERR_OK);
    ASSERT_EQ(index, 3);
}

// Scenario4: Test when trackType is invalid, isLocalResource_ is true and isReleaseMemByManage_ is true.
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTrack_004, TestSize.Level0)
{
    int32_t trackType = 100;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = true;
    playerServerMem_->isReleaseMemByManage_ = true;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    ASSERT_EQ(result, MSERR_INVALID_OPERATION);
}

// Scenario5: Test when isLocalResource_ is false or isReleaseMemByManage_ is false.
HWTEST_F(PlayerServerMemUnitTest, GetCurrentTrack_005, TestSize.Level0)
{
    int32_t trackType = Media::MediaType::MEDIA_TYPE_AUD;
    int32_t index = -1;
    playerServerMem_->isLocalResource_ = false;
    playerServerMem_->isReleaseMemByManage_ = false;
    int32_t result = playerServerMem_->GetCurrentTrack(trackType, index);
    ASSERT_NE(result, MSERR_OK);
}

HWTEST_F(PlayerServerMemUnitTest, LocalResourceRelease_001, TestSize.Level0)
{
    playerServerMem_->isReleaseMemByManage_ = true;
    EXPECT_EQ(playerServerMem_->LocalResourceRelease(), MSERR_OK);
}

HWTEST_F(PlayerServerMemUnitTest, RecoverToInitialized_001, TestSize.Level0)
{
    playerServerMem_->RecoverToInitialized(INFO_TYPE_STATE_CHANGE, PLAYER_INITIALIZED);
    playerServerMem_->RecoverToInitialized(INFO_TYPE_STATE_CHANGE, PLAYER_IDLE);
    playerServerMem_->RecoverToInitialized(INFO_TYPE_EOS, PLAYER_INITIALIZED);
    EXPECT_EQ(playerServerMem_->isRecoverMemByUser_, false);
}

HWTEST_F(PlayerServerMemUnitTest, RecoverToPrepared_001, TestSize.Level0)
{
    playerServerMem_->defaultAudioIndex_ = 1;
    playerServerMem_->RecoverToPrepared(INFO_TYPE_TRACKCHANGE, 0);
    
    playerServerMem_->recoverConfig_.currentTime = 1;
    playerServerMem_->RecoverToPrepared(INFO_TYPE_SEEKDONE, 0);
    
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_25_X;
    playerServerMem_->RecoverToPrepared(INFO_TYPE_SPEEDDONE, 0);

    EXPECT_EQ(playerServerMem_->isRecoverMemByUser_, false);
}

HWTEST_F(PlayerServerMemUnitTest, RecoverToCompleted_001, TestSize.Level0)
{
    playerServerMem_->defaultAudioIndex_ = 1;
    playerServerMem_->RecoverToCompleted(INFO_TYPE_TRACKCHANGE, 0);
    
    playerServerMem_->RecoverToCompleted(INFO_TYPE_STATE_CHANGE, PLAYER_PREPARED);
    
    playerServerMem_->recoverConfig_.speedMode = SPEED_FORWARD_1_25_X;
    playerServerMem_->RecoverToCompleted(INFO_TYPE_SPEEDDONE, 0);

    playerServerMem_->RecoverToCompleted(INFO_TYPE_BUFFERING_UPDATE, 0);
    EXPECT_EQ(playerServerMem_->isRecoverMemByUser_, false);
}

HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_001, TestSize.Level0)
{
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_002, TestSize.Level0)
{
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_003, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->continueReset = 4;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 5);
}

HWTEST_F(PlayerServerMemUnitTest, ResetFrontGroundForMemManage_004, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->continueReset = 5;
    playerServerMem_->ResetFrontGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

HWTEST_F(PlayerServerMemUnitTest, ResetBackGroundForMemManage_001, TestSize.Level0)
{
    playerServerMem_->isAudioPlayer_ = true;
    playerServerMem_->ResetBackGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

HWTEST_F(PlayerServerMemUnitTest, ResetBackGroundForMemManage_002, TestSize.Level0)
{
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->lastOpStatus_ = PLAYER_STARTED;
    playerServerMem_->ResetBackGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

HWTEST_F(PlayerServerMemUnitTest, ResetBackGroundForMemManage_003, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->continueReset = 4; // 5 CONTINUE_RESET_MAX_NUM
    playerServerMem_->ResetBackGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 5);
}

HWTEST_F(PlayerServerMemUnitTest, ResetBackGroundForMemManage_004, TestSize.Level0)
{
    playerServerMem_->lastOpStatus_ = PLAYER_PREPARED;
    playerServerMem_->isAudioPlayer_ = false;
    playerServerMem_->continueReset = 5; // 5 CONTINUE_RESET_MAX_NUM
    playerServerMem_->ResetBackGroundForMemManage();
    EXPECT_EQ(playerServerMem_->continueReset, 0);
}

// Scenario1: Test when type is INFO_TYPE_DEFAULTTRACK and mediaType is MEDIA_TYPE_AUD.
HWTEST_F(PlayerServerMemUnitTest, GetDefaultTrack_001, TestSize.Level0)
{
    PlayerOnInfoType type = INFO_TYPE_DEFAULTTRACK;
    int32_t extra = 0;
    Format infoBody;
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_TYPE, 0); // 0 MEDIA_TYPE_AUD
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_INDEX, 1);
    playerServerMem_->GetDefaultTrack(type, extra, infoBody);
    EXPECT_EQ(playerServerMem_->defaultAudioIndex_, 1);
}

// Scenario2: Test when type is not INFO_TYPE_DEFAULTTRACK.
HWTEST_F(PlayerServerMemUnitTest, GetDefaultTrack_002, TestSize.Level0)
{
    PlayerOnInfoType type = INFO_TYPE_EOS;
    int32_t extra = 0;
    Format infoBody;
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_TYPE, 0); // 0 MEDIA_TYPE_AUD
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_INDEX, 1);
    playerServerMem_->GetDefaultTrack(type, extra, infoBody);
    EXPECT_NE(playerServerMem_->defaultAudioIndex_, 1);
}

// Scenario3: Test when mediaType is not MEDIA_TYPE_AUD.
HWTEST_F(PlayerServerMemUnitTest, GetDefaultTrack_003, TestSize.Level0)
{
    PlayerOnInfoType type = INFO_TYPE_DEFAULTTRACK;
    int32_t extra = 0;
    Format infoBody;
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_TYPE, 1); // 1 MEDIA_TYPE_VID
    infoBody.PutIntValue(PlayerKeys::PLAYER_TRACK_INDEX, 1);
    playerServerMem_->GetDefaultTrack(type, extra, infoBody);
    EXPECT_NE(playerServerMem_->defaultAudioIndex_, 1);
}
} // namespace Media
} // namespace OHOS