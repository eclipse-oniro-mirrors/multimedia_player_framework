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

#include "avcodec_info.h"
#include "media_errors.h"
#include "i_recorder_profiles_service.h"
#include "recorder_profiles_server_mock_unit_test.h"
#include "recorder.h"

using namespace std;
using namespace testing::ext;

constexpr int32_t DEFAULT_AUDIO_BIT_RATE = 96000;
constexpr int32_t DEFAULT_AUDIO_CHANNELS = 2;
constexpr int32_t DEFAULT_AUDIO_SAMPLE_RATE = 48000;

namespace OHOS {
namespace Media {
void RecorderProfilesServerMockUnitTest::SetUpTestCase(void) {}

void RecorderProfilesServerMockUnitTest::TearDownTestCase(void) {}

void RecorderProfilesServerMockUnitTest::SetUp(void)
{
    recorderProfilesInfoServer_ = std::make_shared<RecorderProfilesServer>();
}

void RecorderProfilesServerMockUnitTest::TearDown(void)
{
    recorderProfilesInfoServer_ = nullptr;
}

bool RecorderProfilesServerMockUnitTest::CheckAudioRecorderCapsArray(
    const std::vector<std::shared_ptr<AudioRecorderCaps>> &audioRecorderArray) const
{
    bool flagM4a = false;
    bool flagAAC = false;
    for (auto iter = audioRecorderArray.begin(); iter != audioRecorderArray.end(); iter++) {
        std::shared_ptr<AudioRecorderCaps> pAudioRecorderCaps = *iter;
        if ((pAudioRecorderCaps->containerFormatType.compare(ContainerFormatType::CFT_MPEG_4A) == 0)) {
            flagM4a = true;
        }
        if ((pAudioRecorderCaps->mimeType.compare(CodecMimeType::AUDIO_AAC) == 0)) {
            flagAAC = true;
            EXPECT_GE(pAudioRecorderCaps->bitrate.minVal, 0);
            EXPECT_GE(pAudioRecorderCaps->channels.minVal, 0);
            EXPECT_GE(pAudioRecorderCaps->sampleRate.size(), 0);
        }
    }
    return flagM4a && flagAAC;
}

bool RecorderProfilesServerMockUnitTest::CheckVideoRecorderCapsArray(
    const std::vector<std::shared_ptr<VideoRecorderCaps>> &videoRecorderArray) const
{
    bool flagMP4 = false;
    bool flagMP4A = false;
    bool flagMP4V = false;
    bool flagAVC = false;
    for (auto iter =  videoRecorderArray.begin(); iter !=  videoRecorderArray.end(); iter++) {
        std::shared_ptr< VideoRecorderCaps> pVideoRecorderCaps = *iter;
        if ((pVideoRecorderCaps->containerFormatType.compare(ContainerFormatType::CFT_MPEG_4) == 0)) {
            flagMP4 = true;
        }
        if ((pVideoRecorderCaps->audioEncoderMime.compare(CodecMimeType::AUDIO_AAC) == 0)) {
            flagMP4A = true;
        }
        if ((pVideoRecorderCaps->videoEncoderMime.compare(CodecMimeType::VIDEO_MPEG4) == 0)) {
            flagMP4V = true;
            EXPECT_GE(pVideoRecorderCaps->audioBitrateRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->audioChannelRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->videoBitrateRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->videoFramerateRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->videoWidthRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->videoHeightRange.minVal, 0);
            EXPECT_GE(pVideoRecorderCaps->audioSampleRates.size(), 0);
        }
        if ((pVideoRecorderCaps->videoEncoderMime.compare(CodecMimeType::VIDEO_AVC) == 0)) {
            flagAVC = true;
        }
    }
    return flagMP4 && flagMP4A && flagMP4V && flagAVC;
}

/**
 * @tc.name: recorder_profile_IsAudioRecorderConfigureSupported_0100
 * @tc.desc: recorde profile IsAudioRecorderConfigSupported
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_IsAudioRecorderConfigureSupported_0100, TestSize.Level0)
{
    RecorderProfilesData profilesDate;
    profilesDate.recorderProfile.containerFormatType = ContainerFormatType::CFT_MPEG_4;
    profilesDate.recorderProfile.audioCodec = CodecMimeType::AUDIO_AAC;
    profilesDate.recorderProfile.audioBitrate = DEFAULT_AUDIO_BIT_RATE;
    profilesDate.recorderProfile.audioSampleRate = DEFAULT_AUDIO_SAMPLE_RATE;
    profilesDate.recorderProfile.audioChannels = DEFAULT_AUDIO_CHANNELS;
    EXPECT_TRUE(recorderProfilesInfoServer_->IsAudioRecorderConfigSupported(profilesDate));
}

/**
 * @tc.name: recorder_profile_IsAudioRecorderConfigureSupported_0200
 * @tc.desc: recorde profile IsAudioRecorderConfigSupported when match the wrong audioChannels
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_IsAudioRecorderConfigureSupported_0200, TestSize.Level0)
{
    RecorderProfilesData profilesDate;
    profilesDate.recorderProfile.containerFormatType = ContainerFormatType::CFT_MPEG_4;
    profilesDate.recorderProfile.audioCodec = CodecMimeType::AUDIO_AAC;
    profilesDate.recorderProfile.audioBitrate = DEFAULT_AUDIO_BIT_RATE;
    profilesDate.recorderProfile.audioSampleRate = DEFAULT_AUDIO_SAMPLE_RATE;
    profilesDate.recorderProfile.audioChannels = -1; // Invalid channels
    EXPECT_FALSE(recorderProfilesInfoServer_->IsAudioRecorderConfigSupported(profilesDate));
    profilesDate.recorderProfile.audioBitrate = -1; // Invalid bitrate
    profilesDate.recorderProfile.audioChannels = DEFAULT_AUDIO_CHANNELS;
    EXPECT_FALSE(recorderProfilesInfoServer_->IsAudioRecorderConfigSupported(profilesDate));
    profilesDate.recorderProfile.audioBitrate = DEFAULT_AUDIO_BIT_RATE;
    profilesDate.recorderProfile.audioSampleRate = -1; // Invalid sample rate
    EXPECT_FALSE(recorderProfilesInfoServer_->IsAudioRecorderConfigSupported(profilesDate));
    profilesDate.recorderProfile.audioBitrate = -1; // Invalid bitrate
    profilesDate.recorderProfile.audioSampleRate = -1; // Invalid sample rate
    profilesDate.recorderProfile.audioChannels = -1; // Invalid channels
    EXPECT_FALSE(recorderProfilesInfoServer_->IsAudioRecorderConfigSupported(profilesDate));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfileInfo_0100
 * @tc.desc: recorde profile HasVideoRecorderProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_HasVideoRecorderProfileInfo_0100, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    EXPECT_TRUE(recorderProfilesInfoServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
    sourceId = 0;
    qualityLevel = RECORDER_QUALITY_HIGH;
    EXPECT_TRUE(recorderProfilesInfoServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfileInfo_0200
 * @tc.desc: recorde profile HasVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_HasVideoRecorderProfileInfo_0200, TestSize.Level0)
{
    int32_t sourceId = -1; // Invalid source id
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    EXPECT_FALSE(recorderProfilesInfoServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
    qualityLevel = RECORDER_QUALITY_LOW;
    EXPECT_FALSE(recorderProfilesInfoServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
    sourceId = 0;
    qualityLevel = -1; // Invalid quality Level
    EXPECT_FALSE(recorderProfilesInfoServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

/**
 * @tc.name: recorder_profile_GetAudioRecorderCapsInfo_0100
 * @tc.desc: recorde profile GetAudioRecorderCaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetAudioRecorderCapsInfo_0100, TestSize.Level0)
{
    std::vector<RecorderProfilesData> capabilityArray = recorderProfilesInfoServer_->GetAudioRecorderCapsInfo();
    std::vector<std::shared_ptr<AudioRecorderCaps>> audioRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<AudioRecorderCaps> audioRecorderCaps = std::make_shared<AudioRecorderCaps>((*iter).audioCaps);
        EXPECT_TRUE((*iter).mediaProfileType == RECORDER_TYPE_AUDIO_CAPS);
        audioRecorderCapsArray.push_back(audioRecorderCaps);
    }
    EXPECT_TRUE(CheckAudioRecorderCapsArray(audioRecorderCapsArray));
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderCapsInfo_0100
 * @tc.desc: recorde profile GetVideoRecorderCaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetVideoRecorderCapsInfo_0100, TestSize.Level0)
{
    std::vector<RecorderProfilesData> capabilityArray = recorderProfilesInfoServer_->GetVideoRecorderCapsInfo();
    std::vector<std::shared_ptr<VideoRecorderCaps>> videoRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<VideoRecorderCaps> videoRecorderCaps = std::make_shared<VideoRecorderCaps>((*iter).videoCaps);
        EXPECT_TRUE((*iter).mediaProfileType == RECORDER_TYPE_VIDEO_CAPS);
        videoRecorderCapsArray.push_back(videoRecorderCaps);
    }
    ASSERT_TRUE(videoRecorderCapsArray.size() != 0);
    CheckVideoRecorderCapsArray(videoRecorderCapsArray);
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfileInfo_0100
 * @tc.desc: recorde profile GetVideoRecorderProfileInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetVideoRecorderProfileInfo_0100, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    RecorderProfilesData capability = recorderProfilesInfoServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_EQ(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
    EXPECT_GE(videoRecorderProfile->audioBitrate, 0); // audio bitrate >= 0
    EXPECT_GE(videoRecorderProfile->audioChannels, 0); // audio channels >= 0
    EXPECT_EQ(CodecMimeType::AUDIO_AAC, videoRecorderProfile->audioCodec);
    EXPECT_GE(videoRecorderProfile->audioSampleRate, 0); // audio sampleRate >= 0
    EXPECT_GE(videoRecorderProfile->durationTime, 0); // duration time >= 0
    EXPECT_EQ(RECORDER_QUALITY_LOW, videoRecorderProfile->qualityLevel);
    EXPECT_GE(videoRecorderProfile->videoBitrate, 0); // video bitrate >= 0
    EXPECT_EQ(CodecMimeType::VIDEO_MPEG4, videoRecorderProfile->videoCodec);
    EXPECT_GE(videoRecorderProfile->videoFrameWidth, 0); // video frame width >= 0
    EXPECT_GE(videoRecorderProfile->videoFrameHeight, 0); // video frame height >= 0
    EXPECT_GE(videoRecorderProfile->videoFrameRate, 0); // video frame rate >= 0
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfileInfo_0200
 * @tc.desc: recorde profile GetVideoRecorderProfileInfo when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetVideoRecorderProfileInfo_0200, TestSize.Level0)
{
    int32_t sourceId = -1; // invalid source id
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    RecorderProfilesData capability = recorderProfilesInfoServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_NE(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfileInfo_0300
 * @tc.desc: recorde profile GetVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetVideoRecorderProfileInfo_0300, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    RecorderProfilesData capability = recorderProfilesInfoServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_EQ(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
    EXPECT_GE(videoRecorderProfile->audioBitrate, 0); // audio bitrate >= 0
    EXPECT_GE(videoRecorderProfile->audioChannels, 0); // audio channels >= 0
    EXPECT_GE(videoRecorderProfile->audioSampleRate, 0); // audio sampleRate >= 0
    EXPECT_GE(videoRecorderProfile->durationTime, 0); // duration time >= 0
    EXPECT_EQ(RECORDER_QUALITY_HIGH, videoRecorderProfile->qualityLevel);
    EXPECT_GE(videoRecorderProfile->videoBitrate, 0); // video bitrate >= 0
    EXPECT_GE(videoRecorderProfile->videoFrameWidth, 0); // video frame width >= 0
    EXPECT_GE(videoRecorderProfile->videoFrameHeight, 0); // video frame height >= 0
    EXPECT_GE(videoRecorderProfile->videoFrameRate, 0); // video frame rate >= 0
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfileInfo_0400
 * @tc.desc: recorde profile GetVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerMockUnitTest, recorder_profile_GetVideoRecorderProfileInfo_0400, TestSize.Level0)
{
    int32_t sourceId = -1;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    RecorderProfilesData capability = recorderProfilesInfoServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_NE(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
}
} // namespace Media
} // namespace OHOS