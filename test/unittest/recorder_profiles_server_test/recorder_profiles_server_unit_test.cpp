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

#include "recorder_profiles_server_unit_test.h"
#include "avcodec_info.h"
#include "recorder.h"
#include "media_errors.h"
#include "i_recorder_profiles_service.h"

using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace Media {
void RecorderProfilesServerUnitTest::SetUpTestCase(void) {}
void RecorderProfilesServerUnitTest::TearDownTestCase(void) {}

void RecorderProfilesServerUnitTest::SetUp(void)
{
    recorderProfilesServer_ = std::make_shared<RecorderProfilesServer>();
}

void RecorderProfilesServerUnitTest::TearDown(void)
{
    recorderProfilesServer_ = nullptr;
}

/**
 * @tc.name: recorder_profile_IsAudioRecorderConfigSupported_0100
 * @tc.desc: recorde profile IsAudioRecorderConfigSupported
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_IsAudioRecorderConfigSupported_0100, TestSize.Level0)
{
    RecorderProfilesData profileDate;
    profileDate.recorderProfile.containerFormatType = ContainerFormatType::CFT_MPEG_4;
    profileDate.recorderProfile.audioCodec = CodecMimeType::AUDIO_AAC;
    profileDate.recorderProfile.audioBitrate = 96000; // 96000 common bitrate
    profileDate.recorderProfile.audioSampleRate = 48000; // 48000 common sample rate
    profileDate.recorderProfile.audioChannels = 2; // 2 common channels
    EXPECT_TRUE(recorderProfilesServer_->IsAudioRecorderConfigSupported(profileDate));
}

/**
 * @tc.name: recorder_profile_IsAudioRecorderConfigSupported_0200
 * @tc.desc: recorde profile IsAudioRecorderConfigSupported when match the wrong audioChannels
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_IsAudioRecorderConfigSupported_0200, TestSize.Level0)
{
    RecorderProfilesData profileDate;
    profileDate.recorderProfile.containerFormatType = ContainerFormatType::CFT_MPEG_4;
    profileDate.recorderProfile.audioCodec = CodecMimeType::AUDIO_AAC;
    profileDate.recorderProfile.audioBitrate = 96000; // 96000 common bitrate
    profileDate.recorderProfile.audioSampleRate = 48000; // 48000 common sample rate
    profileDate.recorderProfile.audioChannels = -1; // the wrong channels
    EXPECT_FALSE(recorderProfilesServer_->IsAudioRecorderConfigSupported(profileDate));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfile_0100
 * @tc.desc: recorde profile HasVideoRecorderProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_HasVideoRecorderProfile_0100, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    EXPECT_TRUE(recorderProfilesServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfile_0200
 * @tc.desc: recorde profile HasVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_HasVideoRecorderProfile_0200, TestSize.Level0)
{
    int32_t sourceId = -1;
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    EXPECT_FALSE(recorderProfilesServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfile_0300
 * @tc.desc: recorde profile HasVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_HasVideoRecorderProfile_0300, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    EXPECT_TRUE(recorderProfilesServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

/**
 * @tc.name: recorder_profile_HasVideoRecorderProfile_0400
 * @tc.desc: recorde profile HasVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_HasVideoRecorderProfile_0400, TestSize.Level0)
{
    int32_t sourceId = -1;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    EXPECT_FALSE(recorderProfilesServer_->HasVideoRecorderProfile(sourceId, qualityLevel));
}

bool RecorderProfilesServerUnitTest::CheckAudioRecorderCapsArray(
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

bool RecorderProfilesServerUnitTest::CheckVideoRecorderCapsArray(
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
 * @tc.name: recorder_profile_GetAudioRecorderCaps_0100
 * @tc.desc: recorde profile GetAudioRecorderCaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetAudioRecorderCaps_0100, TestSize.Level0)
{
    std::vector<RecorderProfilesData> capabilityArray = recorderProfilesServer_->GetAudioRecorderCapsInfo();
    std::vector<std::shared_ptr<AudioRecorderCaps>> audioRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<AudioRecorderCaps> audioRecorderCaps = std::make_shared<AudioRecorderCaps>((*iter).audioCaps);
        audioRecorderCapsArray.push_back(audioRecorderCaps);
    }
    EXPECT_TRUE(CheckAudioRecorderCapsArray(audioRecorderCapsArray));
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderCaps_0100
 * @tc.desc: recorde profile GetVideoRecorderCaps
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetVideoRecorderCaps_0100, TestSize.Level0)
{
    std::vector<RecorderProfilesData> capabilityArray = recorderProfilesServer_->GetVideoRecorderCapsInfo();
    std::vector<std::shared_ptr<VideoRecorderCaps>> videoRecorderCapsArray;
    for (auto iter = capabilityArray.begin(); iter != capabilityArray.end(); iter++) {
        std::shared_ptr<VideoRecorderCaps> videoRecorderCaps = std::make_shared<VideoRecorderCaps>((*iter).videoCaps);
        videoRecorderCapsArray.push_back(videoRecorderCaps);
    }
    ASSERT_TRUE(videoRecorderCapsArray.size() != 0);
    CheckVideoRecorderCapsArray(videoRecorderCapsArray);
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfile_0100
 * @tc.desc: recorde profile GetVideoRecorderProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetVideoRecorderProfile_0100, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    RecorderProfilesData capability = recorderProfilesServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_EQ(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
    EXPECT_EQ(96000, videoRecorderProfile->audioBitrate); // 96000 expect audio bitrate
    EXPECT_EQ(2, videoRecorderProfile->audioChannels); // 2 expect channels
    EXPECT_EQ(CodecMimeType::AUDIO_AAC, videoRecorderProfile->audioCodec);
    EXPECT_EQ(48000, videoRecorderProfile->audioSampleRate); // 48000 expect sample rate
    EXPECT_EQ(30, videoRecorderProfile->durationTime); // 30 expect duration time
    EXPECT_EQ(RECORDER_QUALITY_LOW, videoRecorderProfile->qualityLevel);
    EXPECT_EQ(192000, videoRecorderProfile->videoBitrate); // 192000 expect video bitrate
    EXPECT_EQ(CodecMimeType::VIDEO_MPEG4, videoRecorderProfile->videoCodec);
    EXPECT_EQ(176, videoRecorderProfile->videoFrameWidth); // 176 expect width
    EXPECT_EQ(144, videoRecorderProfile->videoFrameHeight); // 144 expect height
    EXPECT_EQ(30, videoRecorderProfile->videoFrameRate); // 30 expect frame rate
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfile_0200
 * @tc.desc: recorde profile GetVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetVideoRecorderProfile_0200, TestSize.Level0)
{
    int32_t sourceId = -1;
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    RecorderProfilesData capability = recorderProfilesServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_NE(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfile_0300
 * @tc.desc: recorde profile GetVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetVideoRecorderProfile_0300, TestSize.Level0)
{
    int32_t sourceId = 0;
    int32_t qualityLevel = RECORDER_QUALITY_HIGH;
    RecorderProfilesData capability = recorderProfilesServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_EQ(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
}

/**
 * @tc.name: recorder_profile_GetVideoRecorderProfile_0400
 * @tc.desc: recorde profile GetVideoRecorderProfile when match the wrong sourceId and qualityLevel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderProfilesServerUnitTest, recorder_profile_GetVideoRecorderProfile_0400, TestSize.Level0)
{
    int32_t sourceId = -1;
    int32_t qualityLevel = RECORDER_QUALITY_LOW;
    RecorderProfilesData capability = recorderProfilesServer_->GetVideoRecorderProfileInfo(sourceId, qualityLevel);
    std::shared_ptr<VideoRecorderProfile> videoRecorderProfile =
        std::make_shared<VideoRecorderProfile>(capability.recorderProfile);
    ASSERT_TRUE(videoRecorderProfile != nullptr);
    EXPECT_NE(ContainerFormatType::CFT_MPEG_4, videoRecorderProfile->containerFormatType);
}
} // namespace Media
} // namespace OHOS