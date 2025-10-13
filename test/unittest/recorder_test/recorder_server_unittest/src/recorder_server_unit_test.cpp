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

#include "recorder_server_unit_test.h"
#include <fcntl.h>
#include <nativetoken_kit.h>
#include <token_setproc.h>
#include <accesstoken_kit.h>
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::RecorderTestParam;
using namespace Security::AccessToken;
namespace OHOS {
namespace Media {
// config for video to request buffer from surface
static VideoRecorderConfig g_videoRecorderConfig;

// HapParams for permission
static HapInfoParams hapInfo = {
    .userID = 100, // 100 user ID
    .bundleName = "com.ohos.test.recordertdd",
    .instIndex = 0, // 0 index
    .appIDDesc = "com.ohos.test.recordertdd",
    .isSystemApp = true
};

static HapPolicyParams hapPolicy = {
    .apl = APL_SYSTEM_BASIC,
    .domain = "test.avrecorder",
    .permList = { },
    .permStateList = {
        {
            .permissionName = "ohos.permission.MICROPHONE",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.READ_MEDIA",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.WRITE_MEDIA",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.KEEP_BACKGROUND_RUNNING",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        },
        {
            .permissionName = "ohos.permission.DUMP",
            .isGeneral = true,
            .resDeviceID = { "local" },
            .grantStatus = { PermissionState::PERMISSION_GRANTED },
            .grantFlags = { 1 }
        }
    }
};

void RecorderServerUnitTest::SetUpTestCase(void)
{
    SetSelfTokenPremission();
}

void RecorderServerUnitTest::TearDownTestCase(void) {}

void RecorderServerUnitTest::SetUp(void)
{
    recorderServer_ = std::make_shared<RecorderServerMock>();
    ASSERT_NE(nullptr, recorderServer_);
    ASSERT_TRUE(recorderServer_->CreateRecorder());
}

void RecorderServerUnitTest::TearDown(void)
{
    if (recorderServer_ != nullptr) {
        recorderServer_->Release();
    }
}

void RecorderServerUnitTest::SetSelfTokenPremission()
{
    AccessTokenIDEx tokenIdEx = { 0 };
    tokenIdEx = AccessTokenKit::AllocHapToken(hapInfo, hapPolicy);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}


/**
 * @tc.name: recorder_GetCurrentCapturerChangeInfo_001
 * @tc.desc: recorder_GetCurrentCapturerChangeInfo_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetCurrentCapturerChangeInfo_001, TestSize.Level0)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
    "recorder_GetCurrentCapturerChangeInfo_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    AudioRecorderChangeInfo changeInfo;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetCurrentCapturerChangeInfo(changeInfo));
    ASSERT_TRUE(changeInfo.capturerInfo.sourceType == g_videoRecorderConfig.aSource);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetLocation_001
 * @tc.desc: record video with setLocation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetLocation_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetLocation_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    recorderServer_->SetLocation(1, 1);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Repeat_001
 * @tc.desc: record video with Repeat
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Repeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_Repeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetFileSplitDuration_001
 * @tc.desc: record video with SetFileSplitDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetFileSplitDuration_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetFileSplitDuration_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioEncoder_Error_001
 * @tc.desc: record video with SetAudioEncoder
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioEncoder_Error_001, TestSize.Level2)
{
    g_videoRecorderConfig.audioSourceId = 0;
    g_videoRecorderConfig.audioFormat = AUDIO_DEFAULT;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAudioEncoder(g_videoRecorderConfig.audioSourceId, g_videoRecorderConfig.audioFormat));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAacProfile_Error_001
 * @tc.desc: record audio with SetAacProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAacProfile_Error_001, TestSize.Level2)
{
    g_videoRecorderConfig.audioSourceId = 0;
    g_videoRecorderConfig.aacProfile = AacProfile::AAC_LC;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAidopAacProfile(g_videoRecorderConfig.audioSourceId, g_videoRecorderConfig.aacProfile));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAacProfile_Error_002
 * @tc.desc: record audio with SetAacProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAacProfile_Error_002, TestSize.Level2)
{
    g_videoRecorderConfig.audioSourceId = 0;
    g_videoRecorderConfig.aacProfile = AacProfile::AAC_HE;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAidopAacProfile(g_videoRecorderConfig.audioSourceId, g_videoRecorderConfig.aacProfile));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAacProfile_Error_003
 * @tc.desc: record audio with SetAacProfile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAacProfile_Error_003, TestSize.Level2)
{
    g_videoRecorderConfig.audioSourceId = 0;
    g_videoRecorderConfig.aacProfile = AacProfile::AAC_HE_V2;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAidopAacProfile(g_videoRecorderConfig.audioSourceId, g_videoRecorderConfig.aacProfile));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetSurface_Error_001
 * @tc.desc: record video with GetSurface
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetSurface_Error_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_GetSurface_Error_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetSurface(2);
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSourceRepeat_001
 * @tc.desc: record video with SetFileSplitDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSourceRepeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetVideoSourceRepeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    int32_t videoSourceIdTwo = 0;
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoSource(VIDEO_SOURCE_SURFACE_ES, videoSourceIdTwo));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioSourceRepeat_001
 * @tc.desc: record video with SetFileSplitDuration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioSourceRepeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.aSource = AUDIO_SOURCE_DEFAULT;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
            "recorder_video_SetAudioSourceRepeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    int32_t audioSourceIdTwo = 0;
    EXPECT_NE(MSERR_OK, recorderServer_->SetAudioSource(AUDIO_SOURCE_DEFAULT, audioSourceIdTwo));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_DrainBufferTrue_001
 * @tc.desc: record video with DrainBufferTrue, stop true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_DrainBufferTrue_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_DrainBufferTrue_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(true));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSourceRGBA_001
 * @tc.desc: record video with SetVideoSourceRGBA
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSourceRGBA_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_RGBA;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetVideoSourceRGBA_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_DrainBufferStarted_001
 * @tc.desc: record video with DrainBufferStarted, stop after pause
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_DrainBufferStarted_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_DrainBufferStarted_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_001
 * @tc.desc: record with sampleRate -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.sampleRate = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_002
 * @tc.desc: record with channelCount -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_002, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.channelCount = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_003
 * @tc.desc: record with audioEncodingBitRate -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_003, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.audioEncodingBitRate = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_004
 * @tc.desc: record with videoFormat VIDEO_CODEC_FORMAT_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_004, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = VIDEO_CODEC_FORMAT_BUTT;
    videoRecorderConfig.audioEncodingBitRate = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_005
 * @tc.desc: record with width -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_005, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.width = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_006
 * @tc.desc: record with height -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_006, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.height = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_007
 * @tc.desc: record with frameRate -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_007, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.frameRate = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_008
 * @tc.desc: record with videoEncodingBitRate -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_008, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.videoEncodingBitRate = -1;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_009
 * @tc.desc: record with videoFormat VIDEO_CODEC_FORMAT_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_009, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = VIDEO_CODEC_FORMAT_BUTT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_010
 * @tc.desc: record with videoFormat VIDEO_CODEC_FORMAT_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_010, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_error.mp4").c_str(), O_RDWR);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_011
 * @tc.desc: record with videoFormat FORMAT_BUTT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_011, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_BUTT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);

    EXPECT_NE(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_012
 * @tc.desc: record with videoFormat FORMAT_DEFAULT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_012, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.enableBFrame = false;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_013
 * @tc.desc: record
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_013, TestSize.Level2)
{
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());

    EXPECT_NE(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_NE(MSERR_OK, recorderServer_->Pause());
    EXPECT_NE(MSERR_OK, recorderServer_->Resume());
    EXPECT_NE(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
}

/**
 * @tc.name: recorder_configure_014
 * @tc.desc: record with enableBFrame and enableTemporalScale true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_014, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.enableTemporalScale = true;
    videoRecorderConfig.enableBFrame = true;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_015
 * @tc.desc: record with audioCodec mp3 + fileFormat mp3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_015, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_MPEG;
    videoRecorderConfig.outPutFormat = FORMAT_MP3;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_015.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_016
 * @tc.desc: record with audioCodec mp3 + fileFormat mp4
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_016, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_MPEG;
    videoRecorderConfig.outPutFormat = FORMAT_MPEG_4;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_016.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_017
 * @tc.desc: record with audioCodec mp3 + fileFormat m4a
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_017, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_MPEG;
    videoRecorderConfig.outPutFormat = FORMAT_M4A;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_017.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_NE(MSERR_OK, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_018
 * @tc.desc: record mp3 with samplerate 64000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_018, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_MPEG;
    videoRecorderConfig.outPutFormat = FORMAT_MP3;
    videoRecorderConfig.sampleRate = 64000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_018.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_019
 * @tc.desc: record wav with samplerate 64000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_019, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_G711MU;
    videoRecorderConfig.outPutFormat = FORMAT_WAV;
    videoRecorderConfig.audioEncodingBitRate = 64000;
    videoRecorderConfig.channelCount = 1;
    videoRecorderConfig.sampleRate = 64000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_019.wav").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_020
 * @tc.desc: record wav with BitRate 128000
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_020, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_G711MU;
    videoRecorderConfig.outPutFormat = FORMAT_WAV;
    videoRecorderConfig.audioEncodingBitRate = 128000;
    videoRecorderConfig.channelCount = 1;
    videoRecorderConfig.sampleRate = 8000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_020.wav").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_021
 * @tc.desc: record wav with channelCount 2
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_021, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_G711MU;
    videoRecorderConfig.outPutFormat = FORMAT_WAV;
    videoRecorderConfig.audioEncodingBitRate = 64000;
    videoRecorderConfig.channelCount = 2;
    videoRecorderConfig.sampleRate = 8000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_021.wav").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_configure_022
 * @tc.desc: Stop releasing resource verification results
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_configure_022, TestSize.Level2)
{
    const int numMainResets = 5;
    const int numThreads = 5;
    const int numResetsPerThead = 5;
    recorderServer_->Prepare();
    std::this_thread::sleep_for(std::chrono::seconds(RECORDER_TIME));
    recorderServer_->Pause();
    recorderServer_->Resume();
    for (int i = 0; i < numMainResets; ++i) {
        recorderServer_->Reset();
    }
    std::vector<std::thread> resetTheads;
    for (int i = 0; i < numThreads; ++i) {
        resetTheads.emplace_back([=, recorderServer = recorderServer_]() {
            for (int j = 0; j < numResetsPerThead; ++j) {
                recorderServer->Reset();
            }
        });
    }
    for (auto& t : resetTheads) {
        if (t.joinable()) {
            t.join();
        }
    }
    recorderServer_->Stop(false);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
}

/**
 * @tc.name: recorder_mp3_001
 * @tc.desc: record mp3
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_mp3_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_MPEG;
    videoRecorderConfig.outPutFormat = FORMAT_MP3;
    videoRecorderConfig.audioEncodingBitRate = 64000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_mp3_001.mp3").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_G711MU_001
 * @tc.desc: record G711MU
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_G711MU_001, TestSize.Level2)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.audioFormat = AUDIO_G711MU;
    videoRecorderConfig.outPutFormat = FORMAT_WAV;
    videoRecorderConfig.audioEncodingBitRate = 64000;
    videoRecorderConfig.channelCount = 1;
    videoRecorderConfig.sampleRate = 8000;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_WAV_001.wav").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_prepare
 * @tc.desc: record prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_prepare, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_prepare.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_yuv_H264
 * @tc.desc: record video with yuv H264
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_yuv_H264, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_yuv_H264.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    system("hidumper -s 3002 -a recorder");
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_es
 * @tc.desc: record video with es
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_es, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_ES;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_es.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_audio_es
 * @tc.desc: record audio with es
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_audio_es, TestSize.Level0)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_audio_es.m4a").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_audio_es_0100
 * @tc.desc: record audio with es
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_audio_es_0100, TestSize.Level0)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.outPutFormat = FORMAT_M4A;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_audio_es.m4a").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_av_yuv_H264
 * @tc.desc: record audio with yuv H264
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_av_yuv_H264, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_av_yuv_H264.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_av_yuv_h264
 * @tc.desc: record audio with yuv h264
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_av_yuv_h264, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_av_yuv_h264.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    recorderServer_->Start();
    sleep(RECORDER_TIME);
    recorderServer_->Stop(false);
    recorderServer_->StopBuffer(PURE_VIDEO);
    recorderServer_->Reset();
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_pause_resume
 * @tc.desc: record video, then pause resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_pause_resume, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_pause_resume.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_stop_start
 * @tc.desc: record video, then stop start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_stop_start, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.audioFormat = AUDIO_DEFAULT;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_stop_start.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_NE(MSERR_OK, recorderServer_->Start());
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_stop_start
 * @tc.desc: record video, then stop start
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_wrongsize, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_wrongsize.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_ERROR, g_videoRecorderConfig));
    recorderServer_->Start();
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    recorderServer_->Reset();
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetOrientationHint_001
 * @tc.desc: record video, SetOrientationHint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetOrientationHint_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
    "recorder_video_SetOrientationHint_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(1, 1);
    recorderServer_->SetOrientationHint(90);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetOrientationHint_002
 * @tc.desc: record video, SetOrientationHint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetOrientationHint_002, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetOrientationHint_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(-91, 0);
    recorderServer_->SetOrientationHint(720);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetOrientationHint_003
 * @tc.desc: record video, SetOrientationHint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetOrientationHint_003, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetOrientationHint_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(91, 0);
    recorderServer_->SetOrientationHint(180);
    system("param set sys.media.dump.surfacesrc.enable true");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetOrientationHint_004
 * @tc.desc: record video, SetOrientationHint
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetOrientationHint_004, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetOrientationHint_004.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(1, 181);
    recorderServer_->SetLocation(1, -181);
    recorderServer_->SetOrientationHint(270);
    system("param set sys.media.dump.surfacesrc.enable false");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_UpdateRotation_001
 * @tc.desc: record video, Update rotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_UpdateRotation_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_UpdateRotation_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    system("param set sys.media.dump.surfacesrc.enable false");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetOrientationHint(0);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_UpdateRotation_002
 * @tc.desc: record video, Update rotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_UpdateRotation_002, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_UpdateRotation_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    system("param set sys.media.dump.surfacesrc.enable false");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetOrientationHint(90);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_UpdateRotation_003
 * @tc.desc: record video, Update rotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_UpdateRotation_003, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_UpdateRotation_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    system("param set sys.media.dump.surfacesrc.enable false");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetOrientationHint(180);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_UpdateRotation_004
 * @tc.desc: record video, Update rotation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_UpdateRotation_004, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_UpdateRotation_004.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    system("param set sys.media.dump.surfacesrc.enable false");
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetOrientationHint(270);
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetCaptureRate_001
 * @tc.desc: record video ,SetCaptureRate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetCaptureRate_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetCaptureRate_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    recorderServer_->SetCaptureRate(0, -0.1);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetMaxFileSize_001
 * @tc.desc: record video ,SetMaxFileSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetMaxFileSize_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetMaxFileSize_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetCaptureRate(0, 30);
    recorderServer_->SetMaxFileSize(-1);
    recorderServer_->SetMaxFileSize(5000);
    recorderServer_->SetNextOutputFile(g_videoRecorderConfig.outputFd);
    recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000);
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetMaxFileSize_002
 * @tc.desc: record video ,SetMaxFileSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetMaxFileSize_002, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetMaxFileSize_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetMaxFileSize(-1);
    recorderServer_->SetNextOutputFile(g_videoRecorderConfig.outputFd);
    recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000);
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetParameter_001
 * @tc.desc: record video, SetParameter
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetParameter_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetParameter_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetDataSource_001
 * @tc.desc: record video, SetDataSource
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetDataSource_001, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetDataSource_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        recorderServer_->SetDataSource(DataSourceType::METADATA, g_videoRecorderConfig.videoSourceId));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetGenre_001
 * @tc.desc: record video, SetGenre
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetGenre_001, TestSize.Level0)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetGenre_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    recorderServer_->SetGenre(videoRecorderConfig.genre);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetGenre_002
 * @tc.desc: record audio SetGenre
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetGenre_002, TestSize.Level0)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.outPutFormat = FORMAT_M4A;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetGenre_002.m4a").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    recorderServer_->SetGenre(videoRecorderConfig.genre);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetCustomInfo_001
 * @tc.desc: record video, SetCustomInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetCustomInfo_001, TestSize.Level0)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    videoRecorderConfig.videoFormat = H264;
    videoRecorderConfig.outPutFormat = FORMAT_DEFAULT;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetCustomInfo_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, videoRecorderConfig));
    Meta customInfo;
    customInfo.SetData("key", "value");
    recorderServer_->SetUserCustomInfo(customInfo);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_SetCustomInfo_002
 * @tc.desc: record audio SetCustomInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_SetCustomInfo_002, TestSize.Level0)
{
    VideoRecorderConfig videoRecorderConfig;
    videoRecorderConfig.outPutFormat = FORMAT_M4A;
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_SetCustomInfo_002.m4a").c_str(), O_RDWR);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, videoRecorderConfig));
    Meta customInfo;
    customInfo.SetData("key", "value");
    recorderServer_->SetUserCustomInfo(customInfo);
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_video_GetMetaSurface
 * @tc.desc: record video with meta data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_GetMetaSurface, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.metaSourceType = VIDEO_META_MAKER_INFO;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_GetMetaSurface.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetMetaSurface(g_videoRecorderConfig.metaSourceId);
    ASSERT_TRUE(surface != nullptr);
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioSourceType_001
 * @tc.desc: record video source as voice recognition
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioSourceType_001, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_SOURCE_VOICE_RECOGNITION;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioSourceType_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioSourceType_002
 * @tc.desc: record video source as voice communication
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioSourceType_002, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_SOURCE_VOICE_COMMUNICATION;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioSourceType_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioSourceType_003
 * @tc.desc: record video source as voice message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioSourceType_003, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_SOURCE_VOICE_MESSAGE;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioSourceType_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_001
 * @tc.desc: record set max duration is undefined
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_002
 * @tc.desc: record set max duration -1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = -1;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_003
 * @tc.desc: record set max duration 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = 0;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_004
 * @tc.desc: record set max duration 1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_004, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = 1;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_004.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_005
 * @tc.desc: record set max duration 5
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_005, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = 5;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_005.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_006
 * @tc.desc: record set max duration but stop first
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_006, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = INT32_MAX;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_006.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_007
 * @tc.desc: record set max duration, pause, resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_007, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.maxDuration = INT32_MAX;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_007.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoEnableStableQualityMode_001
 * @tc.desc: enableStableQualityMode with default value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoEnableStableQualityMode_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoEnableStableQualityMode_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME/2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME/2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoEnableStableQualityMode_002
 * @tc.desc: enableStableQualityMode sets to false while enableTemporalScale is true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoEnableStableQualityMode_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableTemporalScale = true;
    g_videoRecorderConfig.enableStableQualityMode = false;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoEnableStableQualityMode_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME/2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME/2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}
} // namespace Media
} // namespace OHOS