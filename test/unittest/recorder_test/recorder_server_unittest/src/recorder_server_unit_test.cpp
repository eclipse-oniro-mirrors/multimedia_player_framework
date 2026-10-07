/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
#include "recorder_utils.h"

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
    g_videoRecorderConfig = VideoRecorderConfig();
    recorderServer_ = std::make_shared<RecorderServerMock>();
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
    "recorder_GetCurrentCapturerChangeInfo_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetLocation_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(1, 1);
    Location location;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetLocation(location));
    EXPECT_EQ(location.latitude, 1);
    EXPECT_EQ(location.longitude, 1);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_Repeat_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
            "recorder_video_SetFileSplitDuration_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));

    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000));
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
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAudioAacProfile(g_videoRecorderConfig.audioSourceId,
              g_videoRecorderConfig.aacProfile));
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
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAudioAacProfile(g_videoRecorderConfig.audioSourceId,
              g_videoRecorderConfig.aacProfile));
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
            "recorder_video_SetAudioEncoder_Error_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK,
              recorderServer_->SetAudioAacProfile(g_videoRecorderConfig.audioSourceId,
              g_videoRecorderConfig.aacProfile));
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_GetSurface_Error_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetSurface(2);
    EXPECT_EQ(surface, nullptr);
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
            "recorder_video_SetVideoSourceRepeat_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
            "recorder_video_SetAudioSourceRepeat_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_DrainBufferTrue_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetVideoSourceRGBA_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_DrainBufferStarted_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);

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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_015.mp3").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_016.mp3").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_017.mp3").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_018.mp3").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_019.wav").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_020.wav").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_configure_021.wav").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_mp3_001.mp3").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_WAV_001.wav").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_prepare.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_yuv_H264.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_video_es.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_audio_es.m4a").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_audio_es.m4a").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_av_yuv_H264.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
 * @tc.name: recorder_video_pause_resume
 * @tc.desc: record video, then pause resume
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_video_pause_resume, TestSize.Level0)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_pause_resume.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_stop_start.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_wrongsize.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_ERROR, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
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
    "recorder_video_SetOrientationHint_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_SetOrientationHint_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_SetOrientationHint_003.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_SetOrientationHint_004.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_UpdateRotation_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_UpdateRotation_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_UpdateRotation_003.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_video_UpdateRotation_004.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetCaptureRate_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_NE(MSERR_OK, recorderServer_->SetCaptureRate(0, -0.1));
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetMaxFileSize_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_NE(MSERR_OK, recorderServer_->SetCaptureRate(0, 30));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetMaxFileSize(-1));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetMaxFileSize(5000));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetNextOutputFile(g_videoRecorderConfig.outputFd));
    EXPECT_NE(MSERR_OK, recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000));
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetParameter_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    Format format;
    EXPECT_EQ(MSERR_OK, recorderServer_->SetParameter(1, format));
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetDataSource_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetGenre_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetGenre_002.m4a").c_str(), O_RDWR | O_CREAT, 0666);
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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetCustomInfo_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(videoRecorderConfig.outputFd >= 0);

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
    videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_SetCustomInfo_002.m4a").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_video_GetMetaSurface.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
 * @tc.name: recorder_GetMetaSurface_001
 * @tc.desc: GetMetaSurface with non-meta sourceId, IsMeta returns false
 *           Covers branch: outer condition A=false (hirecorder_impl.cpp line 411-415)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMetaSurface_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMetaSurface_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());

    const int32_t VIDEO_SOURCE_ID = SourceIdGenerator::GenerateVideoSourceId(0);
    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetMetaSurface(VIDEO_SOURCE_ID);
    EXPECT_TRUE(surface == nullptr);

    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetMetaSurface_002
 * @tc.desc: GetMetaSurface with meta sourceId but type out of range (>= BUTT)
 *           Covers branch: outer condition A=true, B=false (hirecorder_impl.cpp line 411-415)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMetaSurface_002, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMetaSurface_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());

    const int32_t OUT_OF_RANGE_META_ID = SourceIdGenerator::GenerateMetaSourceId(1);
    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetMetaSurface(OUT_OF_RANGE_META_ID);
    EXPECT_TRUE(surface == nullptr);

    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetMetaSurface_003
 * @tc.desc: GetMetaSurface with valid meta sourceId but metaDataFilters_ empty
 *           (SetMetaSource not called, find returns end())
 *           Covers branch: inner condition C=false (hirecorder_impl.cpp line 415)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMetaSurface_003, TestSize.Level2)
{
    g_videoRecorderConfig.metaSourceType = VIDEO_META_SOURCE_INVALID;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMetaSurface_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());

    const int32_t VALID_META_ID_NOT_IN_MAP = SourceIdGenerator::GenerateMetaSourceId(0);
    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetMetaSurface(VALID_META_ID_NOT_IN_MAP);
    EXPECT_TRUE(surface == nullptr);

    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetMetaSurface_004
 * @tc.desc: GetMetaSurface with zero and negative sourceId, IsMeta returns false
 *           Covers branch: outer condition A=false via sourceId<=0 (hirecorder_impl.cpp line 411-415)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMetaSurface_004, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMetaSurface_004.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());

    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetMetaSurface(0);
    EXPECT_TRUE(surface == nullptr);

    surface = recorderServer_->GetMetaSurface(-1);
    EXPECT_TRUE(surface == nullptr);

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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetAudioSourceType_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetAudioSourceType_003.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_003.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_004.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_005.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_006.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetMaxDuration_007.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_SetVideoEnableStableQualityMode_001.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
        "recorder_SetVideoEnableStableQualityMode_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
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
 * @tc.name: recorder_SetUserMeta_001
 * @tc.desc: SetUserMeta in REC_INITIALIZED state should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_001, TestSize.Level2)
{
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
}

/**
 * @tc.name: recorder_SetUserMeta_002
 * @tc.desc: SetUserMeta in REC_CONFIGURED state should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_002.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_003
 * @tc.desc: SetUserMeta in REC_PREPARED state with valid meta should succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_003.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("USER_META_TEST", "test_metadata");
    
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_004
 * @tc.desc: SetUserMeta in REC_RECORDING state should succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_004, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_004.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("USER_META_TEST", "recording_metadata");
    
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_005
 * @tc.desc: SetUserMeta in REC_PAUSED state should succeed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_005, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_005.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(1);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("USER_META_TEST", "paused_metadata");
    
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_007
 * @tc.desc: SetUserMeta after Reset should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_007, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_007.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_008
 * @tc.desc: SetUserMeta with empty meta in REC_PREPARED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_008, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_008.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(MSERR_PARAM_OUT_OF_RANGE, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_009
 * @tc.desc: SetUserMeta with complex metadata in REC_RECORDING state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_009, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_009.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("USER_META_TEST", "complex_metadata");
    userMeta->SetData(Tag::MEDIA_TITLE, "Test Title");
    userMeta->SetData(Tag::MEDIA_ARTIST, "Test Artist");
    
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_010
 * @tc.desc: SetUserMeta multiple times in REC_PREPARED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_010, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_010.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    
    for (int i = 0; i < 3; i++) {
        std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
        userMeta->SetData("USER_META_TEST", "metadata_" + std::to_string(i));
        
        EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    }
    
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_011
 * @tc.desc: SetUserMeta in REC_ERROR state should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_011, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_011.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_012
 * @tc.desc: SetUserMeta with audio and video recording
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_012, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_012.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("USER_META_TEST", "av_metadata");
    
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_013
 * @tc.desc: SetUserMeta after Release should fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_013, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetUserMeta_013.mp4").c_str(), O_RDWR | O_CREAT, 0666);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    EXPECT_NE(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_001
 * @tc.desc: SQR mode with sqrFactor=51 (max boundary), verify full recording flow succeeds
 *           Covers: branch D (server success), branch F (SQR+sqrFactor in [0,51]),
 *           branch H (adapter Meta→Format conversion)
 *           Boundary: 51 is SQR_FACTOR_MAX, tests upper bound of valid range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = true;
    g_videoRecorderConfig.sqrFactor = 51;
    g_videoRecorderConfig.sqrFactorSet = true;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_002
 * @tc.desc: SQR mode with sqrFactor=0 (min boundary), verify full recording flow succeeds
 *           Covers: branch D (server success), branch F (SQR+sqrFactor in [0,51]),
 *           branch H (adapter Meta→Format conversion)
 *           Boundary: 0 is SQR_FACTOR_MIN, tests lower bound of valid range
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = true;
    g_videoRecorderConfig.sqrFactor = 0;
    g_videoRecorderConfig.sqrFactorSet = true;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_003
 * @tc.desc: Non-SQR mode (VBR) with sqrFactor=-1 (default), verify server does not intercept
 *           Covers: branch E (enableStableQualityMode=false → no range check, pass through),
 *           VBR path (ConfigureVidSqrFactorToEncFormat not called)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = false;
    g_videoRecorderConfig.sqrFactor = SQR_FACTOR_INVALID;
    g_videoRecorderConfig.sqrFactorSet = false;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_004
 * @tc.desc: Call SetVideoSqrFactor in wrong state (before SetFormat), verify state check
 *           Covers: branch A (status_ != REC_CONFIGURED → MSERR_INVALID_OPERATION)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_004, TestSize.Level2)
{
    int32_t videoSourceId = 0;
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoSource(VIDEO_SOURCE_SURFACE_YUV, videoSourceId));
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoSqrFactor(videoSourceId, 30));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_005
 * @tc.desc: SQR mode with sqrFactor=52 (just above max boundary), verify server returns 401
 *           Covers: branch B upper (enableStableQualityMode=true + sqrFactor > 51 → 401)
 *           Boundary: 52 is SQR_FACTOR_MAX+1, tests upper bound violation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_005, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = true;
    g_videoRecorderConfig.sqrFactor = 52;
    g_videoRecorderConfig.sqrFactorSet = true;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_NE(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_006
 * @tc.desc: Non-SQR mode with invalid sqrFactor(60), verify server does not intercept
 *           Covers: branch C (enableStableQualityMode=false + sqrFactor out of range → pass through)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_006, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = false;
    g_videoRecorderConfig.sqrFactor = 60;
    g_videoRecorderConfig.sqrFactorSet = true;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSqrFactor_007
 * @tc.desc: SQR mode with sqrFactor not set (sqrFactorSet=false), verify backward compatible
 *           Covers: sqrFactor not set → SetVideoSqrFactor not called → no 401 → success
 *           This is the backward compatibility scenario: existing apps using SQR without sqrFactor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSqrFactor_007, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.enableStableQualityMode = true;
    g_videoRecorderConfig.sqrFactor = SQR_FACTOR_INVALID;
    g_videoRecorderConfig.sqrFactorSet = false;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetVideoSqrFactor.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);

    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->RequesetBuffer(AUDIO_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    sleep(RECORDER_TIME / 2);
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    recorderServer_->StopBuffer(PURE_VIDEO);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetAVRecorderConfig_001
 * @tc.desc: Server GetAVRecorderConfig after SetFormat, verify config map populated
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetAVRecorderConfig_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetAVRecorderConfig_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    ConfigMap configMap;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetAVRecorderConfig(configMap));
    EXPECT_FALSE(configMap.empty());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetFileGenerationMode_001
 * @tc.desc: Server SetFileGenerationMode with AUTO_CREATE mode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetFileGenerationMode_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetFileGenerationMode_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFileGenerationMode(FileGenerationMode::AUTO_CREATE_CAMERA_SCENE));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetWillMuteWhenInterrupted_002
 * @tc.desc: Server SetWillMuteWhenInterrupted after Prepare, verify state protection returns INVALID_OPERATION
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetWillMuteWhenInterrupted_002, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT +
        "recorder_SetWillMuteWhenInterrupted_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // SetWillMuteWhenInterrupted is only valid in REC_INITIALIZED and REC_CONFIGURED states
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetWillMuteWhenInterrupted(true));
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetWillMuteWhenInterrupted(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetWatermark_001
 * @tc.desc: Server SetWatermark with nullptr buffer after SetFormat, verify error handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetWatermark_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetWatermark_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    bool isWatermarkSupported = false;
    EXPECT_EQ(MSERR_OK, recorderServer_->IsWatermarkSupported(isWatermarkSupported));
    std::shared_ptr<AVBuffer> nullBuffer = nullptr;
    int32_t ret = recorderServer_->SetWatermark(nullBuffer);
    EXPECT_NE(MSERR_OK, ret);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_AddWatermark_001
 * @tc.desc: Server AddWatermark with nullptr buffer, verify error handling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_AddWatermark_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    bool isWatermarkSupported = false;
    EXPECT_EQ(MSERR_OK, recorderServer_->IsWatermarkSupported(isWatermarkSupported));
    std::shared_ptr<AVBuffer> nullBuffer = nullptr;
    int32_t watermarkCount = 0;
    int32_t ret = recorderServer_->AddWatermark(nullBuffer, 0, 0, watermarkCount);
    EXPECT_NE(MSERR_OK, ret);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_AfterSetFormat_001
 * @tc.desc: Server SetUserMeta with valid Meta object after SetFormat and Prepare
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_AfterSetFormat_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetUserMeta_AfterSetFormat_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    auto userMeta = std::make_shared<Meta>();
    userMeta->SetData("test_key", std::string("test_value"));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetLocation_001
 * @tc.desc: Server GetLocation after SetLocation, verify location round-trip
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetLocation_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetLocation_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(45.0, 90.0);
    Location location;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetLocation(location));
    EXPECT_FLOAT_EQ(location.latitude, 45.0);
    EXPECT_FLOAT_EQ(location.longitude, 90.0);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_state_machine_003
 * @tc.desc: Call SetUserMeta before Prepare, verify MSERR_INVALID_STATE returned
 *           Covers: CHECK_STATUS_FAILED_AND_LOGE_RET for SetUserMeta
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_state_machine_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_state_machine_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    auto userMeta = std::make_shared<Meta>();
    userMeta->SetData("key", std::string("value"));
    EXPECT_NE(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_state_machine_004
 * @tc.desc: Call GetMaxAmplitude before Prepare, verify MSERR_NULL_POINTER or MSERR_INVALID_STATE returned
 *           Covers: recorderEngine_ nullptr check and state check for GetMaxAmplitude
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_state_machine_004, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_state_machine_004.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    int32_t amplitude = -1;
    EXPECT_NE(MSERR_OK, recorderServer_->GetMaxAmplitude(amplitude));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_engine_null_001
 * @tc.desc: Call various functions after Release, verify error codes returned
 *           Covers: recorderEngine_ nullptr path after Release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_engine_null_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_engine_null_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    // After Release, recorderEngine_ is nullptr
    EXPECT_NE(MSERR_OK, recorderServer_->Prepare());
    EXPECT_NE(MSERR_OK, recorderServer_->Start());
    EXPECT_NE(MSERR_OK, recorderServer_->Pause());
    EXPECT_NE(MSERR_OK, recorderServer_->Resume());
    EXPECT_NE(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_NE(MSERR_OK, recorderServer_->Reset());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_engine_null_002
 * @tc.desc: Call config functions after Release, verify error codes returned
 *           Covers: recorderEngine_ nullptr path for config functions after Release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_engine_null_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_engine_null_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    // After Release, config functions should fail
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoEncoder(0, H264));
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoSize(0, 1280, 720));
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoFrameRate(0, 30));
    EXPECT_NE(MSERR_OK, recorderServer_->SetMaxDuration(60));
    EXPECT_NE(MSERR_OK, recorderServer_->SetMaxFileSize(100000000));
    EXPECT_NE(MSERR_OK, recorderServer_->SetOutputFile(g_videoRecorderConfig.outputFd));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_engine_null_003
 * @tc.desc: Call metadata/query functions after Release, verify error codes returned
 *           Covers: recorderEngine_ nullptr path for metadata and query functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_engine_null_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_engine_null_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    // After Release, IsWatermarkSupported/GetAvailableEncoder fail (engine nullptr)
    bool isWatermarkSupported = false;
    EXPECT_NE(MSERR_OK, recorderServer_->IsWatermarkSupported(isWatermarkSupported));
    // GetAVRecorderConfig and GetLocation have no state/engine check, always return MSERR_OK
    ConfigMap configMap;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetAVRecorderConfig(configMap));
    Location location;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetLocation(location));
    std::vector<EncoderCapabilityData> encoderInfo;
    EXPECT_NE(MSERR_OK, recorderServer_->GetAvailableEncoder(encoderInfo));
    AudioRecorderChangeInfo changeInfo;
    EXPECT_NE(MSERR_OK, recorderServer_->GetCurrentCapturerChangeInfo(changeInfo));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_double_release_001
 * @tc.desc: Call Release twice, verify second Release returns MSERR_OK (idempotent)
 *           Covers: double-release protection path in RecorderServer::Release
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_double_release_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_double_release_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoIsHdr_003
 * @tc.desc: Call SetVideoIsHdr with invalid sourceId after Release, verify error
 *           Covers: recorderEngine_ nullptr path for SetVideoIsHdr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoIsHdr_003, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H265;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoIsHdr_003.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoIsHdr(0, true));
    EXPECT_NE(MSERR_OK, recorderServer_->SetVideoIsHdr(0, false));
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioAacProfile_001
 * @tc.desc: Call SetAudioAacProfile with valid AAC_LC profile after SetFormat
 *           Covers: SetAudioAacProfile normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioAacProfile_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.aSource = AUDIO_MIC;
    g_videoRecorderConfig.audioFormat = AAC_LC;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioAacProfile_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioAacProfile(g_videoRecorderConfig.audioSourceId,
        AacProfile::AAC_LC));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioAacProfile_002
 * @tc.desc: Call SetAudioAacProfile with AAC_HE profile after SetFormat
 *           Covers: SetAudioAacProfile with different profile
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioAacProfile_002, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.aSource = AUDIO_MIC;
    g_videoRecorderConfig.audioFormat = AAC_LC;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioAacProfile_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioAacProfile(g_videoRecorderConfig.audioSourceId,
        AacProfile::AAC_HE));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioEncoder_Mismatch_001
 * @tc.desc: Set AUDIO_MPEG encoder with FORMAT_MPEG_4, verify mismatch error
 *           Covers: SetAudioEncoder AUDIO_MPEG && FORMAT_MPEG_4 mismatch check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioEncoder_Mismatch_001, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_MIC;
    g_videoRecorderConfig.audioFormat = AUDIO_MPEG;
    g_videoRecorderConfig.outPutFormat = FORMAT_MPEG_4;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioEncoder_Mismatch_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_AUDIOCODEC_FILEFORMAT_MATCH_ERROR_401,
        recorderServer_->SetAudioEncoder(g_videoRecorderConfig.audioSourceId, AUDIO_MPEG));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioBitRate_G711MU_001
 * @tc.desc: Set AUDIO_G711MU encoder with non-64000 bitrate, verify mismatch error
 *           Covers: SetAudioEncodingBitRate AUDIO_G711MU && audioBitRate != 64000 check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioBitRate_G711MU_001, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_MIC;
    g_videoRecorderConfig.audioFormat = AUDIO_G711MU;
    g_videoRecorderConfig.outPutFormat = FORMAT_MPEG_4;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioBitRate_G711MU_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioEncoder(g_videoRecorderConfig.audioSourceId, AUDIO_G711MU));
    // Non-64000 bitrate should fail for G711MU
    EXPECT_EQ(MSERR_AUDIO_G711MU_MATCH_ERROR_401,
        recorderServer_->SetAudioEncodingBitRate(g_videoRecorderConfig.audioSourceId, 48000));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioBitRate_G711MU_002
 * @tc.desc: Set AUDIO_G711MU encoder with correct 64000 bitrate, verify success
 *           Covers: SetAudioEncodingBitRate AUDIO_G711MU && audioBitRate == 64000 path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioBitRate_G711MU_002, TestSize.Level2)
{
    g_videoRecorderConfig.aSource = AUDIO_MIC;
    g_videoRecorderConfig.audioFormat = AUDIO_G711MU;
    g_videoRecorderConfig.outPutFormat = FORMAT_MPEG_4;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioBitRate_G711MU_002.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioEncoder(g_videoRecorderConfig.audioSourceId, AUDIO_G711MU));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioEncodingBitRate(g_videoRecorderConfig.audioSourceId, 64000));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoIsHdr_001
 * @tc.desc: Call SetVideoIsHdr with isHdr=true in REC_CONFIGURED state
 *           Covers: SetVideoIsHdr normal path with isHdr=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoIsHdr_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H265;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoIsHdr_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoSource(g_videoRecorderConfig.vSource,
        g_videoRecorderConfig.videoSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoIsHdr(g_videoRecorderConfig.videoSourceId, true));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoEnableTemporalScale_001
 * @tc.desc: Call SetVideoEnableTemporalScale with true, verify success
 *           Covers: SetVideoEnableTemporalScale normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoEnableTemporalScale_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoEnableTemporalScale_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoSource(g_videoRecorderConfig.vSource,
        g_videoRecorderConfig.videoSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoEnableTemporalScale(g_videoRecorderConfig.videoSourceId, true));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoEnableBFrame_001
 * @tc.desc: Call SetVideoEnableBFrame with true, verify success
 *           Covers: SetVideoEnableBFrame normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoEnableBFrame_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoEnableBFrame_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoSource(g_videoRecorderConfig.vSource,
        g_videoRecorderConfig.videoSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoEnableBFrame(g_videoRecorderConfig.videoSourceId, true));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserCustomInfo_001
 * @tc.desc: Call SetUserCustomInfo in REC_CONFIGURED state, verify success
 *           Covers: SetUserCustomInfo normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserCustomInfo_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetUserCustomInfo_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    Meta userCustomInfo;
    userCustomInfo.SetData("test_key", "test_value");
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserCustomInfo(userCustomInfo));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetGenre_001
 * @tc.desc: Call SetGenre in REC_CONFIGURED state, verify success
 *           Covers: SetGenre normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetGenre_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetGenre_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    std::string genre = "pop";
    EXPECT_EQ(MSERR_OK, recorderServer_->SetGenre(genre));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetNextOutputFile_001
 * @tc.desc: Call SetNextOutputFile in REC_CONFIGURED state, verify success
 *           Covers: SetNextOutputFile normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetNextOutputFile_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetNextOutputFile_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    int32_t nextFd = open((RECORDER_ROOT + "recorder_SetNextOutputFile_001_next.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(nextFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetNextOutputFile(nextFd));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
    close(nextFd);
}

/**
 * @tc.name: recorder_DumpInfo_001
 * @tc.desc: Call DumpInfo with valid fd, verify MSERR_OK
 *           Covers: DumpInfo with fd != -1 branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_DumpInfo_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_DumpInfo_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    int32_t dumpFd = open((RECORDER_ROOT + "recorder_DumpInfo_001_dump.txt").c_str(), O_RDWR | O_CREAT, 0644);
    ASSERT_TRUE(dumpFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->DumpInfo(dumpFd));
    EXPECT_EQ(MSERR_OK, recorderServer_->DumpInfo(-1)); // fd == -1 branch
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
    close(dumpFd);
}

/**
 * @tc.name: recorder_Prepare_Repeat_001
 * @tc.desc: Call Prepare when already in REC_PREPARED state, verify INVALID_OPERATION
 *           Covers: Prepare repeat check (status_ == REC_PREPARED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Prepare_Repeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Prepare_Repeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // Repeat Prepare should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Start_Repeat_001
 * @tc.desc: Call Start when already in REC_RECORDING state, verify INVALID_OPERATION
 *           Covers: Start repeat check (status_ == REC_RECORDING)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Start_Repeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Start_Repeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    // Repeat Start should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Pause_Repeat_001
 * @tc.desc: Call Pause when already in REC_PAUSED state, verify INVALID_OPERATION
 *           Covers: Pause repeat check (status_ == REC_PAUSED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Pause_Repeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Pause_Repeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Pause());
    // Repeat Pause should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Resume_Repeat_001
 * @tc.desc: Call Resume when already in REC_RECORDING state, verify INVALID_OPERATION
 *           Covers: Resume repeat check (status_ == REC_RECORDING)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Resume_Repeat_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Resume_Repeat_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Start());
    // Resume when already recording should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Resume_WrongState_001
 * @tc.desc: Call Resume in REC_INITIALIZED state (not RECORDING or PAUSED), verify INVALID_OPERATION
 *           Covers: Resume state check (status_ != REC_RECORDING && status_ != REC_PAUSED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Resume_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Resume_WrongState_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // Resume in PREPARED state should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Resume());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Stop_WrongState_001
 * @tc.desc: Call Stop in REC_INITIALIZED state, verify INVALID_OPERATION
 *           Covers: Stop state check (status_ != REC_RECORDING && status_ != REC_PAUSED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Stop_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Stop_WrongState_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // Stop in PREPARED state should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Stop(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetFileSplitDuration_WrongState_001
 * @tc.desc: Call SetFileSplitDuration in REC_PREPARED state (not RECORDING/PAUSED), verify INVALID_OPERATION
 *           Covers: SetFileSplitDuration state check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetFileSplitDuration_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetFileSplitDuration_WrongState_001.mp4")
        .c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        recorderServer_->SetFileSplitDuration(FileSplitType::FILE_SPLIT_POST, -1, 1000));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetRecorderCallback_WrongState_001
 * @tc.desc: Call SetRecorderCallback in REC_PREPARED state, verify INVALID_OPERATION
 *           Covers: SetRecorderCallback state check (not INITIALIZED and not CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetRecorderCallback_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetRecorderCallback_WrongState_001.mp4")
        .c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    std::shared_ptr<RecorderCallbackTest> cb = std::make_shared<RecorderCallbackTest>();
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetRecorderCallback(cb));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetRecorderCallback_001
 * @tc.desc: Call SetRecorderCallback in REC_INITIALIZED state, verify success
 *           Covers: SetRecorderCallback normal path in INITIALIZED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetRecorderCallback_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetRecorderCallback_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In INITIALIZED state (before SetFormat), set callback
    std::shared_ptr<RecorderCallbackTest> cb = std::make_shared<RecorderCallbackTest>();
    EXPECT_EQ(MSERR_OK, recorderServer_->SetRecorderCallback(cb));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetMaxAmplitude_WrongState_001
 * @tc.desc: Call GetMaxAmplitude in REC_INITIALIZED state, verify MSERR_INVALID_STATE
 *           Covers: GetMaxAmplitude state check (not PREPARED/RECORDING/PAUSED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMaxAmplitude_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMaxAmplitude_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In INITIALIZED state, GetMaxAmplitude should fail
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->GetMaxAmplitude(amplitude));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetMaxAmplitude_002
 * @tc.desc: Call GetMaxAmplitude after Prepare, verify success
 *           Covers: GetMaxAmplitude normal path in REC_PREPARED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetMaxAmplitude_002, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetMaxAmplitude_002.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    int32_t amplitude = 0;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetMaxAmplitude(amplitude));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetLocation_WrongState_001
 * @tc.desc: Call SetLocation in REC_INITIALIZED state (not REC_CONFIGURED), verify it returns without setting
 *           Covers: SetLocation state check (status_ != REC_CONFIGURED) early return
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetLocation_WrongState_001, TestSize.Level2)
{
    // In INITIALIZED state, SetLocation should return without doing anything
    recorderServer_->SetLocation(10.0, 20.0);
    Location location;
    // GetLocation should return default values (0, 0) since SetLocation was ignored
    EXPECT_EQ(MSERR_OK, recorderServer_->GetLocation(location));
    EXPECT_EQ(0, location.latitude);
    EXPECT_EQ(0, location.longitude);
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
}

/**
 * @tc.name: recorder_SetWatermark_WrongState_001
 * @tc.desc: Call SetWatermark in REC_CONFIGURED state (not REC_PREPARED), verify INVALID_OPERATION
 *           Covers: SetWatermark state check (status_ != REC_PREPARED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetWatermark_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetWatermark_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    // In CONFIGURED state, SetWatermark should fail
    std::shared_ptr<AVBuffer> waterMarkBuffer = nullptr;
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetWatermark(waterMarkBuffer));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_AddWatermark_InvalidSize_001
 * @tc.desc: Call AddWatermark with invalid width=0 and height=0, verify MSERR_INVALID_VAL
 *           Covers: AddWatermark width/height validation (width <= 0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_InvalidSize_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_AddWatermark_InvalidSize_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    std::shared_ptr<AVBuffer> watermarkBuffer = nullptr;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_VAL, recorderServer_->AddWatermark(watermarkBuffer, 0, 100, watermarkCount));
    EXPECT_EQ(MSERR_INVALID_VAL, recorderServer_->AddWatermark(watermarkBuffer, 100, 0, watermarkCount));
    EXPECT_EQ(MSERR_INVALID_VAL,
        recorderServer_->AddWatermark(watermarkBuffer, WATERMARK_WIDTH_HEIGHT_MAX + 1, 100, watermarkCount));
    EXPECT_EQ(MSERR_INVALID_VAL,
        recorderServer_->AddWatermark(watermarkBuffer, 100, WATERMARK_WIDTH_HEIGHT_MAX + 1, watermarkCount));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_AddWatermark_WrongState_001
 * @tc.desc: Call AddWatermark in REC_PREPARED state (not INITIALIZED/CONFIGURED), verify INVALID_OPERATION
 *           Covers: AddWatermark state check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_AddWatermark_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_AddWatermark_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // In PREPARED state, AddWatermark should fail
    std::shared_ptr<AVBuffer> watermarkBuffer = nullptr;
    int32_t watermarkCount = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        recorderServer_->AddWatermark(watermarkBuffer, 100, 100, watermarkCount));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_TransmitQos_001
 * @tc.desc: Call TransmitQos with QOS_USER_INTERACTIVE level, verify success
 *           Covers: TransmitQos normal path with QOS_USER_INTERACTIVE branch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_TransmitQos_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_TransmitQos_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->TransmitQos(QOS::QosLevel::QOS_USER_INTERACTIVE));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetParameter_001
 * @tc.desc: Call SetParameter, verify MSERR_OK (always returns OK)
 *           Covers: SetParameter normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetParameter_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetParameter_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    Format format;
    format.PutIntValue("test_key", 100);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetParameter(0, format));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetAvailableEncoder_001
 * @tc.desc: Call GetAvailableEncoder, verify MSERR_OK and encoder info returned
 *           Covers: GetAvailableEncoder normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetAvailableEncoder_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetAvailableEncoder_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    std::vector<EncoderCapabilityData> encoderInfo;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetAvailableEncoder(encoderInfo));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_IsWatermarkSupported_001
 * @tc.desc: Call IsWatermarkSupported, verify MSERR_OK
 *           Covers: IsWatermarkSupported normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_IsWatermarkSupported_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_IsWatermarkSupported_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    bool isWatermarkSupported = false;
    EXPECT_EQ(MSERR_OK, recorderServer_->IsWatermarkSupported(isWatermarkSupported));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoSource_WrongState_001
 * @tc.desc: Call SetVideoSource after SetOutputFormat (not REC_INITIALIZED), verify INVALID_OPERATION
 *           Covers: SetVideoSource state check (status_ != REC_INITIALIZED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoSource_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoSource_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    // After SetOutputFormat, status is REC_CONFIGURED, SetVideoSource should fail
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        recorderServer_->SetVideoSource(VIDEO_SOURCE_SURFACE_YUV, sourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetAudioSource_WrongState_001
 * @tc.desc: Call SetAudioSource after SetOutputFormat (not REC_INITIALIZED), verify INVALID_OPERATION
 *           Covers: SetAudioSource state check (status_ != REC_INITIALIZED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetAudioSource_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetAudioSource_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    // After SetOutputFormat, status is REC_CONFIGURED, SetAudioSource should fail
    int32_t sourceId = 0;
    EXPECT_EQ(MSERR_INVALID_OPERATION,
        recorderServer_->SetAudioSource(AUDIO_MIC, sourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetOutputFormat_WrongState_001
 * @tc.desc: Call SetOutputFormat twice, second call should fail (not REC_INITIALIZED)
 *           Covers: SetOutputFormat state check (status_ != REC_INITIALIZED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetOutputFormat_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetOutputFormat_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetAudioSource(g_videoRecorderConfig.aSource,
        g_videoRecorderConfig.audioSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    // Second SetOutputFormat in REC_CONFIGURED state should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetOutputFormat(FORMAT_M4A));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetVideoEncoder_WrongState_001
 * @tc.desc: Call SetVideoEncoder in REC_INITIALIZED state (not REC_CONFIGURED), verify INVALID_OPERATION
 *           Covers: SetVideoEncoder state check (status_ != REC_CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetVideoEncoder_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetVideoEncoder_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state, SetVideoEncoder should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetVideoEncoder(0, H264));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetMaxDuration_WrongState_001
 * @tc.desc: Call SetMaxDuration in REC_INITIALIZED state (not REC_CONFIGURED), verify INVALID_OPERATION
 *           Covers: SetMaxDuration state check (status_ != REC_CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetMaxDuration_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetMaxDuration_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state, SetMaxDuration should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetMaxDuration(60));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetOutputFile_WrongState_001
 * @tc.desc: Call SetOutputFile in REC_INITIALIZED state (not REC_CONFIGURED), verify INVALID_OPERATION
 *           Covers: SetOutputFile state check (status_ != REC_CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetOutputFile_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetOutputFile_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state, SetOutputFile should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetOutputFile(g_videoRecorderConfig.outputFd));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Prepare_WrongState_001
 * @tc.desc: Call Prepare in REC_INITIALIZED state (not REC_CONFIGURED), verify INVALID_OPERATION
 *           Covers: Prepare state check (status_ != REC_CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Prepare_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Prepare_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state (after CreateRecorder but before SetFormat), Prepare should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Prepare());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Start_WrongState_001
 * @tc.desc: Call Start in REC_CONFIGURED state (not REC_PREPARED), verify INVALID_OPERATION
 *           Covers: Start state check (status_ != REC_PREPARED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Start_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Start_WrongState_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    // In REC_CONFIGURED state (before Prepare), Start should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Start());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_Pause_WrongState_001
 * @tc.desc: Call Pause in REC_PREPARED state (not REC_RECORDING), verify INVALID_OPERATION
 *           Covers: Pause state check (status_ != REC_RECORDING)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_Pause_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_Pause_WrongState_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // In REC_PREPARED state, Pause should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->Pause());
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_Prepared_001
 * @tc.desc: Call SetUserMeta in REC_PREPARED state, verify success
 *           Covers: SetUserMeta normal path (Status::NO_ERROR → MSERR_OK)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_Prepared_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetUserMeta_Prepared_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("test_key", "test_value");
    EXPECT_EQ(MSERR_OK, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetUserMeta_WrongState_001
 * @tc.desc: Call SetUserMeta in REC_INITIALIZED state, verify MSERR_INVALID_STATE
 *           Covers: SetUserMeta state check (not PREPARED/RECORDING/PAUSED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetUserMeta_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetUserMeta_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state, SetUserMeta should fail with INVALID_STATE
    std::shared_ptr<Meta> userMeta = std::make_shared<Meta>();
    userMeta->SetData("test_key", "test_value");
    EXPECT_EQ(MSERR_INVALID_STATE, recorderServer_->SetUserMeta(userMeta));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetWillMuteWhenInterrupted_001
 * @tc.desc: Call SetWillMuteWhenInterrupted in REC_INITIALIZED state, verify success
 *           Covers: SetWillMuteWhenInterrupted normal path in INITIALIZED state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetWillMuteWhenInterrupted_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetWillMuteWhenInterrupted_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    // In REC_INITIALIZED state, SetWillMuteWhenInterrupted should succeed
    EXPECT_EQ(MSERR_OK, recorderServer_->SetWillMuteWhenInterrupted(true));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetWillMuteWhenInterrupted(false));
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetWillMuteWhenInterrupted_WrongState_001
 * @tc.desc: Call SetWillMuteWhenInterrupted in REC_PREPARED state, verify INVALID_OPERATION
 *           Covers: SetWillMuteWhenInterrupted state check (not INITIALIZED and not CONFIGURED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetWillMuteWhenInterrupted_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.outputFd = open(
        (RECORDER_ROOT + "recorder_SetWillMuteWhenInterrupted_WrongState_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_AUDIO, g_videoRecorderConfig));
    EXPECT_EQ(MSERR_OK, recorderServer_->Prepare());
    // In REC_PREPARED state, SetWillMuteWhenInterrupted should fail
    EXPECT_EQ(MSERR_INVALID_OPERATION, recorderServer_->SetWillMuteWhenInterrupted(true));
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetAVRecorderConfig_Verify_001
 * @tc.desc: Call GetAVRecorderConfig after SetFormat, verify config values
 *           Covers: GetAVRecorderConfig normal path, verify config map values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetAVRecorderConfig_Verify_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetAVRecorderConfig_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    ConfigMap configMap;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetAVRecorderConfig(configMap));
    // Verify some config values
    EXPECT_EQ(configMap["withVideo"], 1);
    EXPECT_EQ(configMap["videoCodec"], static_cast<int32_t>(H264));
    EXPECT_EQ(configMap["rotation"], 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetLocation_Verify_001
 * @tc.desc: Call GetLocation after SetLocation in CONFIGURED state, verify values
 *           Covers: GetLocation normal path with location set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetLocation_Verify_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetLocation_001.mp4").c_str(), O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetLocation(30.0, 60.0);
    Location location;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetLocation(location));
    EXPECT_EQ(location.latitude, 30.0);
    EXPECT_EQ(location.longitude, 60.0);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_SetOrientationHint_001
 * @tc.desc: Call SetOrientationHint in REC_CONFIGURED state, verify success
 *           Covers: SetOrientationHint normal path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_SetOrientationHint_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_SetOrientationHint_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetFormat(PURE_VIDEO, g_videoRecorderConfig));
    recorderServer_->SetOrientationHint(90);
    ConfigMap configMap;
    EXPECT_EQ(MSERR_OK, recorderServer_->GetAVRecorderConfig(configMap));
    EXPECT_EQ(configMap["rotation"], 90);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}

/**
 * @tc.name: recorder_GetSurface_WrongState_001
 * @tc.desc: Call GetSurface in REC_INITIALIZED state (not PREPARED/RECORDING/PAUSED), verify nullptr
 *           Covers: GetSurface state check
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, recorder_GetSurface_WrongState_001, TestSize.Level2)
{
    g_videoRecorderConfig.vSource = VIDEO_SOURCE_SURFACE_YUV;
    g_videoRecorderConfig.videoFormat = H264;
    g_videoRecorderConfig.outputFd = open((RECORDER_ROOT + "recorder_GetSurface_WrongState_001.mp4").c_str(),
        O_RDWR);
    ASSERT_TRUE(g_videoRecorderConfig.outputFd >= 0);
    EXPECT_EQ(MSERR_OK, recorderServer_->SetVideoSource(g_videoRecorderConfig.vSource,
        g_videoRecorderConfig.videoSourceId));
    EXPECT_EQ(MSERR_OK, recorderServer_->SetOutputFormat(g_videoRecorderConfig.outPutFormat));
    // In REC_CONFIGURED state, GetSurface should return nullptr
    OHOS::sptr<OHOS::Surface> surface = recorderServer_->GetSurface(g_videoRecorderConfig.videoSourceId);
    EXPECT_EQ(nullptr, surface);
    EXPECT_EQ(MSERR_OK, recorderServer_->Reset());
    EXPECT_EQ(MSERR_OK, recorderServer_->Release());
    close(g_videoRecorderConfig.outputFd);
}
} // namespace Media
} // namespace OHOS