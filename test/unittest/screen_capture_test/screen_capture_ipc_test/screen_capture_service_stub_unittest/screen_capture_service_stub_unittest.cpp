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

#include "screen_capture_service_stub_unittest.h"
#include "media_errors.h"
#include "media_log.h"

using namespace OHOS;
using namespace testing::ext;
using namespace OHOS::Media;

namespace {
constexpr int MAX_WINDOWS_LEN = 1000;
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServiceStubTest"};
}

void ScreenCaptureServiceStubTest::SetUpTestCase(void)
{
}

void ScreenCaptureServiceStubTest::TearDownTestCase(void)
{
}

void ScreenCaptureServiceStubTest::SetUp(void)
{
    SetHapPermission();
}

void ScreenCaptureServiceStubTest::TearDown(void)
{
}

void ScreenCaptureServiceStubTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(info_, policy_);
    int ret = SetSelfTokenID(tokenIdEx.tokenIDEx);
    if (ret != 0) {
        MEDIA_LOGE("Set hap token failed, err: %{public}d", ret);
    }
}

/**
 * @tc.name  : ~ScreenCaptureServiceStub
 * @tc.number: ~ScreenCaptureServiceStub
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, CreateReleaseStubObject_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    screenCaptureServiceStub->screenCaptureServer_ = nullptr;
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : DestoyServiceStub
 * @tc.number: DestoyServiceStub
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, DestoyServiceStub_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    screenCaptureServiceStub->screenCaptureServer_ = nullptr;
    int ret = screenCaptureServiceStub->DestroyStub();
    EXPECT_EQ(ret, 0);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : errorCode_001
 * @tc.number: errorCode_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, errorCode_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int ret = screenCaptureServiceStub->OnRemoteRequest(-1, data, reply, option);
    EXPECT_EQ(ret, MSERR_INVALID_OPERATION);
    screenCaptureServiceStub = nullptr;
}


/**
 * @tc.name  : errorCode_002
 * @tc.number: errorCode_002
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, errorCode_002, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    int ret = screenCaptureServiceStub->OnRemoteRequest(-1, data, reply, option);
    EXPECT_NE(ret, MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetCaptureMode_001
 * @tc.number: SetCaptureMode_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetCaptureMode_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_CAPTURE_MODE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetListenerObject_001
 * @tc.number: SetListenerObject_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetListenerObject_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_LISTENER_OBJ, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_NO_MEMORY);
    ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::RELEASE, data, reply, option);
    screenCaptureServiceStub = nullptr;
}


/**
 * @tc.name  : SetMicrophoneEnabled_001
 * @tc.number: SetMicrophoneEnabled_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetMicrophoneEnabled_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    data.WriteBool(true);
    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_MIC_ENABLE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::RELEASE, data, reply, option);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetCanvasRotation_001
 * @tc.number: SetCanvasRotation_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetCanvasRotation_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    data.WriteBool(true);
    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_SCREEN_ROTATION, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : ResizeCanvas_001
 * @tc.number: ResizeCanvas_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, ResizeCanvas_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    int32_t width = 1080;
    int32_t height = 1920;
    token = data.WriteInt32(width) && data.WriteInt32(height);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::RESIZE_CANVAS, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_OPERATION);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SkipPrivacyMode_001
 * @tc.number: SkipPrivacyMode_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SkipPrivacyMode_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    std::vector<uint64_t> windowIDsVec = {1};
    token = data.WriteInt32(static_cast<int32_t>(windowIDsVec.size()));
    ASSERT_EQ(token, true);
    for (size_t i = 0; i < windowIDsVec.size(); i++) {
        token = data.WriteUint64(static_cast<uint64_t>(windowIDsVec[i]));
        ASSERT_EQ(token, true);
    }

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SKIP_PRIVACY, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetMaxVideoFrameRate_001
 * @tc.number: SetMaxVideoFrameRate_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetMaxVideoFrameRate_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    int32_t frameRate = 30;
    token = data.WriteInt32(frameRate);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_MAX_FRAME_RATE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_OPERATION);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetDataType_001
 * @tc.number: SetDataType_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetDataType_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    int32_t dataType = 0;
    token = data.WriteInt32(dataType);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_DATA_TYPE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetRecorderInfo_001
 * @tc.number: SetRecorderInfo_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetRecorderInfo_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    RecorderInfo recorderInfo = {.url = "url", .fileFormat = "mp4"};
    token = data.WriteString(recorderInfo.url) && data.WriteString(recorderInfo.fileFormat);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_RECORDER_INFO, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : SetOutputFile_001
 * @tc.number: SetOutputFile_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, SetOutputFile_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::SET_OUTPUT_FILE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : InitAudioEncInfo_001
 * @tc.number: InitAudioEncInfo_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, InitAudioEncInfo_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    AudioEncInfo audioEncInfo = {
        .audioBitrate = 48000,
        .audioCodecformat = AudioCodecFormat::AAC_LC
    };
    token = data.WriteInt32(audioEncInfo.audioBitrate) && data.WriteInt32(audioEncInfo.audioCodecformat);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::INIT_AUDIO_ENC_INFO, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : InitAudioCap_001
 * @tc.number: InitAudioCap_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, InitAudioCap_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    AudioCaptureInfo audioInfo = {
        .audioSampleRate = 0,
        .audioChannels = 0,
        .audioSource = SOURCE_DEFAULT
    };
    token = data.WriteInt32(audioInfo.audioSampleRate) && data.WriteInt32(audioInfo.audioChannels)
        && data.WriteInt32(audioInfo.audioSource);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::INIT_AUDIO_CAP, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : InitVideoEncInfo_001
 * @tc.number: InitVideoEncInfo_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, InitVideoEncInfo_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    VideoEncInfo videoEncInfo = {
        .videoCodec = VideoCodecFormat::H264,
        .videoBitrate = 2000000,
        .videoFrameRate = 30
    };
    token = data.WriteInt32(videoEncInfo.videoCodec) && data.WriteInt32(videoEncInfo.videoBitrate) &&
            data.WriteInt32(videoEncInfo.videoFrameRate);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::INIT_VIDEO_ENC_INFO, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : InitVideoCap_001
 * @tc.number: InitVideoCap_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, InitVideoCap_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    VideoCaptureInfo videoInfo = {
        .videoFrameWidth = 720,
        .videoFrameHeight = 1280,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA
    };
    token = data.WriteUint64(videoInfo.displayId) && data.WriteInt32(videoInfo.taskIDs.size());
    ASSERT_EQ(token, true);
    int count = 0;
    for (int32_t taskID : videoInfo.taskIDs) {
        token = data.WriteInt32(taskID);
        ASSERT_EQ(token, true);
        count++;
        if (count >= MAX_WINDOWS_LEN) {
            break;
        }
    }
    token = data.WriteInt32(videoInfo.videoFrameWidth) && data.WriteInt32(videoInfo.videoFrameHeight) &&
            data.WriteInt32(videoInfo.videoSource);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::INIT_VIDEO_CAP, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : StartScreenCapture_001
 * @tc.number: StartScreenCapture_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, StartScreenCapture_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    bool isPrivacyAuthorityEnabled = true;
    token = data.WriteBool(isPrivacyAuthorityEnabled);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::START_SCREEN_CAPTURE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_VAL);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : StartScreenCaptureWithSurface_001
 * @tc.number: StartScreenCaptureWithSurface_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, StartScreenCaptureWithSurface_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    bool isPrivacyAuthorityEnabled = true;
    token = data.WriteBool(isPrivacyAuthorityEnabled);
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::START_SCREEN_CAPTURE_WITH_SURFACE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : StartScreenCaptureWithSurface_001
 * @tc.number: StartScreenCaptureWithSurface_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, StopScreenCapture_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::STOP_SCREEN_CAPTURE, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_OK);
    screenCaptureServiceStub = nullptr;
}

/**
 * @tc.name  : AcquireAudioBuffer_001
 * @tc.number: AcquireAudioBuffer_001
 * @tc.desc  : FUNC
 */
HWTEST_F(ScreenCaptureServiceStubTest, AcquireAudioBuffer_001, TestSize.Level1)
{
    sptr<ScreenCaptureServiceStub> screenCaptureServiceStub = ScreenCaptureServiceStub::Create();
    ASSERT_NE(screenCaptureServiceStub, nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    bool token = data.WriteInterfaceToken(screenCaptureServiceStub->GetDescriptor());
    ASSERT_EQ(token, true);
    AudioCaptureSourceType type = AudioCaptureSourceType::MIC;
    token = data.WriteInt32(type);

    int ret = screenCaptureServiceStub->OnRemoteRequest(
            IStandardScreenCaptureService::ACQUIRE_AUDIO_BUF, data, reply, option);
    EXPECT_EQ(ret, MSERR_OK);
    EXPECT_EQ(reply.ReadInt32(), MSERR_INVALID_OPERATION);
    screenCaptureServiceStub = nullptr;
}