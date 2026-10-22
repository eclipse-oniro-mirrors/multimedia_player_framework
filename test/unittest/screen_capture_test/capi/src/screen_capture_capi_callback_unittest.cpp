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

#include <fcntl.h>
#include <iostream>
#include <string>
#include "media_errors.h"
#include "screen_capture_unit_test.h"
#include "native_avscreen_capture.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace testing::ext;
using namespace std;
using namespace OHOS::Media::ScreenCaptureTestParam;

namespace OHOS {
namespace Media {

/* ==================== Recording with data callback enabled ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_data_callback_001, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_data_callback_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_with_data_callback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_data_callback_002, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_data_callback_002 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_with_data_callback_002.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        true, true, true, true));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_data_callback_stream_001, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_data_callback_stream_001 before");
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== isStart checks: callbacks after Start ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_display_callback_after_start_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    auto displayCb = [](OH_AVScreenCapture *cap, uint64_t displayId, void *data) {
        (void)cap;
        (void)displayId;
        (void)data;
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetDisplayCallback(capture, displayCb, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_selection_callback_after_start_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    auto selCb = [](OH_AVScreenCapture *cap, OH_AVScreenCapture_UserSelectionInfo *sel, void *data) {
        (void)cap;
        (void)sel;
        (void)data;
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetSelectionCallback(capture, selCb, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

HWTEST_F(ScreenCaptureUnitTest, capi_privacy_callback_after_start_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    auto privCb = [](OH_AVScreenCapture *cap, OH_PrivacyProtectInfo *info, void *data) {
        (void)cap;
        (void)info;
        (void)data;
    };
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK,
        OH_AVScreenCapture_SetPrivacyProtectCallback(capture, privCb, nullptr));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Release edge cases ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_release_video_buffer_empty_queue_001, TestSize.Level2)
{
    OH_AVScreenCapture *capture = OH_AVScreenCapture_Create();
    ASSERT_NE(capture, nullptr);
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT,
        OH_AVScreenCapture_ReleaseVideoBuffer(capture));
    EXPECT_EQ(AV_SCREEN_CAPTURE_ERR_OK, OH_AVScreenCapture_Release(capture));
}

/* ==================== Recording with content changed callback ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_content_changed_callback_001, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_content_changed_callback_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_with_content_changed_callback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, false, true, true));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== Recording with display callback ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_display_callback_001, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_display_callback_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_with_display_callback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetDisplayCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== Recording with selection + privacy callback ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_with_selection_privacy_callback_001, TestSize.Level2)
{
    MEDIA_LOGI("capi_record_with_selection_privacy_callback_001 before");
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_with_selection_privacy_callback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetSelectionCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetPrivacyProtectCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== 5s recording with data callback to trigger buffer callbacks ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_data_cb_5s_all_playback_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_data_cb_5s_all_playback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_record_data_cb_5s_app_playback_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_data_cb_5s_app_playback_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_record_data_cb_5s_stream_001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_record_data_cb_5s_mic_only_001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = MIC
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    config_.audioInfo.innerCapInfo.audioSource = SOURCE_INVALID;
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== isStart=true: callbacks after Start ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_display_callback_after_start_real_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_display_callback_after_start_real_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, false, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetDisplayCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    EXPECT_NE(MSERR_OK, screenCapture_->SetDisplayCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_selection_callback_after_start_real_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_selection_callback_after_start_real_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetSelectionCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    EXPECT_NE(MSERR_OK, screenCapture_->SetSelectionCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

HWTEST_F(ScreenCaptureUnitTest, capi_privacy_callback_after_start_real_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_privacy_callback_after_start_real_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = APP_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetPrivacyProtectCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    EXPECT_NE(MSERR_OK, screenCapture_->SetPrivacyProtectCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== Release during active recording (StopCallback path) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_release_during_recording_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_release_during_recording_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        false, true, true, false));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== Recording with all callbacks enabled (error+data+state+content) ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_all_callbacks_5s_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("capi_record_all_callbacks_5s_001.mp4", recorderInfo);
    SetConfigFile(config_, recorderInfo);
    AudioCaptureInfo micCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = SOURCE_DEFAULT
    };
    config_.audioInfo.micCapInfo = micCapInfo;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_,
        true, true, true, true));
    EXPECT_EQ(MSERR_OK, screenCapture_->SetDisplayCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetSelectionCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->SetPrivacyProtectCallback());
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenRecording());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenRecording());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
}

/* ==================== Recording with only old-style callback (no data callback) 5s ==================== */

HWTEST_F(ScreenCaptureUnitTest, capi_record_old_style_cb_5s_001, TestSize.Level2)
{
    SetConfig(config_);
    config_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    AudioCaptureInfo innerCapInfo = {
        .audioSampleRate = 16000, .audioChannels = 2, .audioSource = ALL_PLAYBACK
    };
    config_.audioInfo.innerCapInfo = innerCapInfo;
    OpenFile("capi_record_old_style_cb_5s_001");
    aFlag = 1;
    vFlag = 1;
    screenCaptureCb_ = std::make_shared<ScreenCaptureUnitTestCallback>(screenCapture_, aFile, vFile, aFlag, vFlag);
    ASSERT_NE(nullptr, screenCaptureCb_);
    EXPECT_EQ(MSERR_OK, screenCapture_->SetScreenCaptureCallback(screenCaptureCb_));
    EXPECT_EQ(MSERR_OK, screenCapture_->Init(config_));
    EXPECT_EQ(MSERR_OK, screenCapture_->StartScreenCapture());
    sleep(RECORDER_TIME_5);
    EXPECT_EQ(MSERR_OK, screenCapture_->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, screenCapture_->Release());
    CloseFile();
}

} // namespace Media
} // namespace OHOS
