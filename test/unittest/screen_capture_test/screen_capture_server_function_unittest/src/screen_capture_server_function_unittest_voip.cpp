/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include "image_source.h"
#include "image_type.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "param_wrapper.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_002, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_002.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(StartFileAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_003.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(false);
    ASSERT_EQ(screenCaptureServer_->GetMicWorkingState(), false);
    ASSERT_EQ(StartFileAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnVoIPStatusChanged_004, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("screen_capture_voip_004.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->SetMicrophoneEnabled(true);
    ASSERT_EQ(StartFileAudioCapture(), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = true;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    screenCaptureServer_->audioSource_->isInVoIPCall_ = false;
    ASSERT_EQ(screenCaptureServer_->OnVoIPStatusChanged(false), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->OnSpeakerAliveStatusChanged(true), MSERR_OK);
    sleep(RECORDER_TIME / 2);
    ASSERT_EQ(screenCaptureServer_->GetMicWorkingState(), true);
    ASSERT_EQ(screenCaptureServer_->StopScreenCapture(), MSERR_OK);
}
} // Media
} // OHOS