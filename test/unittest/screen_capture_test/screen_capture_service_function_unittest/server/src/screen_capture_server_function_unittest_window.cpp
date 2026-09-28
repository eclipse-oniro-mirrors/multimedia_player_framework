/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"
#include <sys/stat.h>
#include <unistd.h>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {
HWTEST_F(ScreenCaptureServerFunctionTest, StartPrivacyWindow_001, TestSize.Level2)
{
    ASSERT_EQ(screenCaptureServer_->StartPrivacyWindow(""), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_001, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"false\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_002, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_003, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_004, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"12345\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_005, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_006, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_007, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_008, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_009, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(""), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_010, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string
        choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0, \"isInnerAudioBoxSelected\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->isInnerAudioBoxSelected_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_011, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->isInnerAudioBoxSelected_ = true;
    std::string
        choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0, \"isInnerAudioBoxSelected\": \"false\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->isInnerAudioBoxSelected_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_013, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice = "{\"stopRecording\": \"true\","
                         "\"appPrivacyProtectionSwitch\": \"true\","
                         "\"systemPrivacyProtectionSwitch\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_014, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice = "{\"stopRecording\": \"false\","
                         "\"appPrivacyProtectionSwitch\": \"true\","
                         "\"systemPrivacyProtectionSwitch\": \"true\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_015, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice = "{\"stopRecording\": \"false\","
                         "\"appPrivacyProtectionSwitch\": \"true\","
                         "\"systemPrivacyProtectionSwitch\": \"false\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_016, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice = "{\"stopRecording\": \"false\","
                         "\"appPrivacyProtectionSwitch\": \"false\","
                         "\"systemPrivacyProtectionSwitch\": \"true\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_017, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice = "{\"stopRecording\": \"false\","
                         "\"appPrivacyProtectionSwitch\": \"false\","
                         "\"systemPrivacyProtectionSwitch\": \"false\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

// ===================== HandleRunningCase_Stream =====================

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_001, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": "true",
        "appPrivacyProtectionSwitch": "true",
        "systemPrivacyProtectionSwitch": "true"
    }
    )";
    int32_t result = screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(result, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_002, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": "false",
        "appPrivacyProtectionSwitch": "true",
        "systemPrivacyProtectionSwitch": "true"
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_003, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": "false",
        "appPrivacyProtectionSwitch": "true",
        "systemPrivacyProtectionSwitch": "false"
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_004, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": "false",
        "appPrivacyProtectionSwitch": "false",
        "systemPrivacyProtectionSwitch": "true"
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_005, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": "false",
        "appPrivacyProtectionSwitch": "false",
        "systemPrivacyProtectionSwitch": "false"
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_006, TestSize.Level2)
{
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": false,
        "appPrivacyProtectionSwitch": true,
        "systemPrivacyProtectionSwitch": false
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    EXPECT_EQ(screenCaptureServer_->appPrivacyProtectionSwitch_, true);
    EXPECT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_007, TestSize.Level2)
{
    screenCaptureServer_->appPrivacyProtectionSwitch_ = true;
    screenCaptureServer_->systemPrivacyProtectionSwitch_ = true;
    Json::Value root;
    std::string content = R"({"stopRecording": false})";
    screenCaptureServer_->HandleRunningCase(root, content);
    ASSERT_EQ(screenCaptureServer_->appPrivacyProtectionSwitch_, true);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Stream_008, TestSize.Level2)
{
    screenCaptureServer_->appPrivacyProtectionSwitch_ = true;
    screenCaptureServer_->systemPrivacyProtectionSwitch_ = true;
    Json::Value root;
    std::string content = R"(
    {
        "stopRecording": 0,
        "appPrivacyProtectionSwitch": 123,
        "systemPrivacyProtectionSwitch": null
    }
    )";
    screenCaptureServer_->HandleRunningCase(root, content);
    ASSERT_EQ(screenCaptureServer_->appPrivacyProtectionSwitch_, true);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_ParseFail, TestSize.Level2)
{
    Json::Value root;
    std::string content = "invalid json";
    ASSERT_EQ(screenCaptureServer_->HandleRunningCase(root, content), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_ParseNonObject, TestSize.Level2)
{
    Json::Value root;
    std::string content = "[]";
    ASSERT_EQ(screenCaptureServer_->HandleRunningCase(root, content), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_NoStopRecording, TestSize.Level2)
{
    screenCaptureServer_->appPrivacyProtectionSwitch_ = false;
    screenCaptureServer_->systemPrivacyProtectionSwitch_ = false;
    Json::Value root;
    std::string content = R"({"appPrivacyProtectionSwitch": "true", "systemPrivacyProtectionSwitch": "true"})";
    screenCaptureServer_->HandleRunningCase(root, content);
    ASSERT_EQ(screenCaptureServer_->appPrivacyProtectionSwitch_, true);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_PrivacyUnchanged, TestSize.Level2)
{
    screenCaptureServer_->appPrivacyProtectionSwitch_ = true;
    screenCaptureServer_->systemPrivacyProtectionSwitch_ = true;
    Json::Value root;
    std::string content =
        R"({"stopRecording": "false", "appPrivacyProtectionSwitch": "true", "systemPrivacyProtectionSwitch": "true"})";
    screenCaptureServer_->HandleRunningCase(root, content);
    ASSERT_EQ(screenCaptureServer_->appPrivacyProtectionSwitch_, true);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, true);
}

// ===================== HandleRunningCase_Picker =====================

// _005 does not use IsPickerPopUp/StartPicker, only tests choice→PrepareSelectWindow path.
HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_005, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->missionInfos_ = {{100, true}};
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 100}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_018, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = R"({"choice":"false"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"false\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_003, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->missionInfos_ = {{100, true}};
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 100}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_007, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 100}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_BoolChoice, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = R"({"choice": true, "displayId": 0, "missionId": 0})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isPresentPickerPopWindow_, false);
    screenCaptureServer_->StopScreenCapture();
    screenCaptureServer_->Release();
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleRunningCase_Picker_BoolDeny, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.strategy
        .pickerPopUp = AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    std::string choice = R"({"choice": false})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->isPresentPickerPopWindow_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_InvalidState, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    std::string content = R"({"choice": "true"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(content), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_ParseFail, TestSize.Level2)
{
    Json::Value root;
    std::string content = "invalid json";
    ASSERT_EQ(screenCaptureServer_->HandlePopupWindowCase(root, content), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_ParseNonObject, TestSize.Level2)
{
    Json::Value root;
    std::string content = "[]";
    ASSERT_EQ(screenCaptureServer_->HandlePopupWindowCase(root, content), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_NoCheckBox, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->checkBoxSelected_ = true;
    std::string choice = R"({"choice": "false"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->checkBoxSelected_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_NoChoice, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->checkBoxSelected_ = false;
    std::string choice = R"({"checkBoxSelected": "true"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->checkBoxSelected_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_DenyChoice, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = R"({"choice": "false", "checkBoxSelected": "true"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->checkBoxSelected_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandlePopupWindowCase_AudioBoxAbsent, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->isInnerAudioBoxSelected_ = true;
    std::string choice = R"({"choice": "false", "checkBoxSelected": "true"})";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(choice), MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->isInnerAudioBoxSelected_, true);
}

#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    bool isSkip = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_002, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isSystemRecorder_.store(true);
    bool isSkip = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_003, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    bool isSkip = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_004, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isSystemRecorder_.store(true);
    bool isSkip = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCapture_001, TestSize.Level2)
{
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isScreenCaptureAuthority_ = true;
    screenCaptureServer_->PostStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->isScreenCaptureAuthority_, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCapture_002, TestSize.Level2)
{
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isScreenCaptureAuthority_ = false;
    screenCaptureServer_->PostStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->isScreenCaptureAuthority_, false);
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_001, TestSize.Level2)
{
    Json::Value root;
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->displayIds_.size(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_002, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1, \"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1);
    EXPECT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_WINDOW);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_003, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : -1, \"missionId\" : -1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->displayIds_.size(), 0);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_004, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->missionInfos_[0].missionId, 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_005, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : \"hello\", \"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->missionInfos_[0].missionId, 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_006, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->displayIds_[0], 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_007, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1, \"missionId\" : \"hello\"}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->displayIds_[0], 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_008, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1, \"missionId\" : \"hello\"}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_EQ(screenCaptureServer_->captureConfig_.captureMode, CaptureMode::CAPTURE_SPECIFIED_SCREEN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, DestroyPopWindow_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    bool ret = screenCaptureServer_->DestroyPopWindow();
    ASSERT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, DestroyPopWindow_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    bool ret = screenCaptureServer_->DestroyPopWindow();
    ASSERT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, DestroyPopWindow_003, TestSize.Level2)
{
    screenCaptureServer_->connection_ = sptr<UIExtensionAbilityConnection>(
        new (std::nothrow) UIExtensionAbilityConnection(""));
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    bool ret = screenCaptureServer_->DestroyPopWindow();
    ASSERT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetAVScreenCaptureConfigurableParameters_001, TestSize.Level2)
{
    std::string resultStr;
    ASSERT_EQ(screenCaptureServer_->GetAVScreenCaptureConfigurableParameters(resultStr), MSERR_OK);
    ASSERT_EQ(resultStr, "{\"appPrivacyProtectionSwitch\":true,\"systemPrivacyProtectionSwitch\":true}\n");
}

#ifdef SUPPORT_PICKER_PHONE_PAD
HWTEST_F(ScreenCaptureServerFunctionTest, PresentPicker_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.audioInfo.innerCapInfo
        .state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_TRUE(screenCaptureServer_->ShouldShowShareSystemAudioBox());
    EXPECT_TRUE(screenCaptureServer_->ShouldShowSensitiveCheckBox());
    screenCaptureServer_->PresentPicker();
    EXPECT_FALSE(screenCaptureServer_->ShouldShowShareSystemAudioBox());
    EXPECT_FALSE(screenCaptureServer_->ShouldShowSensitiveCheckBox());
}
#endif

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SkipPrivacy_001, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {100};
    screenCaptureServer_->OnStartScreenCapture(false);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SkipPrivacy_002, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {100};
    screenCaptureServer_->OnStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SkipPrivacy_003, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {100};
    screenCaptureServer_->OnStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SkipPrivacy_004, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {};
    screenCaptureServer_->OnStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SkipPrivacy_005, TestSize.Level2)
{
    SetValidConfig();
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.videoInfo.videoCapInfo.taskIDs = {100, 200};
    screenCaptureServer_->OnStartScreenCapture(true);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTING);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_SkipPrivacy_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isSystemRecorder_.store(true);
    bool isSkipPrivacyWindow = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkipPrivacyWindow), MSERR_OK);
    ASSERT_EQ(isSkipPrivacyWindow, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_SkipPrivacy_002, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isSystemRecorder_.store(true);
    bool isSkipPrivacyWindow = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkipPrivacyWindow), MSERR_OK);
    ASSERT_EQ(isSkipPrivacyWindow, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StartScreenCaptureInner_SkipPrivacy_001, TestSize.Level2)
{
    SetValidConfig();
    config_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    config_.videoInfo.videoCapInfo.taskIDs = {100};
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->isSystemRecorder_.store(true);
    screenCaptureServer_->isScreenCaptureAuthority_ = true;
    ASSERT_EQ(screenCaptureServer_->StartScreenCaptureInner(true), MSERR_OK);
}

// ===================== UpdateMissionData (L689-727) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_BackgroundForeground_B2, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({10, true});
    std::vector<uint64_t> allIds;
    auto flags = screenCaptureServer_->UpdateMissionData(10, SessionState::STATE_BACKGROUND, allIds);
    EXPECT_EQ(flags & UPDATE_MIRROR, UPDATE_MIRROR);
    EXPECT_FALSE(screenCaptureServer_->missionInfos_[0].isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_DisconnectForeground_B2, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({10, true});
    std::vector<uint64_t> allIds;
    auto flags = screenCaptureServer_->UpdateMissionData(10, SessionState::STATE_DISCONNECT, allIds);
    EXPECT_EQ(flags & UPDATE_MIRROR, UPDATE_MIRROR);
    EXPECT_EQ(flags & REMOVE_WHITE_LIST, REMOVE_WHITE_LIST);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_DisconnectEmptyList_B2, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({10, false});
    std::vector<uint64_t> allIds;
    auto flags = screenCaptureServer_->UpdateMissionData(10, SessionState::STATE_DISCONNECT, allIds);
    EXPECT_EQ(flags & NOTIFY_UNAVAILABLE, NOTIFY_UNAVAILABLE);
    EXPECT_TRUE(screenCaptureServer_->missionInfos_.empty());
}

// ===================== AddWhiteListWindows / RemoveWhiteListWindows (L2963-2997) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AddWhiteListWindows_NotActive_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(screenCaptureServer_->AddWhiteListWindows(windows), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RemoveWhiteListWindows_NotActive_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(screenCaptureServer_->RemoveWhiteListWindows(windows), MSERR_INVALID_OPERATION);
}

// ===================== SetPickerMode (L3011-3024) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetPickerMode_InvalidMode_B2, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->SetPickerMode(static_cast<PickerMode>(-1)), MSERR_INVALID_VAL);
}

// ===================== SkipPrivacyMode / SkipPrivacyModeInner (L3439-3467) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SkipPrivacyMode_BeforeStart_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(screenCaptureServer_->SkipPrivacyMode(windows), MSERR_OK);
    EXPECT_EQ(screenCaptureServer_->skipPrivacyWindowIDsVec_.size(), 2u);
}

// ===================== DestroyPrivacySheet (L3705-3726) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, DestroyPrivacySheet_EmptyBundleName_B2, TestSize.Level2)
{
    constexpr char key[] = "const.multimedia.screencapture.screenrecorderbundlename";
    auto &params = GetScreenCaptureSystemParam();
    std::string saved = params[key];
    params[key] = "";
    screenCaptureServer_->callingLabel_ = "test";
    bool ret = screenCaptureServer_->DestroyPrivacySheet();
    EXPECT_FALSE(ret);
    params[key] = saved;
}

// ===================== AddWatermark (L4129-1148) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, AddWatermark_NotCreated_B2, TestSize.Level2)
{
    std::shared_ptr<AVBuffer> buffer = CreateWatermarkBuffer();
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    int32_t count = 0;
    EXPECT_EQ(screenCaptureServer_->AddWatermark(buffer, 200, 200, count), MSERR_INVALID_OPERATION_CREATE);
}

// ===================== SetScreenCaptureStrategy (L3856-3869) =====================

HWTEST_F(ScreenCaptureServerFunctionTest, SetScreenCaptureStrategy_AfterPopup_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ScreenCaptureStrategy strategy;
    strategy.enablePause = true;
    EXPECT_EQ(screenCaptureServer_->SetScreenCaptureStrategy(strategy), MSERR_INVALID_OPERATION_CREATE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, SetScreenCaptureStrategy_Success_B2, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    ScreenCaptureStrategy strategy;
    strategy.enablePause = true;
    strategy.keepCaptureDuringCall = true;
    EXPECT_EQ(screenCaptureServer_->SetScreenCaptureStrategy(strategy), MSERR_OK);
    EXPECT_TRUE(screenCaptureServer_->captureConfig_.strategy.enablePause);
}

// ===================== InitVideoCap_PickerModePopUp =====================

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    videoInfo.displayId = 0;
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), true);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    videoInfo.taskIDs.push_back(1001);
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), true);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    videoInfo.taskIDs.push_back(1001);
    videoInfo.taskIDs.push_back(1002);
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), false);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_004, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_INVAILD;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), false);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_005, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_HOME_SCREEN;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), false);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_006, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_APP;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef PC_STANDARD
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), false);
#endif
}

HWTEST_F(ScreenCaptureServerFunctionTest, InitVideoCap_PickerModePopUp_007, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    VideoCaptureInfo videoInfo;
    videoInfo.videoFrameWidth = 1920;
    videoInfo.videoFrameHeight = 1080;
    videoInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    ASSERT_EQ(screenCaptureServer_->InitVideoCap(videoInfo), MSERR_OK);
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    ASSERT_EQ(screenCaptureServer_->IsPickerPopUp(), false);
#endif
}
} // namespace Media
} // namespace OHOS
