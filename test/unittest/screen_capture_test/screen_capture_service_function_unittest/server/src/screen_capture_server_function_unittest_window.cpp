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

#include <unistd.h>
#include <sys/stat.h>
#include "screen_capture_server_function_unittest.h"
#include "ui_extension_ability_connection.h"

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
HWTEST_F(ScreenCaptureServerFunctionTest, StartPrivacyWindow_001, TestSize.Level2)
{
    ASSERT_NE(screenCaptureServer_->StartPrivacyWindow(""), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"false\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = -1;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"12345\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = 10086;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": -1, \"missionId\": -1}";
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    std::string choice = "{\"choice\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    ASSERT_NE(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, ""), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->showShareSystemAudioBox_ = true;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0, \"isInnerAudioBoxSelected\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->showShareSystemAudioBox_ = true;
    screenCaptureServer_->isInnerAudioBoxSelected_ = true;
    std::string choice =
        "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0, \"isInnerAudioBoxSelected\": \"false\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->isInnerAudioBoxSelected_, false);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ReportAVScreenCaptureUserChoice_012, TestSize.Level2)
{
    SetInvalidConfig();
    config_.audioInfo.micCapInfo.audioSampleRate = 16000;
    config_.audioInfo.micCapInfo.audioChannels = 2;
    config_.audioInfo.micCapInfo.audioSource = AudioCaptureSourceType::SOURCE_DEFAULT;
    config_.audioInfo.innerCapInfo.audioSampleRate = 16000;
    config_.audioInfo.innerCapInfo.audioChannels = 2;
    config_.audioInfo.innerCapInfo.audioSource = AudioCaptureSourceType::ALL_PLAYBACK;
    ASSERT_EQ(InitStreamScreenCaptureServer(), MSERR_OK);
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"choice\": \"true\", \"displayId\": 0, \"missionId\": 0, \"isInnerAudioBoxSelected\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"stopRecording\": \"true\","
        "\"appPrivacyProtectionSwitch\": \"true\","
        "\"systemPrivacyProtectionSwitch\": \"true\"}";
    ASSERT_EQ(screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice), MSERR_OK);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"stopRecording\": \"false\","
        "\"appPrivacyProtectionSwitch\": \"true\","
        "\"systemPrivacyProtectionSwitch\": \"true\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"stopRecording\": \"false\","
        "\"appPrivacyProtectionSwitch\": \"true\","
        "\"systemPrivacyProtectionSwitch\": \"false\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"stopRecording\": \"false\","
        "\"appPrivacyProtectionSwitch\": \"false\","
        "\"systemPrivacyProtectionSwitch\": \"true\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice);
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
    int32_t sessionId = screenCaptureServer_->sessionId_;
    ASSERT_EQ(StartStreamAudioCapture(), MSERR_OK);
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->showShareSystemAudioBox_ = false;
    screenCaptureServer_->isInnerAudioBoxSelected_ = false;
    std::string choice =
        "{\"stopRecording\": \"false\","
        "\"appPrivacyProtectionSwitch\": \"false\","
        "\"systemPrivacyProtectionSwitch\": \"false\"}";
    screenCaptureServer_->ReportAVScreenCaptureUserChoice(sessionId, choice);
    ASSERT_EQ(screenCaptureServer_->systemPrivacyProtectionSwitch_, false);
}

#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    bool isSkip = false;
    ASSERT_NE(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_002, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
    bool isSkip = false;
    ASSERT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_003, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    bool isSkip = false;
    ASSERT_NE(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_004, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = ScreenCaptureServer::ROOT_UID + 1;
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->appName_ = ScreenRecorderBundleName;
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
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_002, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1, \"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_003, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : -1, \"missionId\" : -1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_004, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_005, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : \"hello\", \"missionId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_006, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareSelectWindow_007, TestSize.Level2)
{
    Json::Value root;
    const std::string rawString = "{\"displayId\" : 1, \"missionId\" : \"hello\"}";
    Json::Reader reader;
    reader.parse(rawString, root);
    screenCaptureServer_->PrepareSelectWindow(root);
    ASSERT_NE(screenCaptureServer_, nullptr);
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

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareUserSelectionInfo_001, TestSize.Level2)
{
    ScreenCaptureUserSelectionInfo selectionInfo;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->PrepareUserSelectionInfo(selectionInfo);
    ASSERT_EQ(selectionInfo.selectType, 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrepareUserSelectionInfo_002, TestSize.Level2)
{
    ScreenCaptureUserSelectionInfo selectionInfo;
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_SCREEN;
    screenCaptureServer_->displayIds_ = {1};
    screenCaptureServer_->PrepareUserSelectionInfo(selectionInfo);
    ASSERT_EQ(selectionInfo.displayIds.size(), 1);
    ASSERT_EQ(selectionInfo.displayIds.front(), 1);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrivateWindowListenerInScreenCapture_001, TestSize.Level2)
{
    screenCaptureServer_->RegisterPrivateWindowListener();
    screenCaptureServer_->displayListener_->OnPrivateWindow(true);
    ASSERT_NE(screenCaptureServer_->displayListener_, nullptr);
}

HWTEST_F(ScreenCaptureServerFunctionTest, PrivateWindowListenerInScreenCapture_002, TestSize.Level2)
{
    screenCaptureServer_->RegisterPrivateWindowListener();
    screenCaptureServer_->displayListener_->OnPrivateWindow(false);
    ASSERT_NE(screenCaptureServer_->displayListener_, nullptr);
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
    screenCaptureServer_->connection_ =
        sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(""));
    screenCaptureServer_->captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    bool ret = screenCaptureServer_->DestroyPopWindow();
    ASSERT_EQ(ret, true);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetDisplayIdOfWindows_001, TestSize.Level2)
{
    uint64_t defaultDisplayIdValue = 0;
    screenCaptureServer_->missionIds_ = {};
    ASSERT_EQ(screenCaptureServer_->GetDisplayIdOfWindows(defaultDisplayIdValue), defaultDisplayIdValue);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetDisplayIdOfWindows_002, TestSize.Level2)
{
    uint64_t defaultDisplayIdValue = 0;
    screenCaptureServer_->missionIds_ = {0};
    ASSERT_EQ(screenCaptureServer_->GetDisplayIdOfWindows(defaultDisplayIdValue), defaultDisplayIdValue);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetAVScreenCaptureConfigurableParameters_001, TestSize.Level2)
{
    int32_t sessionId = screenCaptureServer_->sessionId_;
    std::string resultStr;
    ASSERT_EQ(screenCaptureServer_->GetAVScreenCaptureConfigurableParameters(sessionId, resultStr), MSERR_OK);
    ASSERT_EQ(resultStr, "{\"appPrivacyProtectionSwitch\":true,\"systemPrivacyProtectionSwitch\":true}\n");
}
} // Media
} // OHOS