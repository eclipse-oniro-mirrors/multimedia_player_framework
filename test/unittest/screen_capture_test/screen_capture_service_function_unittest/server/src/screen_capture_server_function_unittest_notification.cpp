/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "incall_observer.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "mock/mock_audio_capturer.h"
#include "screen_capture_server.h"
#include "screen_capture_server_function_unittest.h"
#include <algorithm>
#include <vector>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {

namespace {
class StateChangeRecorder : public ScreenCaptureCallBack {
public:
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override {}
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override {}
    void OnVideoBufferAvailable(bool isReady) override {}
    void OnStateChange(AVScreenCaptureStateCode stateCode) override
    {
        receivedStates_.push_back(stateCode);
    }
    void OnDisplaySelected(uint64_t displayId) override {}
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area) override {}
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override {}
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) override {}

    void Reset()
    {
        receivedStates_.clear();
    }
    bool Contains(AVScreenCaptureStateCode code) const
    {
        return std::find(receivedStates_.begin(), receivedStates_.end(), code) != receivedStates_.end();
    }

private:
    std::vector<AVScreenCaptureStateCode> receivedStates_;
};

void SetupMixModeSource(ScreenCaptureServer *server)
{
    server->audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, server);
    server->audioSource_->SetAudioRendererState(0);
}
} // namespace

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyMicOn_Success_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("notify_mic_on_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    auto recorder = std::make_shared<StateChangeRecorder>();
    screenCaptureServer_->cbProxy_->SetCallback(recorder);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ASSERT_EQ(screenCaptureServer_->SetMicrophoneEnabled(true), MSERR_OK);
    ASSERT_TRUE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNMUTED_BY_USER));
    ASSERT_FALSE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyMicOff_Success_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("notify_mic_off_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    auto recorder = std::make_shared<StateChangeRecorder>();
    screenCaptureServer_->cbProxy_->SetCallback(recorder);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    ASSERT_EQ(screenCaptureServer_->SetMicrophoneEnabled(true), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->SetMicrophoneEnabled(false), MSERR_OK);
    ASSERT_TRUE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_MUTED_BY_USER));
    ASSERT_FALSE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyTelCallStart_MicRunning_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("notify_tel_start_running_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    auto recorder = std::make_shared<StateChangeRecorder>();
    screenCaptureServer_->cbProxy_->SetCallback(recorder);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    SetupMixModeSource(screenCaptureServer_.get());
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->micAudioCapture_ = micWrapper;

    screenCaptureServer_->isInTelCall_.store(true);
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    ASSERT_TRUE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyTelCallStart_MicNotRunning_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("notify_tel_start_not_running_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    auto recorder = std::make_shared<StateChangeRecorder>();
    screenCaptureServer_->cbProxy_->SetCallback(recorder);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = true;
    SetupMixModeSource(screenCaptureServer_.get());
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_STOPED;
    screenCaptureServer_->micAudioCapture_ = micWrapper;

    screenCaptureServer_->isInTelCall_.store(true);
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    ASSERT_FALSE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyTelCallStart_MicSwitchOff_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo("notify_tel_start_switch_off_001.mp4", recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    auto recorder = std::make_shared<StateChangeRecorder>();
    screenCaptureServer_->cbProxy_->SetCallback(recorder);

    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isMicrophoneSwitchTurnOn_ = false;
    SetupMixModeSource(screenCaptureServer_.get());
    auto micWrapper = CreateTestWrapper(screenCaptureServer_->captureConfig_.audioInfo.micCapInfo, "OS_MicAudioCapture",
        false);
    micWrapper->captureState_ = AudioCapturerWrapperState::CAPTURER_RECORDING;
    screenCaptureServer_->micAudioCapture_ = micWrapper;

    screenCaptureServer_->isInTelCall_.store(true);
    ASSERT_EQ(screenCaptureServer_->SyncAudioCaptures(), MSERR_OK);
    ASSERT_FALSE(recorder->Contains(SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE));
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButtonResponse_001, TestSize.Level2)
{
    auto stateBefore = screenCaptureServer_->captureState_.load();
    screenCaptureServer_->HandleNotificationButtonResponse("unknown_button");
    EXPECT_EQ(screenCaptureServer_->captureState_.load(), stateBefore);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButtonResponse_002, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    screenCaptureServer_->HandleNotificationButtonResponse("stop");
    EXPECT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STOPPED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButtonResponse_003, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->HandleNotificationButtonResponse("pause");
    EXPECT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::CREATED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, HandleNotificationButtonResponse_004, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->HandleNotificationButtonResponse("resume");
    EXPECT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::CREATED);
}

} // namespace Media
} // namespace OHOS
