/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include "screen_capture_client.h"
#include "screen_capture_listener_stub.h"
#include "i_standard_screen_capture_service.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
namespace ScreenCaptureIpcUT {

class TestScreenCaptureService : public IStandardScreenCaptureService {
public:
    sptr<IRemoteObject> AsObject() override { return nullptr; }
    void Release() override {}
    int32_t DestroyStub() override { return MSERR_OK; }
    int32_t SetCaptureMode(CaptureMode captureMode) override { return MSERR_OK; }
    int32_t SetDataType(DataType dataType) override { return MSERR_OK; }
    int32_t SetRecorderInfo(RecorderInfo recorderInfo) override { return MSERR_OK; }
    int32_t SetOutputFile(int32_t fd) override { return MSERR_OK; }
    int32_t SetAndCheckLimit() override { return MSERR_OK; }
    int32_t SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo) override { return MSERR_OK; }
    int32_t InitAudioEncInfo(AudioEncInfo audioEncInfo) override { return MSERR_OK; }
    int32_t InitAudioCap(AudioCaptureInfo audioInfo) override { return MSERR_OK; }
    int32_t InitVideoEncInfo(VideoEncInfo videoEncInfo) override { return MSERR_OK; }
    int32_t InitVideoCap(VideoCaptureInfo videoInfo) override { return MSERR_OK; }
    int32_t StartScreenCapture(bool isPrivacyAuthorityEnabled = false) override { return MSERR_OK; }
    int32_t StartScreenCaptureWithSurface(sptr<Surface> surface,
        bool isPrivacyAuthorityEnabled = false) override { return MSERR_OK; }
    int32_t StopScreenCapture() override { return MSERR_OK; }
    int32_t PresentPicker() override { return MSERR_OK; }
    int32_t SetMicrophoneEnabled(bool isMicrophone) override { return MSERR_OK; }
    int32_t SetCanvasRotation(bool canvasRotation) override { return MSERR_OK; }
    int32_t SetContentAutoRotation(bool contentAutoRotation) override { return MSERR_OK; }
    int32_t ShowCursor(bool showCursor) override { return MSERR_OK; }
    int32_t ResizeCanvas(int32_t width, int32_t height) override { return MSERR_OK; }
    int32_t SkipPrivacyMode(const std::vector<uint64_t> &windowIDsVec) override { return MSERR_OK; }
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override { return MSERR_OK; }
    int32_t SetListenerObject(const sptr<IRemoteObject> &object) override { return MSERR_OK; }
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer,
        AudioCaptureSourceType type) override { return MSERR_OK; }
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer,
        int32_t &fence,
        int64_t &timestamp, OHOS::Rect &damage) override { return MSERR_OK; }
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override { return MSERR_OK; }
    int32_t ReleaseVideoBuffer() override { return MSERR_OK; }
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override { return MSERR_OK; }
    int32_t AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override { return MSERR_OK; }
    int32_t RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override { return MSERR_OK; }
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override { return MSERR_OK; }
    int32_t ExcludePickerWindows(const std::vector<int32_t> &windowIDsVec) override { return MSERR_OK; }
    int32_t SetPickerMode(PickerMode pickerMode) override { return MSERR_OK; }
    int32_t SetScreenCaptureStrategy(const ScreenCaptureStrategy &strategy) override { return MSERR_OK; }
    int32_t UpdateSurface(sptr<Surface> surface) override { return MSERR_OK; }
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area) override { return MSERR_OK; }
    int32_t GetMultiDisplayCaptureCapability(const std::vector<uint64_t> &displayIds,
        
        MultiDisplayCapability &capability) override { return MSERR_OK; }
    int32_t PauseScreenCapture() override { return MSERR_OK; }
    int32_t ResumeScreenCapture() override { return MSERR_OK; }
    int32_t AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer,
        int32_t width,
        int32_t height, int32_t &watermarkCount) override { return MSERR_OK; }
};

class TestScreenCaptureCallBack : public ScreenCaptureCallBack {
public:
    void OnError(ScreenCaptureErrorType errorType, int32_t errorCode) override {}
    void OnAudioBufferAvailable(bool isReady, AudioCaptureSourceType type) override {}
    void OnVideoBufferAvailable(bool isReady) override {}
    void OnStateChange(AVScreenCaptureStateCode stateCode) override {}
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area) override {}
    void OnDisplaySelected(uint64_t displayId) override {}
    void OnUserSelected(ScreenCaptureUserSelectionInfo selectionInfo) override {}
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect privacyProtect) override {}
};

class ScreenCaptureClientUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

/* Test all ScreenCaptureClient methods with null proxy (error path coverage) */

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetCaptureMode_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetDataType_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetDataType(DataType::ORIGINAL_STREAM));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetRecorderInfo_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    RecorderInfo info;
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetRecorderInfo(info));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetOutputFile_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetOutputFile(1));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetAndCheckLimit_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetAndCheckLimit());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_InitAudioEncInfo_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    AudioEncInfo info;
    EXPECT_EQ(MSERR_NO_MEMORY, client.InitAudioEncInfo(info));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_InitAudioCap_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    AudioCaptureInfo info;
    EXPECT_EQ(MSERR_NO_MEMORY, client.InitAudioCap(info));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_InitVideoEncInfo_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    VideoEncInfo info;
    EXPECT_EQ(MSERR_NO_MEMORY, client.InitVideoEncInfo(info));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_InitVideoCap_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    VideoCaptureInfo info;
    EXPECT_EQ(MSERR_NO_MEMORY, client.InitVideoCap(info));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_StartScreenCapture_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.StartScreenCapture(false));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_StopScreenCapture_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.StopScreenCapture());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_PresentPicker_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.PresentPicker());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_AcquireAudioBuffer_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    std::shared_ptr<AudioBuffer> audioBuffer;
    EXPECT_EQ(MSERR_NO_MEMORY,
        client.AcquireAudioBuffer(audioBuffer, AudioCaptureSourceType::MIC));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_AcquireVideoBuffer_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    sptr<OHOS::SurfaceBuffer> surfaceBuffer;
    int32_t fence = 0;
    int64_t timestamp = 0;
    OHOS::Rect damage;
    EXPECT_EQ(MSERR_NO_MEMORY,
        client.AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ReleaseAudioBuffer_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.ReleaseAudioBuffer(AudioCaptureSourceType::MIC));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ReleaseVideoBuffer_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.ReleaseVideoBuffer());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetMicrophoneEnabled_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_UNKNOWN, client.SetMicrophoneEnabled(true));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetCanvasRotation_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetCanvasRotation(true));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ShowCursor_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.ShowCursor(true));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ResizeCanvas_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.ResizeCanvas(720, 1280));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SkipPrivacyMode_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_UNKNOWN, client.SkipPrivacyMode({1, 2, 3}));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetMaxVideoFrameRate_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetMaxVideoFrameRate(30));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetScreenCaptureCallback_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetScreenCaptureCallback(nullptr));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ExcludeContent_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    ScreenCaptureContentFilter filter;
    EXPECT_EQ(MSERR_NO_MEMORY, client.ExcludeContent(filter));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_AddWhiteListWindows_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.AddWhiteListWindows({1, 2, 3}));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_RemoveWhiteListWindows_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.RemoveWhiteListWindows({1, 2, 3}));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ExcludePickerWindows_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_UNKNOWN, client.ExcludePickerWindows({1, 2, 3}));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetPickerMode_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_UNKNOWN, client.SetPickerMode(PickerMode::MIN_VAL));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetScreenCaptureStrategy_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    ScreenCaptureStrategy strategy;
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetScreenCaptureStrategy(strategy));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetCaptureAreaHighlight_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    AVScreenCaptureHighlightConfig config;
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetCaptureAreaHighlight(config));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetCaptureArea_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetCaptureArea(0, area));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_GetMultiDisplayCap_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    MultiDisplayCapability capability;
    EXPECT_EQ(MSERR_NO_MEMORY, client.GetMultiDisplayCaptureCapability({0, 1}, capability));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_PauseScreenCapture_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_SERVICE_DIED, client.PauseScreenCapture());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_ResumeScreenCapture_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_SERVICE_DIED, client.ResumeScreenCapture());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_CreateListenerObject_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.CreateListenerObject());
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_Release_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    client.Release();
    EXPECT_TRUE(true);
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_MediaServerDied_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    client.MediaServerDied();
    EXPECT_TRUE(true);
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetContentAutoRotation_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_SERVICE_DIED, client.SetContentAutoRotation(true));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_UpdateSurface_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.UpdateSurface(nullptr));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_AddWatermark_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    std::shared_ptr<AVBuffer> buffer;
    int32_t count = 0;
    EXPECT_EQ(MSERR_SERVICE_DIED, client.AddWatermark(buffer, 100, 100, count));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetAndCheckSaLimit_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    OHOS::AudioStandard::AppInfo appInfo;
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetAndCheckSaLimit(appInfo));
}

} // namespace ScreenCaptureIpcUT
} // namespace Media
} // namespace OHOS
