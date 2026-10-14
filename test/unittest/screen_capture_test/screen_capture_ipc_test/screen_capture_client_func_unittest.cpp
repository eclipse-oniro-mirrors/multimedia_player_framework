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

/* Test all ScreenCaptureClient methods with null proxy (error path coverage) */

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetCaptureMode_001, TestSize.Level2)
{
    ScreenCaptureClient client(nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client.SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN));
}

HWTEST_F(ScreenCaptureClientUnitTest, NullProxy_SetDataType_001, TestSize.Level2)

/* ==================== Success path tests with mock proxy ==================== */

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_ConfigMethods_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    ASSERT_NE(svc, nullptr);
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(MSERR_OK, client->SetCaptureMode(CaptureMode::CAPTURE_HOME_SCREEN));
    EXPECT_EQ(MSERR_OK, client->SetDataType(DataType::ORIGINAL_STREAM));
    RecorderInfo ri;
    EXPECT_EQ(MSERR_OK, client->SetRecorderInfo(ri));
    EXPECT_EQ(MSERR_OK, client->SetOutputFile(1));
    EXPECT_EQ(MSERR_OK, client->SetAndCheckLimit());
    AudioEncInfo aei;
    EXPECT_EQ(MSERR_OK, client->InitAudioEncInfo(aei));
    AudioCaptureInfo aci;
    EXPECT_EQ(MSERR_OK, client->InitAudioCap(aci));
    VideoEncInfo vei;
    EXPECT_EQ(MSERR_OK, client->InitVideoEncInfo(vei));
    VideoCaptureInfo vci;
    EXPECT_EQ(MSERR_OK, client->InitVideoCap(vci));
    client->Release();
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_CaptureMethods_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(MSERR_OK, client->StartScreenCapture(false));
    EXPECT_EQ(MSERR_OK, client->StartScreenCaptureWithSurface(nullptr, false));
    EXPECT_EQ(MSERR_OK, client->StopScreenCapture());
    EXPECT_EQ(MSERR_OK, client->PresentPicker());
    std::shared_ptr<AudioBuffer> ab;
    EXPECT_EQ(MSERR_OK, client->AcquireAudioBuffer(ab, AudioCaptureSourceType::MIC));
    sptr<OHOS::SurfaceBuffer> sb;
    int32_t fence = 0;
    int64_t ts = 0;
    OHOS::Rect damage;
    EXPECT_EQ(MSERR_OK, client->AcquireVideoBuffer(sb, fence, ts, damage));
    EXPECT_EQ(MSERR_OK, client->ReleaseAudioBuffer(AudioCaptureSourceType::MIC));
    EXPECT_EQ(MSERR_OK, client->ReleaseVideoBuffer());
    client->Release();
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_SettingsMethods_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(MSERR_OK, client->SetMicrophoneEnabled(true));
    EXPECT_EQ(MSERR_OK, client->SetCanvasRotation(true));
    EXPECT_EQ(MSERR_OK, client->ShowCursor(true));
    EXPECT_EQ(MSERR_OK, client->ResizeCanvas(720, 1280));
    EXPECT_EQ(MSERR_OK, client->SkipPrivacyMode({1, 2, 3}));
    EXPECT_EQ(MSERR_OK, client->SetMaxVideoFrameRate(30));
    ScreenCaptureContentFilter filter;
    EXPECT_EQ(MSERR_OK, client->ExcludeContent(filter));
    EXPECT_EQ(MSERR_OK, client->AddWhiteListWindows({1, 2, 3}));
    EXPECT_EQ(MSERR_OK, client->RemoveWhiteListWindows({1, 2, 3}));
    EXPECT_EQ(MSERR_OK, client->ExcludePickerWindows({1, 2, 3}));
    EXPECT_EQ(MSERR_OK, client->SetPickerMode(PickerMode::MIN_VAL));
    ScreenCaptureStrategy strategy;
    EXPECT_EQ(MSERR_OK, client->SetScreenCaptureStrategy(strategy));
    AVScreenCaptureHighlightConfig hlc;
    EXPECT_EQ(MSERR_OK, client->SetCaptureAreaHighlight(hlc));
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(MSERR_OK, client->SetCaptureArea(0, area));
    MultiDisplayCapability cap;
    EXPECT_EQ(MSERR_OK, client->GetMultiDisplayCaptureCapability({0, 1}, cap));
    EXPECT_EQ(MSERR_OK, client->PauseScreenCapture());
    EXPECT_EQ(MSERR_OK, client->ResumeScreenCapture());
    EXPECT_EQ(MSERR_OK, client->SetContentAutoRotation(true));
    client->Release();
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_SetCallback_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(MSERR_NO_MEMORY, client->SetScreenCaptureCallback(nullptr));
    auto cb = std::make_shared<TestScreenCaptureCallBack>();
    EXPECT_EQ(MSERR_OK, client->SetScreenCaptureCallback(cb));
    client->Release();
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_MediaServerDied_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    auto cb = std::make_shared<TestScreenCaptureCallBack>();
    EXPECT_EQ(MSERR_OK, client->SetScreenCaptureCallback(cb));
    client->MediaServerDied();
    EXPECT_EQ(MSERR_UNKNOWN, client->SetMicrophoneEnabled(true));
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_AddWatermark_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    std::shared_ptr<AVBuffer> buffer;
    int32_t count = 0;
    EXPECT_EQ(MSERR_OK, client->AddWatermark(buffer, 100, 100, count));
    client->Release();
}

HWTEST_F(ScreenCaptureClientUnitTest, MockProxy_UpdateSurface_001, TestSize.Level2)
{
    auto svc = sptr<TestScreenCaptureService>::MakeSptr();
    auto client = ScreenCaptureClient::Create(svc);
    ASSERT_NE(client, nullptr);
    EXPECT_EQ(MSERR_INVALID_VAL, client->UpdateSurface(nullptr));
    client->Release();
}

} // namespace ScreenCaptureIpcUT
} // namespace Media
} // namespace OHOS
