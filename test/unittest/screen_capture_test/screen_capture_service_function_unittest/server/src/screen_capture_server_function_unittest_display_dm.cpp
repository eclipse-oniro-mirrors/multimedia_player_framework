/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "media_errors.h"
#include "media_utils.h"
#include "mock/mock_display_objects.h"
#include "mock/mock_media_utils.h"
#include "mock/mock_recorder_service.h"
#include "mock/mock_screen_capture_service_providers.h"
#include "mock/mock_screen_display_manager.h"
#include "screen_capture_server_function_unittest.h"
#include "screen_capture_server_manager.h"
#include <gtest/gtest.h>
#include <unistd.h>

using ::testing::_;
using ::testing::ByRef;
using ::testing::Return;
using namespace testing::ext;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {

namespace {
constexpr ScreenId TEST_SCREEN_ID = 100;
constexpr ScreenId TEST_VIRTUAL_SCREEN_ID = 200;
constexpr ScreenId TEST_MAIN_SCREEN_ID = 300;
constexpr int32_t TEST_DISPLAY_WIDTH = 720;
constexpr int32_t TEST_DISPLAY_HEIGHT = 1280;

void SetupRecorderDefaultsDm(MockRecorderService &m)
{
    ON_CALL(m, SetVideoSource(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetOutputFormat(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioEncoder(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioSampleRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioChannels(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetAudioEncodingBitRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEncoder(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoSize(_, _, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoFrameRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEncodingBitRate(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetVideoEnableBFrame(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetOutputFile(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, SetStabilizationMode(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Prepare()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, GetSurface(_)).WillByDefault(Return(OHOS::Surface::CreateSurfaceAsConsumer()));
    ON_CALL(m, SetAudioDataSource(_, _)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Start()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Stop(_)).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Release()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Pause()).WillByDefault(Return(MSERR_OK));
    ON_CALL(m, Resume()).WillByDefault(Return(MSERR_OK));
}

void SetupCreateVirtualScreenFlow(MockScreenManagerFlowActions &sm, MockDisplayManagerFlowActions &dm)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(dm, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(dm, GetDisplayById(_)).WillByDefault(Return(display));
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(sm, CreateVirtualScreen(_)).WillByDefault(Return(TEST_VIRTUAL_SCREEN_ID));
    ON_CALL(sm, SetVirtualScreenAutoRotation(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(sm, SetScreenSkipProtectedWindow(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(sm, SetScreenPrivacyWindowTagSwitch(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(sm, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(sm, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(sm, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(sm, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(dm, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
}
} // namespace

// Self-contained fixture: constructs a ScreenCaptureServer backed by the mock
// providers and wires the display/screen *flow* overrides
// (MockScreenManagerFlowActions / MockDisplayManagerFlowActions) so the
// link-time-overridden libdm methods dispatch to gmock expectations instead of
// the (unavailable in-test) display service. The main test binary is untouched
// — these overrides live only in this target.
class ScreenCaptureServerDisplayDmTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;
    void SetHapPermission();
    void BuildHomeScreenFileConfig();

protected:
    ScreenCaptureServerPtr server_;
    // Order matters: flow mocks must outlive the server (their `current`
    // pointers are read while the server's display path runs).
    std::unique_ptr<MockScreenManagerFlowActions> smFlow_;
    std::unique_ptr<MockDisplayManagerFlowActions> dmFlow_;
    AVScreenCaptureConfig config_;

private:
    Security::AccessToken::HapInfoParams hapInfo_ = {.userID = 100,
        .bundleName = "com.ohos.test.screencapturetdd",
        .instIndex = 0,
        .appIDDesc = "com.ohos.test.screencapturetdd",
        .isSystemApp = true};
    // clang-format off
    Security::AccessToken::HapPolicyParams hapPolicy_ = {
        .apl = Security::AccessToken::APL_SYSTEM_BASIC,
        .domain = "test.domain.screencapturetdd",
        .permList = {},
        .permStateList = {
            { .permissionName = "ohos.permission.MICROPHONE", .isGeneral = true,
              .resDeviceID = { "local" },
              .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
              .grantFlags = { 1 } },
            { .permissionName = "ohos.permission.READ_MEDIA", .isGeneral = true,
              .resDeviceID = { "local" },
              .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
              .grantFlags = { 1 } },
            { .permissionName = "ohos.permission.WRITE_MEDIA", .isGeneral = true,
              .resDeviceID = { "local" },
              .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
              .grantFlags = { 1 } },
            { .permissionName = "ohos.permission.CAPTURE_SCREEN", .isGeneral = true,
              .resDeviceID = { "local" },
              .grantStatus = { Security::AccessToken::PermissionState::PERMISSION_GRANTED },
              .grantFlags = { 1 } },
        }
    };
    // clang-format on
};

void ScreenCaptureServerDisplayDmTest::SetHapPermission()
{
    Security::AccessToken::AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = Security::AccessToken::AccessTokenKit::AllocHapToken(hapInfo_, hapPolicy_);
    (void)SetSelfTokenID(tokenIdEx.tokenIDEx);
}

void ScreenCaptureServerDisplayDmTest::SetUp()
{
    ON_CALL(GetMockMediaUtils(), IsSACalling()).WillByDefault(Return(false));
    SetHapPermission();
    server_ = MakeScreenCaptureServer();
    ASSERT_NE(server_, nullptr);
    // providers_ = mock providers (CreateRecorder stays real; tests that need a
    // recorder inject MockRecorderService directly into server_->recorder_).
    auto mockProviders = CreateMockProviders();
    server_->providers_ = std::move(mockProviders);
    server_->listenerManager_->providers_ = server_->providers_.get();
    sptr<IStandardScreenCaptureListener> listener = new StandardScreenCaptureServerUnittestCallback();
    server_->cbProxy_->SetCallback(std::make_shared<ScreenCaptureListenerCallback>(listener));

    smFlow_ = std::make_unique<MockScreenManagerFlowActions>();
    dmFlow_ = std::make_unique<MockDisplayManagerFlowActions>();
}

void ScreenCaptureServerDisplayDmTest::TearDown()
{
    smFlow_.reset();
    dmFlow_.reset();
    if (server_) {
        server_->Release();
        server_ = nullptr;
    }
}

void ScreenCaptureServerDisplayDmTest::BuildHomeScreenFileConfig()
{
    AudioCaptureInfo micCapinfo = {.audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::SOURCE_DEFAULT};
    AudioCaptureInfo innerCapInfo = {.audioSampleRate = 16000,
        .audioChannels = 2,
        .audioSource = AudioCaptureSourceType::ALL_PLAYBACK};
    VideoCaptureInfo videoCap = {.videoFrameWidth = TEST_DISPLAY_WIDTH,
        .videoFrameHeight = TEST_DISPLAY_HEIGHT,
        .videoSource = VIDEO_SOURCE_SURFACE_RGBA};
    VideoEncInfo videoEnc = {.videoCodec = VideoCodecFormat::H264, .videoBitrate = 2000000, .videoFrameRate = 30};
    AudioInfo audioInfo = {.micCapInfo = micCapinfo, .innerCapInfo = innerCapInfo};
    VideoInfo videoInfo = {.videoCapInfo = videoCap, .videoEncInfo = videoEnc};
    config_ = {.captureMode = CAPTURE_HOME_SCREEN,
        .dataType = DataType::CAPTURE_FILE,
        .audioInfo = audioInfo,
        .videoInfo = videoInfo};
}

// ---- PoC: GetDefaultDisplaySync non-null + Display::GetScreenId ----
// GetDisplayIdOfWindows returns defaultDisplay->GetScreenId() when missionInfos_
// is empty (line 2599-2601). Previously unreachable (display null in test env).
HWTEST_F(ScreenCaptureServerDisplayDmTest, GetDisplayIdOfWindows_DefaultDisplayOk_PoC, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    server_->missionInfos_.clear();
    EXPECT_EQ(server_->GetDisplayIdOfWindows(), TEST_SCREEN_ID);
}

// ---- GetDefaultDisplaySync non-null + GetDisplayById non-null + MakeMirror ----
// SetupVirtualScreenMirror (CAPTURE_HOME_SCREEN) success path (L2670-2705).
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_HomeScreen_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_OK);
    ASSERT_FALSE(server_->sourceDisplayIds_.empty());
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

// ---- CAPTURE_SPECIFIED_WINDOW, displayIds_ empty -> uses default display ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_SpecifiedWindow_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_SPECIFIED_WINDOW;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_.clear();
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_OK);
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

// ---- CAPTURE_SPECIFIED_SCREEN: GetAllDisplayIds non-empty, MakeMirror ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_SpecifiedScreen_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    std::vector<DisplayId> allIds = {TEST_SCREEN_ID};
    ON_CALL(*dmFlow_, GetAllDisplayIds(_)).WillByDefault(Return(allIds));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_SPECIFIED_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_SCREEN_ID};
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_OK);
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

// ---- MakeVirtualScreenMirror (non-region) -> SetupVirtualScreenMirror ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenMirror_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isRegionCapture_.store(false);
    server_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(server_->MakeVirtualScreenMirror(), MSERR_OK);
}

// ---- MakeVirtualScreenExtended success: GetDisplayById + Convert + SetMulti ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_Success, TestSize.Level2)
{
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(true));
    ON_CALL(*smFlow_, SetMultiScreenMode(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetMultiScreenRelativePosition(_, _)).WillByDefault(Return(DMError::DM_OK));

    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_OK);
    ASSERT_FALSE(server_->sourceDisplayIds_.empty());
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_MAIN_SCREEN_ID);
}

// ---- PrepareVirtualScreenMirror success (mirror branch): GetScreenById non-null ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, PrepareVirtualScreenMirror_Mirror_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    // SkipPrivacyModeInner -> SetVirtualScreenSecurityExemption
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->canvasRotation_ = false;
    server_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(server_->PrepareVirtualScreenMirror(), MSERR_OK);
}

// ---- PrepareVirtualScreenMirror success (extended branch) ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, PrepareVirtualScreenMirror_Extended_Success, TestSize.Level2)
{
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(true));
    ON_CALL(*smFlow_, SetMultiScreenMode(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetMultiScreenRelativePosition(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->captureConfig_.captureMode = CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    server_->canvasRotation_ = false;
    EXPECT_EQ(server_->PrepareVirtualScreenMirror(), MSERR_OK);
}

// ---- ChangeMirrorScreen success: StopMirror + CreateMirror(->MakeMirror) ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, ChangeMirrorScreen_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, StopMirror(_)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_SCREEN_ID};
    server_->sourceDisplayIds_.clear();
    server_->captureState_ = AVScreenCaptureState::CREATED;
    server_->ChangeMirrorScreen();
    ASSERT_FALSE(server_->sourceDisplayIds_.empty());
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

// ---- CreateVirtualScreen success (file/home): full CreateVirtualScreen impl ----
// Covers CreateVirtualScreen(ScreenManager) valid id -> GetDefaultDisplaySync
// non-null -> PrepareVirtualScreenMirror -> GetScreenById non-null -> MakeMirror.
HWTEST_F(ScreenCaptureServerDisplayDmTest, CreateVirtualScreen_FileHome_Success, TestSize.Level2)
{
    BuildHomeScreenFileConfig();
    server_->captureConfig_ = config_;
    server_->showCursor_ = true; // skip ShowCursorInner
    server_->canvasRotation_ = false;

    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, CreateVirtualScreen(_)).WillByDefault(Return(TEST_VIRTUAL_SCREEN_ID));
    ON_CALL(*smFlow_, SetVirtualScreenAutoRotation(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenSkipProtectedWindow(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenPrivacyWindowTagSwitch(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));

    sptr<OHOS::Surface> consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(consumer, nullptr);
    EXPECT_EQ(server_->CreateVirtualScreen(consumer), MSERR_OK);
    EXPECT_TRUE(server_->isConsumerStart_);
}

// ---- DestroyVirtualScreen success: isConsumerStart_ true -> StopMirror+Destroy ----
HWTEST_F(ScreenCaptureServerDisplayDmTest, DestroyVirtualScreen_Success, TestSize.Level2)
{
    ON_CALL(*smFlow_, StopMirror(_)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, DestroyVirtualScreen(_, _)).WillByDefault(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isConsumerStart_ = true;
    server_->DestroyVirtualScreen();
    EXPECT_EQ(server_->virtualScreenId_, SCREEN_ID_INVALID);
    EXPECT_FALSE(server_->isConsumerStart_);
}

// ===================== error paths within display functions =====================

// SetupVirtualScreenMirror: GetDefaultDisplaySync null -> MSERR_UNKNOWN (L2673)
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_DefaultDisplayNull, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(sptr<Rosen::Display>(nullptr)));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_UNKNOWN);
}

// SetupVirtualScreenMirror: CreateMirror(MakeMirror) fails -> MSERR_UNKNOWN (L2698)
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_MakeMirrorFail, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_UNKNOWN);
}

// SetupVirtualScreenMirror SPECIFIED_SCREEN: allDisplayIds empty -> MSERR_UNKNOWN (L2684)
HWTEST_F(ScreenCaptureServerDisplayDmTest, SetupVirtualScreenMirror_SpecifiedScreen_AllIdsEmpty, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetAllDisplayIds(_)).WillByDefault(Return(std::vector<Rosen::DisplayId>{}));
    server_->captureConfig_.captureMode = CAPTURE_SPECIFIED_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_SCREEN_ID};
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_UNKNOWN);
}

// MakeVirtualScreenExtended: GetDisplayById null -> MSERR_INVALID_VAL (L2730)
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_DisplayNull, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(sptr<Rosen::Display>(nullptr)));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_INVALID_VAL);
}

// MakeVirtualScreenExtended: ConvertScreenIdToRsScreenId false -> MSERR_UNKNOWN (L2735)
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_ConvertFail, TestSize.Level2)
{
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(false));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_UNKNOWN);
}

// MakeVirtualScreenExtended: SetMultiScreenMode fails -> MSERR_UNKNOWN (L2739)
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_SetMultiScreenModeFail, TestSize.Level2)
{
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(true));
    ON_CALL(*smFlow_, SetMultiScreenMode(_, _, _)).WillByDefault(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_UNKNOWN);
}

// MakeVirtualScreenExtended: SetMultiScreenRelativePosition fails -> MSERR_UNKNOWN (L2744)
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_SetRelativePositionFail, TestSize.Level2)
{
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(true));
    ON_CALL(*smFlow_, SetMultiScreenMode(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetMultiScreenRelativePosition(_, _)).WillByDefault(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_UNKNOWN);
}

// MakeVirtualScreenExtended: displayIds_ empty -> MSERR_INVALID_VAL (L2727)
HWTEST_F(ScreenCaptureServerDisplayDmTest, MakeVirtualScreenExtended_DisplayIdsEmpty, TestSize.Level2)
{
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_.clear();
    EXPECT_EQ(server_->MakeVirtualScreenExtended(), MSERR_INVALID_VAL);
}

// ===================== StartScreenCaptureFile (L1412-1443) =====================

// Full success path: InitRecorder (INNER_MODE) -> SyncAudioCaptures -> Start -> CreateVirtualScreen
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartScreenCaptureFile_Success_InnerMode, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaultsDm(*mock);
    server_->recorder_ = mock;
    server_->outputFd_ = 1;
    server_->fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    server_->isMicrophoneSwitchTurnOn_ = false;
    server_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->captureConfig_.audioInfo.innerCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->captureConfig_.audioInfo.micCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    server_->captureConfig_.videoInfo.videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->captureConfig_.videoInfo.videoCapInfo.videoSource = VIDEO_SOURCE_SURFACE_RGBA;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = TEST_DISPLAY_WIDTH;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = TEST_DISPLAY_HEIGHT;
    server_->showCursor_ = true;
    SetupCreateVirtualScreenFlow(*smFlow_, *dmFlow_);
    EXPECT_EQ(server_->StartScreenCaptureFile(), MSERR_OK);
    EXPECT_TRUE(server_->isConsumerStart_);
    server_->recorder_ = nullptr;
}

// InitRecorder fails (GetSurface null) -> recorder released, returns GETSURFACE
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartScreenCaptureFile_InitRecorderFail_GetSurface, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaultsDm(*mock);
    EXPECT_CALL(*mock, GetSurface(_)).WillOnce(Return(nullptr));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    server_->recorder_ = mock;
    server_->outputFd_ = 1;
    server_->fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    server_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    server_->captureConfig_.audioInfo.innerCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->captureConfig_.audioInfo.micCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    server_->captureConfig_.videoInfo.videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_EQ(server_->StartScreenCaptureFile(), MSERR_UNKNOWN_RECORDER_GETSURFACE);
    EXPECT_EQ(server_->recorder_, nullptr);
}

// recorder->Start fails -> ON_SCOPE_EXIT releases recorder, returns error
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartScreenCaptureFile_RecorderStartFail, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaultsDm(*mock);
    ON_CALL(*mock, Start()).WillByDefault(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    server_->recorder_ = mock;
    server_->outputFd_ = 1;
    server_->fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    server_->isMicrophoneSwitchTurnOn_ = false;
    server_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    server_->captureConfig_.audioInfo.innerCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->captureConfig_.audioInfo.micCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    server_->captureConfig_.videoInfo.videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    EXPECT_EQ(server_->StartScreenCaptureFile(), MSERR_UNKNOWN);
    EXPECT_EQ(server_->recorder_, nullptr);
}

// CreateVirtualScreen fails (MakeMirror error) -> returns MSERR_UNKNOWN_MAKE_MIRROR
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartScreenCaptureFile_CreateVirtualScreenFail, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    SetupRecorderDefaultsDm(*mock);
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    server_->recorder_ = mock;
    server_->outputFd_ = 1;
    server_->fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    server_->isMicrophoneSwitchTurnOn_ = false;
    server_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    server_->captureConfig_.audioInfo.innerCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->captureConfig_.audioInfo.micCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    server_->captureConfig_.videoInfo.videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_VALID;
    server_->showCursor_ = true;
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*smFlow_, CreateVirtualScreen(_)).WillByDefault(Return(TEST_VIRTUAL_SCREEN_ID));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    EXPECT_EQ(server_->StartScreenCaptureFile(), MSERR_UNKNOWN_MAKE_MIRROR);
    EXPECT_EQ(server_->recorder_, nullptr);
}

// ===================== StartStreamHomeVideoCapture (L2440-2489) =====================

// surface mode: isSurfaceMode_ true -> CreateVirtualScreen(surface_) success
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartStreamHomeVideoCapture_SurfaceMode_Success, TestSize.Level2)
{
    server_->isSurfaceMode_ = true;
    server_->surface_ = OHOS::Surface::CreateSurfaceAsConsumer();
    ASSERT_NE(server_->surface_, nullptr);
    server_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = TEST_DISPLAY_WIDTH;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = TEST_DISPLAY_HEIGHT;
    server_->showCursor_ = true;
    SetupCreateVirtualScreenFlow(*smFlow_, *dmFlow_);
    EXPECT_EQ(server_->StartStreamHomeVideoCapture(), MSERR_OK);
    server_->surface_ = nullptr;
}

// VALIDATION_IGNORE -> StartStreamVideoCapture returns OK without invoking home video
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_StartStreamVideoCapture_VideoIgnore_ReturnsOk, TestSize.Level2)
{
    server_->captureConfig_.videoInfo.videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
    EXPECT_EQ(server_->StartStreamVideoCapture(), MSERR_OK);
}

// ===================== CreateVirtualScreen / PrepareVirtualScreenMirror (L2502-2588) =====================

// GetDefaultDisplaySync null -> density skipped at L2509, but SetupVirtualScreenMirror
// later requires display -> MSERR_UNKNOWN_MAKE_MIRROR (covers the display-null density branch)
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CreateVirtualScreen_DisplayNull_DensitySkipped, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(sptr<Rosen::Display>(nullptr)));
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*smFlow_, CreateVirtualScreen(_)).WillByDefault(Return(TEST_VIRTUAL_SCREEN_ID));
    ON_CALL(*smFlow_, SetVirtualScreenAutoRotation(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenSkipProtectedWindow(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenPrivacyWindowTagSwitch(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, DestroyVirtualScreen(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameWidth = TEST_DISPLAY_WIDTH;
    server_->captureConfig_.videoInfo.videoCapInfo.videoFrameHeight = TEST_DISPLAY_HEIGHT;
    server_->showCursor_ = true;
    sptr<OHOS::Surface> consumer = OHOS::Surface::CreateSurfaceAsConsumer();
    EXPECT_EQ(server_->CreateVirtualScreen(consumer), MSERR_UNKNOWN_MAKE_MIRROR);
}

// canvasRotation_ true -> SetCanvasRotationInner invoked inside PrepareVirtualScreenMirror
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_PrepareVirtualScreenMirror_CanvasRotationTrue, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenCanvasRotation(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->canvasRotation_ = true;
    server_->captureState_ = AVScreenCaptureState::CREATED;
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    EXPECT_EQ(server_->PrepareVirtualScreenMirror(), MSERR_OK);
}

// GetScreenById null -> MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_PrepareVirtualScreenMirror_GetScreenByIdNull, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(sptr<Rosen::Screen>(nullptr)));
    ON_CALL(*smFlow_, DestroyVirtualScreen(_, _)).WillByDefault(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->canvasRotation_ = false;
    EXPECT_EQ(server_->PrepareVirtualScreenMirror(), MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN);
}

// MakeVirtualScreen (SetupVirtualScreenMirror) fails via MakeMirror error -> MSERR_UNKNOWN_MAKE_MIRROR
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_PrepareVirtualScreenMirror_MakeVirtualScreenFail, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    ON_CALL(*smFlow_, DestroyVirtualScreen(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isRegionCapture_.store(false);
    server_->canvasRotation_ = false;
    EXPECT_EQ(server_->PrepareVirtualScreenMirror(), MSERR_UNKNOWN_MAKE_MIRROR);
}

// ===================== SetupVirtualScreenMirror / CreateMirror (L2670-2705, L639-658) =====================

// CAPTURE_SPECIFIED_WINDOW with displayIds_ already set -> uses displayIds_.front()
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetupVirtualScreenMirror_SpecifiedWindow_DisplayIdsSet, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->captureConfig_.captureMode = CAPTURE_SPECIFIED_WINDOW;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->displayIds_ = {TEST_SCREEN_ID};
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->SetupVirtualScreenMirror(mirrorIds), MSERR_OK);
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

// CreateMirror in PAUSED state with canvasRotation_ false -> MakeMirrorWithRotation
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CreateMirror_PausedWithRotation, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, MakeMirrorWithRotation(_, _, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::PAUSED;
    server_->canvasRotation_ = false;
    std::vector<uint64_t> displayIds = {TEST_SCREEN_ID};
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->CreateMirror(displayIds, mirrorIds), DMError::DM_OK);
}

// CreateMirror in ACTIVE (STARTED) state -> plain MakeMirror (skips GetDisplayById)
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CreateMirror_ActiveState, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, MakeMirror(_, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    std::vector<uint64_t> displayIds = {TEST_SCREEN_ID};
    std::vector<ScreenId> mirrorIds = {TEST_VIRTUAL_SCREEN_ID};
    EXPECT_EQ(server_->CreateMirror(displayIds, mirrorIds), DMError::DM_OK);
}

// ===================== MakeVirtualScreenMirror region (L2715-2717) =====================

// isRegionCapture_ true -> delegates to SetCaptureAreaInner
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_MakeVirtualScreenMirror_RegionCapture, TestSize.Level2)
{
    ON_CALL(*smFlow_, MakeMirrorWithRegion(_, _, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, GetScreenAreaOfDisplayArea(_, _, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isRegionCapture_.store(true);
    server_->regionDisplayId_ = TEST_SCREEN_ID;
    server_->regionArea_ = {0, 0, 100, 100};
    EXPECT_EQ(server_->MakeVirtualScreenMirror(), MSERR_OK);
}

// ===================== SetCaptureAreaInner (L3042-3075) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureAreaInner_Success, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetScreenAreaOfDisplayArea(_, _, _, _)).WillByDefault(Return(DMError::DM_OK));
    EXPECT_CALL(*smFlow_, MakeMirrorWithRegion(_, _, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureAreaInner(TEST_SCREEN_ID, area), MSERR_OK);
    ASSERT_FALSE(server_->sourceDisplayIds_.empty());
    EXPECT_EQ(server_->sourceDisplayIds_.front(), TEST_SCREEN_ID);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureAreaInner_GetScreenAreaFail, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetScreenAreaOfDisplayArea(_, _, _, _)).WillByDefault(Return(DMError::DM_ERROR_UNKNOWN));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureAreaInner(TEST_SCREEN_ID, area), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureAreaInner_MakeMirrorRegionFail, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetScreenAreaOfDisplayArea(_, _, _, _)).WillByDefault(Return(DMError::DM_OK));
    EXPECT_CALL(*smFlow_, MakeMirrorWithRegion(_, _, _, _)).WillOnce(Return(DMError::DM_ERROR_INVALID_MODE_ID));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureAreaInner(TEST_SCREEN_ID, area), MSERR_UNKNOWN);
}

// ===================== SetCaptureArea (L3026-3040) =====================

// Not running + valid area -> MSERR_OK, isRegionCapture_ set
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureArea_NotRunning_Ok, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    server_->captureState_ = AVScreenCaptureState::CREATED;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureArea(TEST_SCREEN_ID, area), MSERR_OK);
    EXPECT_TRUE(server_->isRegionCapture_.load());
    EXPECT_EQ(server_->regionDisplayId_, TEST_SCREEN_ID);
}

// Running + SetCaptureAreaInner success
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureArea_Running_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    ON_CALL(*dmFlow_, GetScreenAreaOfDisplayArea(_, _, _, _)).WillByDefault(Return(DMError::DM_OK));
    EXPECT_CALL(*smFlow_, MakeMirrorWithRegion(_, _, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureState_ = AVScreenCaptureState::STARTED;
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureArea(TEST_SCREEN_ID, area), MSERR_OK);
}

// Invalid area (negative) -> CheckDisplayArea fails -> MSERR_INVALID_VAL
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCaptureArea_InvalidArea, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    server_->captureState_ = AVScreenCaptureState::CREATED;
    OHOS::Rect area = {-1, 0, 100, 100};
    EXPECT_EQ(server_->SetCaptureArea(TEST_SCREEN_ID, area), MSERR_INVALID_VAL);
}

// ===================== CheckDisplayArea (L3095-3114) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CheckDisplayArea_DisplayNull, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(sptr<Rosen::Display>(nullptr)));
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_FALSE(server_->CheckDisplayArea(TEST_SCREEN_ID, area));
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CheckDisplayArea_NegativeArea, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    OHOS::Rect area = {0, -5, 100, 100};
    EXPECT_FALSE(server_->CheckDisplayArea(TEST_SCREEN_ID, area));
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CheckDisplayArea_OutOfRange, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    OHOS::Rect area = {0, 0, TEST_DISPLAY_WIDTH + 100, TEST_DISPLAY_HEIGHT};
    EXPECT_FALSE(server_->CheckDisplayArea(TEST_SCREEN_ID, area));
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_CheckDisplayArea_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(display));
    OHOS::Rect area = {0, 0, 100, 100};
    EXPECT_TRUE(server_->CheckDisplayArea(TEST_SCREEN_ID, area));
}

// ===================== GetMultiDisplayCaptureCapability (L3077-3093) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_GetMultiDisplayCaptureCapability_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, QueryMultiScreenCapture(_, _)).WillOnce(Return(DMError::DM_OK));
    std::vector<uint64_t> displayIds = {1, 2};
    MultiDisplayCapability capability;
    EXPECT_EQ(server_->GetMultiDisplayCaptureCapability(displayIds, capability), MSERR_OK);
    EXPECT_TRUE(capability.isMultiDisplaySupport);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_GetMultiDisplayCaptureCapability_NotSupport_ReturnsOk, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, QueryMultiScreenCapture(_, _)).WillOnce(Return(DMError::DM_ERROR_DEVICE_NOT_SUPPORT));
    std::vector<uint64_t> displayIds = {1, 2};
    MultiDisplayCapability capability;
    EXPECT_EQ(server_->GetMultiDisplayCaptureCapability(displayIds, capability), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_GetMultiDisplayCaptureCapability_UnknownError, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, QueryMultiScreenCapture(_, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    std::vector<uint64_t> displayIds = {1, 2};
    MultiDisplayCapability capability;
    EXPECT_EQ(server_->GetMultiDisplayCaptureCapability(displayIds, capability), MSERR_UNKNOWN);
}

// ===================== ResizeCanvas (L3388-3417) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResizeCanvas_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, ResizeVirtualScreen(_, _, _, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_EQ(server_->ResizeCanvas(100, 100), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResizeCanvas_InvalidHeight, TestSize.Level2)
{
    server_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(server_->ResizeCanvas(100, 0), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResizeCanvas_ResizeFail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, ResizeVirtualScreen(_, _, _, _, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_EQ(server_->ResizeCanvas(100, 100), MSERR_INVALID_OPERATION);
}

// ===================== UpdateSurface (L3419-3437) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_UpdateSurface_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualScreenSurface(_, _)).WillOnce(Return(DMError::DM_OK));
    server_->isSurfaceMode_ = true;
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    sptr<OHOS::Surface> surface = OHOS::Surface::CreateSurfaceAsConsumer();
    EXPECT_EQ(server_->UpdateSurface(surface), MSERR_OK);
    EXPECT_EQ(server_->surface_, surface);
    server_->surface_ = nullptr;
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_UpdateSurface_SurfaceNull, TestSize.Level2)
{
    server_->isSurfaceMode_ = true;
    server_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(server_->UpdateSurface(nullptr), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_UpdateSurface_SetSurfaceFail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualScreenSurface(_, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->isSurfaceMode_ = true;
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    sptr<OHOS::Surface> surface = OHOS::Surface::CreateSurfaceAsConsumer();
    EXPECT_EQ(server_->UpdateSurface(surface), MSERR_UNSUPPORT);
}

// ===================== SetMaxVideoFrameRate (L3469-3493) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetMaxVideoFrameRate_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    EXPECT_EQ(server_->SetMaxVideoFrameRate(30), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetMaxVideoFrameRate_InvalidRate, TestSize.Level2)
{
    server_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(server_->SetMaxVideoFrameRate(0), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetMaxVideoFrameRate_SetFail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    EXPECT_EQ(server_->SetMaxVideoFrameRate(30), MSERR_INVALID_OPERATION);
}

// ===================== SkipPrivacyMode / SkipPrivacyModeInner (L3439-3467) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SkipPrivacyMode_NotActive_Ok, TestSize.Level2)
{
    server_->captureState_ = AVScreenCaptureState::CREATED;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(server_->SkipPrivacyMode(windows), MSERR_OK);
    EXPECT_EQ(server_->skipPrivacyWindowIDsVec_, windows);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SkipPrivacyMode_Active_Success, TestSize.Level2)
{
    EXPECT_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1};
    EXPECT_EQ(server_->SkipPrivacyMode(windows), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SkipPrivacyMode_Active_Fail, TestSize.Level2)
{
    EXPECT_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1};
    EXPECT_EQ(server_->SkipPrivacyMode(windows), MSERR_UNKNOWN);
}

// ===================== SetCanvasRotation (L3312-3337) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCanvasRotation_NotActive_Ok, TestSize.Level2)
{
    server_->captureState_ = AVScreenCaptureState::CREATED;
    EXPECT_EQ(server_->SetCanvasRotation(true), MSERR_OK);
    EXPECT_TRUE(server_->canvasRotation_);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCanvasRotation_Active_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualMirrorScreenCanvasRotation(_, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    EXPECT_EQ(server_->SetCanvasRotation(true), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCanvasRotation_Active_Fail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualMirrorScreenCanvasRotation(_, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    EXPECT_EQ(server_->SetCanvasRotation(true), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_SetCanvasRotation_Active_Unsupport, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, SetVirtualMirrorScreenCanvasRotation(_, _))
        .WillOnce(Return(DMError::DM_ERROR_DEVICE_NOT_SUPPORT));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->appVersion_ = 25;
    EXPECT_EQ(server_->SetCanvasRotation(true), MSERR_UNSUPPORT);
    server_->appVersion_ = -1;
}

// ===================== AddWhiteListWindows / RemoveWhiteListWindows (L2963-2997) =====================

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_AddWhiteListWindows_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, AddVirtualScreenWhiteList(_, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(server_->AddWhiteListWindows(windows), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_AddWhiteListWindows_Fail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, AddVirtualScreenWhiteList(_, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1};
    EXPECT_EQ(server_->AddWhiteListWindows(windows), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_RemoveWhiteListWindows_Success, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, RemoveVirtualScreenWhiteList(_, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1, 2};
    EXPECT_EQ(server_->RemoveWhiteListWindows(windows), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_RemoveWhiteListWindows_Fail, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, RemoveVirtualScreenWhiteList(_, _)).WillOnce(Return(DMError::DM_ERROR_UNKNOWN));
    server_->captureState_ = AVScreenCaptureState::STARTED;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    std::vector<uint64_t> windows = {1};
    EXPECT_EQ(server_->RemoveWhiteListWindows(windows), MSERR_UNKNOWN);
}

// ===================== ResumeVideoCapture (L4082-4103) =====================

// Extended screen + surface set + CreateVirtualScreen success (needs extended mirror flow)
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResumeVideoCapture_ExtendedScreen_Success, TestSize.Level2)
{
    server_->captureConfig_.captureMode = CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    server_->isSurfaceMode_ = true;
    server_->surface_ = OHOS::Surface::CreateSurfaceAsConsumer();
    auto mainDisplay = MakeMockDisplay(TEST_MAIN_SCREEN_ID, TEST_DISPLAY_WIDTH, TEST_DISPLAY_HEIGHT);
    ON_CALL(*dmFlow_, GetDisplayById(_)).WillByDefault(Return(mainDisplay));
    ON_CALL(*dmFlow_, ConvertScreenIdToRsScreenId(_, _)).WillByDefault(Return(true));
    ON_CALL(*smFlow_, SetMultiScreenMode(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetMultiScreenRelativePosition(_, _)).WillByDefault(Return(DMError::DM_OK));
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    auto screen = MakeMockScreen(TEST_VIRTUAL_SCREEN_ID);
    ON_CALL(*smFlow_, CreateVirtualScreen(_)).WillByDefault(Return(TEST_VIRTUAL_SCREEN_ID));
    ON_CALL(*smFlow_, SetVirtualScreenAutoRotation(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenSkipProtectedWindow(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetScreenPrivacyWindowTagSwitch(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, GetScreenById(_)).WillByDefault(Return(screen));
    ON_CALL(*smFlow_, SetVirtualMirrorScreenScaleMode(_, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*smFlow_, SetVirtualScreenMaxRefreshRate(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    ON_CALL(*dmFlow_, SetVirtualScreenSecurityExemption(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->displayIds_ = {TEST_MAIN_SCREEN_ID};
    EXPECT_EQ(server_->ResumeVideoCapture(), MSERR_OK);
    server_->surface_ = nullptr;
}

// Extended screen + surface null -> MSERR_INVALID_OPERATION
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResumeVideoCapture_ExtendedScreen_SurfaceNull, TestSize.Level2)
{
    server_->captureConfig_.captureMode = CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    server_->isSurfaceMode_ = false;
    server_->producerSurface_ = nullptr;
    EXPECT_EQ(server_->ResumeVideoCapture(), MSERR_INVALID_OPERATION);
}

// Mirror screen + valid virtualScreenId_ + MakeVirtualScreenMirror success
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResumeVideoCapture_Mirror_Success, TestSize.Level2)
{
    auto display = MakeMockDisplay(TEST_SCREEN_ID);
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(display));
    ON_CALL(*smFlow_, MakeMirror(_, _, _)).WillByDefault(Return(DMError::DM_OK));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isRegionCapture_.store(false);
    EXPECT_EQ(server_->ResumeVideoCapture(), MSERR_OK);
    EXPECT_TRUE(server_->isConsumerStart_);
}

// Mirror screen + valid virtualScreenId_ but GetDefaultDisplaySync null -> MakeVirtualScreenMirror
// (SetupVirtualScreenMirror) fails -> MSERR_UNKNOWN_MAKE_MIRROR
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_ResumeVideoCapture_Mirror_Fail, TestSize.Level2)
{
    ON_CALL(*dmFlow_, GetDefaultDisplaySync(_, _)).WillByDefault(Return(sptr<Rosen::Display>(nullptr)));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isRegionCapture_.store(false);
    EXPECT_EQ(server_->ResumeVideoCapture(), MSERR_UNKNOWN_MAKE_MIRROR);
}

// ===================== PauseVideoCapture (L4063-4080) =====================

// Extended screen -> DestroyVirtualScreen path
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_PauseVideoCapture_ExtendedScreen, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, DestroyVirtualScreen(_, _)).WillOnce(Return(DMError::DM_OK));
    server_->captureConfig_.captureMode = CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isConsumerStart_ = true;
    EXPECT_EQ(server_->PauseVideoCapture(), MSERR_OK);
    EXPECT_FALSE(server_->isConsumerStart_);
    EXPECT_EQ(server_->virtualScreenId_, SCREEN_ID_INVALID);
}

// Normal + isConsumerStart_ true -> StopMirror
HWTEST_F(ScreenCaptureServerDisplayDmTest, Flow_PauseVideoCapture_Normal_ConsumerStart, TestSize.Level2)
{
    EXPECT_CALL(*smFlow_, StopMirror(_)).WillOnce(Return(DMError::DM_OK));
    server_->captureConfig_.captureMode = CAPTURE_HOME_SCREEN;
    server_->virtualScreenId_ = TEST_VIRTUAL_SCREEN_ID;
    server_->isConsumerStart_ = true;
    EXPECT_EQ(server_->PauseVideoCapture(), MSERR_OK);
    EXPECT_FALSE(server_->isConsumerStart_);
}

} // namespace Media
} // namespace OHOS
