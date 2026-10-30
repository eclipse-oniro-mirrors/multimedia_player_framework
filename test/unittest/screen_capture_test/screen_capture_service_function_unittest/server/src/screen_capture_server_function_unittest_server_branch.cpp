/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version  2.0 (the "License");
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
#include "mock/mock_recorder_service.h"
#include "screen_capture_server.h"
#include "screen_capture_server_function_unittest.h"
#include <json/json.h>
#include <limits>

using namespace testing::ext;
using namespace OHOS::Media::ScreenCaptureTestParam;
using namespace OHOS::Media;
using namespace OHOS::Rosen;

namespace OHOS {
namespace Media {

namespace {
// Allocate a HAP token that has the single given permission granted, returning its token id.
Security::AccessToken::AccessTokenID SetupTokenWithSinglePerm(const std::string &perm)
{
    Security::AccessToken::HapInfoParams info = {.userID = 100, .bundleName = "com.ohos.test.scperm",
        .instIndex = 0, .appIDDesc = "com.ohos.test.scperm", .isSystemApp = true};
    Security::AccessToken::HapPolicyParams policy = {
        .apl = Security::AccessToken::APL_SYSTEM_CORE,
        .domain = "test.domain.scperm",
        .permList = {},
        .permStateList = {
            {.permissionName = perm, .isGeneral = true, .resDeviceID = {"local"},
             .grantStatus = {Security::AccessToken::PermissionState::PERMISSION_GRANTED}, .grantFlags = {1}}
        }
    };
    return Security::AccessToken::AccessTokenKit::AllocHapToken(info, policy).tokenIDEx;
}
} // namespace

HWTEST_F(ScreenCaptureServerFunctionTest, ShouldShowSensitiveCheckBox_PickerPopUp_001, TestSize.Level2)
{
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_FALSE(screenCaptureServer_->ShouldShowSensitiveCheckBox());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShouldShowSensitiveCheckBox_NotOriginalStream_001, TestSize.Level2)
{
    screenCaptureServer_->isPresentPickerPopWindow_ = false;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    EXPECT_FALSE(screenCaptureServer_->ShouldShowSensitiveCheckBox());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ShouldShowSensitiveCheckBox_BothTrue_001, TestSize.Level2)
{
    screenCaptureServer_->isPresentPickerPopWindow_ = false;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    EXPECT_TRUE(screenCaptureServer_->ShouldShowSensitiveCheckBox());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_NullInput_001, TestSize.Level2)
{
    Json::Value nullAppInfo; // default-constructed Json::Value is null
    EXPECT_FALSE(screenCaptureServer_->ParseAppMissionIds(nullAppInfo));
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_BundleNameNotString_001, TestSize.Level2)
{
    Json::Value appInfo;
    appInfo["bundleName"] = 123; // int, not a string
    appInfo["appIndex"] = 0;
    EXPECT_FALSE(screenCaptureServer_->ParseAppMissionIds(appInfo));
}

HWTEST_F(ScreenCaptureServerFunctionTest, ParseAppMissionIds_AppIndexNotInt_001, TestSize.Level2)
{
    Json::Value appInfo;
    appInfo["bundleName"] = "com.test.app";
    appInfo["appIndex"] = "not_an_int"; // string, not an int
    EXPECT_FALSE(screenCaptureServer_->ParseAppMissionIds(appInfo));
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_SurfaceModeNull_001, TestSize.Level2)
{
    SetValidConfig(); // dataType = ORIGINAL_STREAM, valid audio (16000/2) + video (720x1280)
    screenCaptureServer_->captureConfig_ = config_;
    screenCaptureServer_->isSurfaceMode_ = true;
    screenCaptureServer_->surface_ = nullptr;
    ASSERT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_BothIgnore_Direct_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0; // -> CheckAudioCapInfo sets IGNORE
    config_.videoInfo.videoCapInfo.videoFrameWidth = 0;
    config_.videoInfo.videoCapInfo.videoFrameHeight = 0; // -> CheckVideoCapInfo sets IGNORE
    screenCaptureServer_->captureConfig_ = config_;
    screenCaptureServer_->isSurfaceMode_ = false;
    ASSERT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_InnerCapInvalid_Direct_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.innerCapInfo.audioSampleRate = 1; // 1 not in supported rates -> INVALID
    screenCaptureServer_->captureConfig_ = config_;
    screenCaptureServer_->isSurfaceMode_ = false;
    ASSERT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ChangeMirrorScreen_NullVirtualScreen_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreen_ = nullptr;
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->ChangeMirrorScreen();
    // Early return: sourceDisplayIds_ must remain empty (no mirror applied)
    EXPECT_TRUE(screenCaptureServer_->sourceDisplayIds_.empty());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ChangeMirrorScreen_EmptyDisplayIds_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreen_ = MakeTestVirtualScreen(100);
    screenCaptureServer_->displayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->ChangeMirrorScreen();
    EXPECT_TRUE(screenCaptureServer_->sourceDisplayIds_.empty());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ChangeMirrorScreen_AlreadyCaptureScreen_001, TestSize.Level2)
{
    screenCaptureServer_->virtualScreen_ = MakeTestVirtualScreen(100);
    screenCaptureServer_->displayIds_.clear();
    screenCaptureServer_->displayIds_.push_back(100);
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(100); // IsCaptureScreen(100) == true
    screenCaptureServer_->ChangeMirrorScreen();
    ASSERT_EQ(screenCaptureServer_->sourceDisplayIds_.size(), 1u);
    EXPECT_EQ(screenCaptureServer_->sourceDisplayIds_.front(), 100u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyWindowVisible_OverflowMissionId_001, TestSize.Level2)
{
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE;
    constexpr uint64_t overflowMissionId = static_cast<uint64_t>(std::numeric_limits<int32_t>::max()) + 1;
    screenCaptureServer_->NotifyWindowVisible(overflowMissionId);
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, NotifyWindowVisible_ListWindowInfoFail_001, TestSize.Level2)
{
    screenCaptureServer_->curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE;
    screenCaptureServer_->NotifyWindowVisible(100); // valid id, but ListWindowInfo fails
    EXPECT_EQ(screenCaptureServer_->curWindowEvent_,
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Foreground_NewMission_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_FOREGROUND, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(ADD_WHITE_LIST | NOTIFY_VISIBLE));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_EQ(screenCaptureServer_->missionInfos_.front().missionId, 100u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Foreground_ExistingMission_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, false});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_FOREGROUND, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(0));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_TRUE(screenCaptureServer_->missionInfos_.front().isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Background_MissionAbsent_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, true});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(999, Rosen::SessionState::STATE_BACKGROUND, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(0));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_TRUE(screenCaptureServer_->missionInfos_.front().isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Background_NotForeground_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, false});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_BACKGROUND, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(0));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_FALSE(screenCaptureServer_->missionInfos_.front().isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Background_Foreground_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, true});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_BACKGROUND, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(UPDATE_MIRROR));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_FALSE(screenCaptureServer_->missionInfos_.front().isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Disconnect_MissionAbsent_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, true});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(999, Rosen::SessionState::STATE_DISCONNECT, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(REMOVE_WHITE_LIST));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_Disconnect_LastMission_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, true});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_DISCONNECT, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(UPDATE_MIRROR | NOTIFY_UNAVAILABLE | REMOVE_WHITE_LIST));
    EXPECT_TRUE(screenCaptureServer_->missionInfos_.empty());
}

// default case: STATE_INACTIVE (not in switch) -> flags=0
HWTEST_F(ScreenCaptureServerFunctionTest, UpdateMissionData_DefaultState_001, TestSize.Level2)
{
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100u, true});
    std::vector<uint64_t> allIds;
    uint8_t flags = screenCaptureServer_->UpdateMissionData(100, Rosen::SessionState::STATE_INACTIVE, allIds);
    ASSERT_EQ(flags, static_cast<uint8_t>(0));
    ASSERT_EQ(screenCaptureServer_->missionInfos_.size(), 1u);
    EXPECT_TRUE(screenCaptureServer_->missionInfos_.front().isForeground);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCaptureStreamParams_InnerIgnoreVideoValid_Direct_001, TestSize.Level2)
{
    SetValidConfig();
    config_.audioInfo.innerCapInfo.audioSampleRate = 0;
    config_.audioInfo.innerCapInfo.audioChannels = 0; // -> CheckAudioCapInfo sets IGNORE
    // videoCapInfo stays 720x1280 -> CheckVideoCapInfo sets VALID
    screenCaptureServer_->captureConfig_ = config_;
    screenCaptureServer_->isSurfaceMode_ = false;
    ASSERT_EQ(screenCaptureServer_->CheckCaptureStreamParams(), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, UpdatePrivacyUsingPermissionState_NonStartNonStop_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appUid = 100; // != ROOT_UID -> IsUserPrivacyAuthorityNeeded() == true
    constexpr auto otherState = static_cast<VideoPermissionState>(2); // not START_VIDEO(0) nor STOP_VIDEO(1)
    EXPECT_TRUE(screenCaptureServer_->UpdatePrivacyUsingPermissionState(otherState));
}

namespace {
class BranchCovNullCallBack : public ScreenCaptureCallBack {
public:
    void OnError(ScreenCaptureErrorType, int32_t) override {}
    void OnAudioBufferAvailable(bool, AudioCaptureSourceType) override {}
    void OnVideoBufferAvailable(bool) override {}
    void OnStateChange(AVScreenCaptureStateCode) override {}
    void OnDisplaySelected(uint64_t) override {}
    void OnCaptureContentChanged(AVScreenCaptureContentChangedEvent, ScreenCaptureRect *) override {}
    void OnUserSelected(ScreenCaptureUserSelectionInfo) override {}
    void OnPrivacyProtect(AVScreenCapturePrivacyProtect) override {}
};
} // namespace

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCaptureSuccessAction_NotSystemRecorder_001, TestSize.Level2)
{
    screenCaptureServer_->cbProxy_->SetCallback(std::make_shared<BranchCovNullCallBack>());
    screenCaptureServer_->isSystemRecorder_.store(false);
    screenCaptureServer_->sourceDisplayIds_.clear();
    screenCaptureServer_->sourceDisplayIds_.push_back(SCREEN_ID_INVALID);
    EXPECT_FALSE(screenCaptureServer_->isSystemRecorder_.load()); // verify store took effect
    screenCaptureServer_->PostStartScreenCaptureSuccessAction();
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STARTED);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetVirtualScreenName_ExtendedScreen_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_VIRTUAL_EXTENDED_SCREEN;
    EXPECT_EQ(screenCaptureServer_->GetVirtualScreenName(), "CooperationExtend");
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckCustScrRecPermission_NoPerm_001, TestSize.Level2)
{
    // appInfo_.appTokenId defaults to 0 (not granted PERM_CUST_SCR_REC) -> VerifyAccessToken fails
    EXPECT_FALSE(screenCaptureServer_->CheckCustScrRecPermission());
}

HWTEST_F(ScreenCaptureServerFunctionTest, ExcludeContent_ShowCursorFalse_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED; // CAP_ALIVE + CAP_ACTIVE
    screenCaptureServer_->virtualScreen_ = ScreenCaptureTestParam::MakeTestVirtualScreen(1);
    screenCaptureServer_->innerAudioCapture_ = nullptr;
    screenCaptureServer_->showCursor_ = false;
    ScreenCaptureContentFilter filter;
    EXPECT_EQ(screenCaptureServer_->ExcludeContent(filter), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCaptureByEvent_NotAlive_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED;
    EXPECT_EQ(screenCaptureServer_->StopScreenCaptureByEvent(
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_InvalidWidth_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED; // CAP_ACTIVE
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(-1, 1280), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_InvalidHeight_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(720, -1), MSERR_INVALID_VAL);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResizeCanvas_NullScreen_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->captureConfig_.dataType = DataType::ORIGINAL_STREAM;
    screenCaptureServer_->virtualScreen_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ResizeCanvas(720, 1280), MSERR_INVALID_OPERATION);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SpecifiedWindow_NoMission_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.dataType = DataType::INVAILD;
    screenCaptureServer_->missionInfos_.clear();
    EXPECT_EQ(screenCaptureServer_->OnStartScreenCapture(true), MSERR_UNSUPPORT);
}

HWTEST_F(ScreenCaptureServerFunctionTest, OnStartScreenCapture_SpecifiedWindow_OneMission_001, TestSize.Level2)
{
    screenCaptureServer_->captureConfig_.captureMode = CaptureMode::CAPTURE_SPECIFIED_WINDOW;
    screenCaptureServer_->captureConfig_.dataType = DataType::INVAILD;
    screenCaptureServer_->missionInfos_.clear();
    screenCaptureServer_->missionInfos_.push_back({100, true});
    EXPECT_EQ(screenCaptureServer_->OnStartScreenCapture(true), MSERR_UNSUPPORT);
}

HWTEST_F(ScreenCaptureServerFunctionTest, GetScreenScaleMode_UnmappedFillMode_001, TestSize.Level2)
{
    auto mode = screenCaptureServer_->GetScreenScaleMode(static_cast<AVScreenCaptureFillMode>(2));
    EXPECT_EQ(mode, Rosen::ScreenScaleMode::UNISCALE_MODE);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MSErrorToScreenCaptureError_Unsupport_001, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->MSErrorToScreenCaptureError(MSERR_UNSUPPORT),
        AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNSUPPORT);
}

HWTEST_F(ScreenCaptureServerFunctionTest, MSErrorToScreenCaptureError_Other_001, TestSize.Level2)
{
    EXPECT_EQ(screenCaptureServer_->MSErrorToScreenCaptureError(MSERR_UNKNOWN),
        AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, AddWatermark_RecFail_001, TestSize.Level2)
{
    auto mock = std::make_shared<MockRecorderService>();
    EXPECT_CALL(*mock, AddWatermark(_, _, _, _)).WillOnce(Return(MSERR_UNKNOWN));
    screenCaptureServer_->recorder_ = mock;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::CREATED;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    auto buffer = CreateWatermarkBuffer();
    int32_t count = 1;
    int32_t ret = screenCaptureServer_->AddWatermark(buffer, 100, 100, count);
    screenCaptureServer_->recorder_ = nullptr; // cleanup before final assertion
    ASSERT_EQ(ret, MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, RequestUserPrivacyAuthority_NotEnabled_001, TestSize.Level2)
{
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = false;
    screenCaptureServer_->appInfo_.appTokenId = IPCSkeleton::GetCallingTokenID(); // HAP token w/ CAPTURE_SCREEN
    bool isSkip = false;
    EXPECT_EQ(screenCaptureServer_->RequestUserPrivacyAuthority(isSkip), MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CheckScreenCapturePermission_NoPerm_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appTokenId = 999999; // invalid token, lacks CAPTURE_SCREEN
    EXPECT_FALSE(screenCaptureServer_->CheckScreenCapturePermission());
}

// ===================== Permission GRANTED branches (custom HAP tokens) =====================
HWTEST_F(ScreenCaptureServerFunctionTest, CheckPrivacyWindowSkipPermission_WithPerm_001, TestSize.Level2)
{
    screenCaptureServer_->appInfo_.appTokenId =
        SetupTokenWithSinglePerm("ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE");
    EXPECT_TRUE(screenCaptureServer_->CheckPrivacyWindowSkipPermission());
}

HWTEST_F(ScreenCaptureServerFunctionTest, PauseScreenCapture_PauseRecorderFail_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;
    auto mock = std::make_shared<MockRecorderService>();
    EXPECT_CALL(*mock, Pause()).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Stop(_)).WillOnce(Return(MSERR_OK));   // StopCaptureOnError -> StopScreenCaptureRecorder
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    screenCaptureServer_->recorder_ = mock;
    EXPECT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_UNKNOWN_RECORDER_PAUSE);
}

// Full start + Pause (state -> PAUSED) -> replace recorder_ with mock failing Resume ->
HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCapture_ResumeRecorderFail_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;
    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK); // state -> PAUSED
    auto mock = std::make_shared<MockRecorderService>();
    EXPECT_CALL(*mock, Resume()).WillOnce(Return(MSERR_UNKNOWN));
    EXPECT_CALL(*mock, Stop(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    screenCaptureServer_->recorder_ = mock;
    EXPECT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_UNKNOWN_RECORDER_RESUME);
}

HWTEST_F(ScreenCaptureServerFunctionTest, ResumeScreenCapture_CreateVirtualScreenFail_001, TestSize.Level2)
{
    RecorderInfo recorderInfo;
    SetRecorderInfo(recorderInfo);
    SetValidConfigFile(recorderInfo);
    ASSERT_EQ(InitFileScreenCaptureServer(), MSERR_OK);
    ASSERT_EQ(screenCaptureServer_->StartScreenCapture(false), MSERR_OK);
    screenCaptureServer_->captureConfig_.strategy.enablePause = true;
    ASSERT_EQ(screenCaptureServer_->PauseScreenCapture(), MSERR_OK); // state PAUSED, virtualScreen_ reset
    screenCaptureServer_->consumer_ = nullptr;
    EXPECT_EQ(screenCaptureServer_->ResumeScreenCapture(), MSERR_UNKNOWN);
}

HWTEST_F(ScreenCaptureServerFunctionTest, StopScreenCaptureInner_PickerPopUp_001, TestSize.Level2)
{
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STARTED;
    screenCaptureServer_->isPresentPickerPopWindow_ = true;
    screenCaptureServer_->captureConfig_.dataType = DataType::CAPTURE_FILE;
    auto mock = std::make_shared<MockRecorderService>();
    EXPECT_CALL(*mock, Stop(_)).WillOnce(Return(MSERR_OK));
    EXPECT_CALL(*mock, Release()).WillOnce(Return(MSERR_OK));
    screenCaptureServer_->recorder_ = mock;
    int32_t ret = screenCaptureServer_->StopScreenCaptureInner(
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
    screenCaptureServer_->recorder_ = nullptr; // cleanup before final assertion
    ASSERT_EQ(ret, MSERR_OK);
}

HWTEST_F(ScreenCaptureServerFunctionTest, CreateScreenCaptureServer_NullProviders_001, TestSize.Level2)
{
    ASSERT_EQ(CreateScreenCaptureServer(nullptr), nullptr);
    auto providers = CreateMockProviders();
    auto *svc = CreateScreenCaptureServer(providers.release());
    ASSERT_NE(svc, nullptr);
    auto *server = static_cast<ScreenCaptureServer *>(svc); // cast to concrete type
    auto name = server->GetVirtualScreenName(); // member call, value assertion
    DestroyScreenCaptureServer(svc);            // cleanup before final assertion
    EXPECT_EQ(name, "screen_capture");
}

HWTEST_F(ScreenCaptureServerFunctionTest, PostStartScreenCaptureFail_Enabled_001, TestSize.Level2)
{
    screenCaptureServer_->cbProxy_->SetCallback(std::make_shared<BranchCovNullCallBack>());
    screenCaptureServer_->isPrivacyAuthorityEnabled_ = true;
    screenCaptureServer_->captureState_ = AVScreenCaptureState::STOPPED; // StopScreenCaptureInner early return
    screenCaptureServer_->PostStartScreenCaptureFail(MSERR_UNKNOWN);
    ASSERT_EQ(screenCaptureServer_->captureState_, AVScreenCaptureState::STOPPED);
}

} // namespace Media
} // namespace OHOS

