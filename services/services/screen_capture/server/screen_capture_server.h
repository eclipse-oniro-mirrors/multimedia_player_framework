/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef SCREEN_CAPTURE_SERVICE_SERVER_H
#define SCREEN_CAPTURE_SERVICE_SERVER_H

#include "audio_capturer_wrapper.h"
#include "audio_data_source.h"
#include "i_screen_capture_service.h"
#include "screen_capture.h"
#include "screen_capture_callback_proxy.h"
#include "screen_capture_listener_manager.h"
#include "screen_capture_server_base.h"
#include "task_queue.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <json/json.h>
#include <memory>
#include <mutex>
#include <nocopyable.h>
#include <notification_local_live_view_subscriber.h>
#include <queue>
#include <string>
#include <thread>
#include <ui_extension_ability_connection.h>
#include <vector>

namespace OHOS::Media {

struct MissionInfo {
    uint64_t missionId;
    bool isForeground;
};

enum MissionSideEffect : uint8_t {
    NONE = 0,
    ADD_WHITE_LIST = 1,
    UPDATE_MIRROR = 2,
    REMOVE_WHITE_LIST = 4,
    NOTIFY_VISIBLE = 8,
    NOTIFY_UNAVAILABLE = 16,
};

class NotificationSubscriber : public OHOS::Notification::NotificationLocalLiveViewSubscriber {
public:
    void OnConnected() override;
    void OnDisconnected() override;
    void OnResponse(int32_t notificationId,
        OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption) override;
    void OnDied() override;
};

class ScreenCaptureServer : public std::enable_shared_from_this<ScreenCaptureServer>,
                            public IScreenCaptureService,
                            public IScreenCaptureEventListener,
                            public NoCopyable {
public:
    static std::shared_ptr<IScreenCaptureService> Create(std::unique_ptr<IScreenCaptureServiceProviders> providers);
    explicit ScreenCaptureServer(std::unique_ptr<IScreenCaptureServiceProviders> providers);
    ~ScreenCaptureServer() override;

    int32_t SetCaptureMode(CaptureMode captureMode) override;
    int32_t SetDataType(DataType dataType) override;
    int32_t SetRecorderInfo(RecorderInfo recorderInfo) override;
    int32_t SetOutputFile(int32_t outputFd) override;
    int32_t SetAndCheckLimit() override;
    int32_t SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo) override;
    int32_t InitAudioEncInfo(AudioEncInfo audioEncInfo) override;
    int32_t InitAudioCap(AudioCaptureInfo audioInfo) override;
    int32_t InitVideoEncInfo(VideoEncInfo videoEncInfo) override;
    int32_t InitVideoCap(VideoCaptureInfo videoInfo) override;
    int32_t StartScreenCapture(bool isPrivacyAuthorityEnabled) override;
    int32_t StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled) override;
    int32_t StopScreenCapture() override;
    int32_t StopAndRelease(AVScreenCaptureStateCode state);
    int32_t PresentPicker() override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence, int64_t &timestamp,
        OHOS::Rect &damage, OHOS::Rect &rsRect) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    bool GetMicWorkingState();
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t SetContentAutoRotation(bool contentAutoRotation) override;
    int32_t ShowCursor(bool showCursor) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t SkipPrivacyMode(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    void Release() override;
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override;
    int32_t AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t ExcludePickerWindows(const std::vector<int32_t> &windowIDsVec) override;
    int32_t SetPickerMode(PickerMode pickerMode) override;
    int32_t SetScreenCaptureStrategy(ScreenCaptureStrategy strategy) override;
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override;
    int32_t UpdateSurface(sptr<Surface> surface) override;
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area) override;
    int32_t GetMultiDisplayCaptureCapability(const std::vector<uint64_t> &displayIds,
        MultiDisplayCapability &capability) override;
    int32_t PauseScreenCapture() override;
    int32_t ResumeScreenCapture() override;
    int32_t AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer, int32_t width, int32_t height,
        int32_t &watermarkCount) override;

    int32_t ReportAVScreenCaptureUserChoice(const std::string &content);
    int32_t GetAVScreenCaptureConfigurableParameters(std::string &resultStr);
    void OnWindowLifecycle(Rosen::ISessionLifecycleListener::SessionLifecycleEvent event) override;
    void OnWindowInfoChanged(Rosen::DisplayId displayId) override;
    void OnPrivateWindowChange(bool hasPrivate) override;
    void OnScreenConnect(Rosen::ScreenId screenId) override;
    void OnScreenDisconnect(Rosen::ScreenId screenId) override;
    void OnLanguageSwitch() override;
    void OnRecordDisplayChange(const std::vector<Rosen::DisplayId> &displayIds) override;
#ifdef SUPPORT_CALL
    void OnCallStateChanged(bool isInCall) override;
#endif
    void OnAccountSwitched() override;
    void OnAudioRendererStateChanged(
        const std::vector<std::shared_ptr<AudioStandard::AudioRendererChangeInfo>> &audioRendererChangeInfos) override;
    void OnBatchLifecycleEvent(
        const std::vector<Rosen::ISessionLifecycleListener::LifecycleEventPayload> &payloads) override;
    void OnAppInstanceLifecycleEvent(const Rosen::ISessionLifecycleListener::LifecycleEventPayload &payload) override;

    void SetSessionId(int32_t sessionId);
    void GetAndSetAppVersion();
    bool CheckAppVersionForUnsupport(Rosen::DMError result);
    int32_t StopScreenCaptureByEvent(AVScreenCaptureStateCode stateCode);
    void HandleNotificationButtonResponse(const std::string &buttonName);
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> GetWantAgent(const std::string &callingLabel,
        int32_t sessionId);
    void PrivacyProtected(Rosen::ScreenId &virtualScreenId, bool systemPrivacyProtectionSwitch,
        bool appPrivacyProtectionSwitch);
#ifdef SUPPORT_CALL
    int32_t TelCallStateUpdated(bool isInTelCall);
#endif
    void UpdateMicrophoneEnabled();
    int32_t ShowCursorInner();
    void SetDisplayId(uint64_t displayId);
    void SetDisplayId(std::vector<uint64_t> &&displayIds);
    void ChangeMirrorScreen();
    void NotifyWindowVisible(uint64_t missionId);
    void FinishPrepareSelectWindow();
    uint8_t UpdateMissionData(uint64_t missionId, Rosen::SessionState state, std::vector<uint64_t> &allIds);
    void NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect *area);
    void NotifyprivacyProtect();
    bool IsState(uint32_t cap) const;
    bool IsSCRecorderFileWithVideo();
    bool IsStopAcquireAudioBufferFlag();
    bool IsMicrophoneSwitchTurnOn();
    int32_t AudioRendererStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void OnSceneSessionManagerDied(const wptr<IRemoteObject> &remote);
    bool IsCaptureScreen(uint64_t displayId);

private:
    int32_t OnReceiveUserPrivacyAuthority(bool isAllowed);
    int32_t StartScreenCaptureInner(bool isPrivacyAuthorityEnabled);
    int32_t PrepareStartCapture();
    int32_t OnStartScreenCapture(bool isSkipPrivacyWindow = false);
    bool IsFirstStartPidInstance(int32_t pid);
    bool FirstPidUpdatePrivacyUsingPermissionState(int32_t pid);
    void PostStartScreenCapture(bool isSuccess);
    void PostStartScreenCaptureFail();
    void PostStartScreenCaptureSuccessAction();
    int32_t InitRecorderInfo(std::shared_ptr<IRecorderService> &recorder, AudioCaptureInfo audioInfo);
    int32_t InitRecorderMix();
    int32_t InitRecorderInner();
    int32_t InitRecorderMic();
    int32_t InitRecorder();
    Rosen::OutlineShape ConvertToOutlineShape(ScreenCaptureHighlightMode mode);
    void UpdateHighlightOutline(bool isStarted);
    void SetHighlightConfigForWindowManager(bool isStarted, Rosen::OutlineParams &outlineParams);
    bool IsSetHighlightConfig();
    int32_t StartScreenCaptureFile();
    int32_t StartScreenCaptureStream();
    int32_t SyncAudioCaptures(bool ignoreMicError = false);
    std::string GenerateThreadNameByPrefix(std::string threadName);
    int32_t StartInnerAudioCapture();
    int32_t StartMicAudioCapture(bool isVoip);
    int32_t StartStreamVideoCapture();
    int32_t StartStreamHomeVideoCapture();
    int32_t StopScreenCaptureInner(AVScreenCaptureStateCode stateCode);
    int32_t StopAudioAndVideoCapture();
    bool IsLastStartedPidInstance(int32_t pid);
    bool LastPidUpdatePrivacyUsingPermissionState(int32_t pid);
    void PostStopScreenCapture(AVScreenCaptureStateCode stateCode);
    int32_t StopAudioCapture();
    int32_t StopVideoCapture();
    int32_t StopScreenCaptureRecorder();
    int32_t CheckAllParams();
    int32_t CheckCaptureStreamParams();
    int32_t CheckCaptureFileParams();
    int32_t SetCanvasRotationInner();
    int32_t SkipPrivacyModeInner();
    int32_t SetScreenScaleMode();
    void InitAppInfo();
    void ConvertTaskIdsToMissionIds();
    void SetupCaptureListeners();
    void CloseFd();
    void StopMicAudio();
    void ReleaseInner();
    void GetDumpFlag();

    Rosen::VirtualScreenOption InitVirtualScreenOption(sptr<OHOS::Surface> consumer);
    std::string GetVirtualScreenName() const;
    int32_t SetupVirtualScreenMirror(std::vector<Rosen::ScreenId> &mirrorIds);
    Rosen::DMError CreateMirror(const std::vector<uint64_t> &displayIds, std::vector<Rosen::ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirror();
    int32_t MakeVirtualScreenExtended();
    int32_t CreateVirtualScreen(sptr<OHOS::Surface> consumer);
    int32_t SetVirtualScreenAutoRotation();
    int32_t PrepareVirtualScreenMirror();
    void DestroyVirtualScreen();
    int32_t ParseAppMissionIds(const Json::Value &appInformation);
    void ParseDisplayId(const Json::Value &displayIdJson);

    bool CheckScreenCapturePermission();
    bool IsUserPrivacyAuthorityNeeded();
    bool UpdatePrivacyUsingPermissionState(VideoPermissionState state);
    bool CheckPrivacyWindowSkipPermission();
    int32_t RequestUserPrivacyAuthority(bool &isSkipPrivacyWindow);
    int32_t StartPrivacyWindow(const std::string &cmdStr);
    int32_t StartAuthWindow();
    int32_t GetCallerUserId();
    void SetCaptureConfig(CaptureMode captureMode, int32_t missionId = -1); // -1 invalid
    Rosen::ScreenScaleMode GetScreenScaleMode(const AVScreenCaptureFillMode &fillMode);
    int32_t ReportAVScreenCaptureUserChoiceImpl(const std::string &content);
    int32_t HandlePopupWindowCase(Json::Value &root, const std::string &content);
    int32_t HandleStreamDataCase(Json::Value &root, const std::string &content);
    int32_t HandlePresentPickerWindowCase(Json::Value &root, const std::string &content);
    void PrepareSelectWindow(Json::Value &root);
    bool IsSkipPrivacyWindow();
    void BuildCommonParams(Json::Value &root);

#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    bool IsPickerPopUp();
    int32_t StartPicker();
#ifdef PC_STANDARD
    void SendConfigToUIParams(AAFwk::Want &want);
#elif defined(SUPPORT_PICKER_PHONE_PAD)
    void BuildPickerParams(Json::Value &root);
#endif
#endif

#ifdef PC_STANDARD
    bool IsHopper();
    void SetTimeoutScreenoffDisableLock(bool lockScreen);
#endif
    bool CheckCustScrRecPermission();
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    int32_t TryStartNotification();
    int32_t TryNotificationOnPostStartScreenCapture();
#endif
    int32_t StartNotification();
    void SetupPublishRequest(NotificationRequest &request);
    void InitLiveViewContent();
    void UpdateLiveViewContent();
    void UpdateLiveViewButton();
    void UpdateLiveViewPrivacy();
    std::shared_ptr<PixelMap> GetPixelMap(std::string path);
    std::shared_ptr<PixelMap> GetPixelMapSvg(std::string path, int32_t width, int32_t height);
    void ResSchedReportData(int64_t value, std::unordered_map<std::string, std::string> payload);
    int64_t GetCurrentMillisecond();
    void SetMetaDataReport();
    void SetMediaKitReport(const std::string &errMsg);
    void SetErrorInfo(int32_t errCode, const std::string &errMsg, StopReason stopReason, bool userAgree);
    void RegisterPrivateWindowListener();
    void RegisterScreenConnectListener();
    uint64_t GetDisplayIdOfWindows();
    std::string GetStringByResourceName(const char *name);
    void InitResourceManager();
    bool DestroyPopWindow();
    bool DestroyPrivacySheet();
    void StopNotStartedScreenCapture(AVScreenCaptureStateCode stateCode);
    int32_t SetCaptureAreaInner(uint64_t displayId, OHOS::Rect area);
    bool CheckDisplayArea(uint64_t displayId, OHOS::Rect area);
    int32_t HandleOriginalStreamPrivacy();
    void PublishScreenCaptureEvent(const std::string &state);
    void OnCaptureContentChanged(bool isMirrorChanged = false);
    int32_t PauseVideoCapture();
    int32_t ResumeVideoCapture();
    int32_t PauseRecorder();
    int32_t ResumeRecorder();
    int32_t PauseScreenCaptureInner(AVScreenCaptureStateCode stateCode);
    int32_t ResumeScreenCaptureInner(AVScreenCaptureStateCode stateCode);
    int32_t GetWatermarkCount(int32_t &watermarkCount);
    void StopCaptureOnError(const std::string &reportMsg);

private:
    std::mutex mutex_;
    std::mutex captureIdsMutex_;
    mutable std::shared_mutex captureConfigMutex_;
    TaskQueue taskQue_{"SCServer"};
    std::shared_ptr<ScreenCaptureCallbackProxy> cbProxy_ = nullptr;
    bool canvasRotation_ = false;
    bool showCursor_ = true;
    std::atomic<bool> isMicrophoneSwitchTurnOn_{true};
    std::atomic<bool> isPrivacyAuthorityEnabled_{false};
    bool showSensitiveCheckBox_ = false;
    bool checkBoxSelected_ = false;
    bool showShareSystemAudioBox_ = false;
    bool isInnerAudioBoxSelected_ = true;
    std::atomic<bool> appPrivacyProtectionSwitch_{true};
    std::atomic<bool> systemPrivacyProtectionSwitch_{true};
    std::vector<uint64_t> surfaceIdList_ = {};
    std::vector<uint8_t> surfaceTypeList_ = {};
    std::atomic<bool> stopAcquireAudioBufferFromAudio_ = false;

    int32_t sessionId_ = 0;
    int32_t notificationId_ = 0;
    std::string callingLabel_;
    std::string liveViewText_;
    std::string liveViewSubText_;
    float density_ = 0.0f;
    int32_t capsuleVpSize_ = 18;
    int32_t capsulePxSize_ = 0;
    int32_t saUid_ = -1;
    int32_t appVersion_ = -1;

    /* used for both CAPTURE STREAM and CAPTURE FILE */
    OHOS::AudioStandard::AppInfo appInfo_;
    bool isScreenCaptureAuthority_ = false;
    std::atomic<bool> isPresentPickerPopWindow_{false};
    std::string appName_ = "";
    std::atomic<bool> isSystemRecorder_ = {false};
    AVScreenCaptureConfig captureConfig_;
    AVScreenCaptureAvType avType_ = AVScreenCaptureAvType::INVALID_TYPE;
    AVScreenCaptureDataMode dataMode_ = AVScreenCaptureDataMode::BUFFER_MODE;
    StatisticalEventInfo statisticalEventInfo_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    sptr<OHOS::Surface> producerSurface_ = nullptr;
    bool isConsumerStart_ = false;
    bool isDump_ = false;
    bool isSystemUI2_ = false;
    Rosen::ScreenId virtualScreenId_ = Rosen::SCREEN_ID_INVALID;
    Rosen::Rotation targetRotation_ = Rosen::Rotation::ROTATION_0;
    std::vector<Rosen::ScreenId> sourceDisplayIds_;
    std::vector<Rosen::ScreenId> displayIds_;
    std::vector<MissionInfo> missionInfos_;
    int32_t interestWindowId_ = -1;

    std::atomic<bool> isGetAppMissionId_ = true;
    std::atomic<Rosen::ScreenId> curWindowInDisplayId_{Rosen::SCREEN_ID_INVALID};
    std::atomic<AVScreenCaptureContentChangedEvent>
        curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    std::atomic<Rosen::ISessionLifecycleListener::SessionLifecycleEvent>
        curWindowLifecycle_ = Rosen::ISessionLifecycleListener::SessionLifecycleEvent::FOREGROUND;
    ScreenCaptureContentFilter contentFilter_;
    std::atomic<AVScreenCaptureState> captureState_ = AVScreenCaptureState::CREATED;
    std::shared_ptr<Notification::NotificationLocalLiveViewContent> localLiveViewContent_;
    int64_t startTime_ = 0;
    bool isTimePaused_ = false;
    sptr<UIExtensionAbilityConnection> connection_ = nullptr;
    std::unique_ptr<IScreenCaptureServiceProviders> providers_;
    std::shared_ptr<ScreenCaptureListenerManager> listenerManager_ = nullptr;
    std::atomic<bool> isRegionCapture_{false};
    uint64_t regionDisplayId_ = 0;
    OHOS::Rect regionArea_ = {0, 0, 0, 0};

    /* used for CAPTURE STREAM */
    sptr<IBufferConsumerListener> surfaceCb_ = nullptr;
    sptr<OHOS::Surface> surface_ = nullptr;
    std::atomic<bool> isSurfaceMode_{false};
    std::shared_ptr<AudioCapturerWrapper> innerAudioCapture_;
    std::shared_ptr<AudioCapturerWrapper> micAudioCapture_;
    std::mutex audioMutex_;

    /* used for CAPTURE FILE */
    std::shared_ptr<IRecorderService> recorder_ = nullptr;
    OutputFormatType fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    int32_t outputFd_ = -1;
    int32_t audioSourceId_ = 0;
    int32_t videoSourceId_ = 0;
    std::shared_ptr<AudioDataSource> audioSource_ = nullptr;
    /* used for DFX events */
    uint64_t instanceId_ = 0;
    std::vector<uint64_t> skipPrivacyWindowIDsVec_;
    Global::Resource::ResourceManager *resourceManager_ = nullptr;
    Global::Resource::ResConfig *resConfig_ = nullptr;

    /* used for customize picker */
    std::vector<int32_t> excludedWindowIDsVec_;
    PickerMode pickerMode_ = PickerMode::SCREEN_AND_WINDOW;
    std::atomic<bool> isPickerModePopUp_{false};
#ifdef SUPPORT_CALL
    std::atomic<bool> isInTelCall_ = false;
#endif
    std::atomic<bool> recorderFileWithVideo_{false};

private:
    static int32_t CheckAudioCapParam(const AudioCaptureInfo &audioCapInfo);
    static int32_t CheckVideoCapParam(const VideoCaptureInfo &videoCapInfo);
    static int32_t CheckAudioEncParam(const AudioEncInfo &audioEncInfo);
    static int32_t CheckVideoEncParam(const VideoEncInfo &videoEncInfo);
    static int32_t CheckAudioCapInfo(AudioCaptureInfo &audioCapInfo);
    static int32_t CheckVideoCapInfo(VideoCaptureInfo &videoCapInfo);
    static int32_t CheckAudioEncInfo(AudioEncInfo &audioEncInfo);
    static int32_t CheckVideoEncInfo(VideoEncInfo &videoEncInfo);
    static int32_t CheckCaptureMode(CaptureMode captureMode);
    static int32_t CheckDataType(DataType dataType);
    static void GetChoiceFromJson(Json::Value &root, const std::string &content, std::string key, std::string &value);
    static void GetValueFromJson(Json::Value &root, const std::string &content, std::string key, bool &value);

private:
    static constexpr int32_t ROOT_UID = 0;
    static constexpr int32_t AUDIO_BITRATE_MIN = 8000;
    static constexpr int32_t AUDIO_BITRATE_MAX = 384000;
    static constexpr int32_t VIDEO_BITRATE_MIN = 1;
    static constexpr int32_t VIDEO_BITRATE_MAX = 30000000;
    static constexpr int32_t VIDEO_FRAME_RATE_MIN = 1;
    static constexpr int32_t VIDEO_FRAME_RATE_MAX = 60;
    static constexpr int32_t VIDEO_FRAME_WIDTH_MAX = 10240;
    static constexpr int32_t VIDEO_FRAME_HEIGHT_MAX = 4320;
    static constexpr int32_t SESSION_ID_INVALID = -1;
    static constexpr int32_t AV_SCREEN_CAPTURE_SESSION_UID = 1013;
    static constexpr const char *NOTIFICATION_SCREEN_RECORDING_TITLE_ID = "notification_screen_recording_title";
    static constexpr const char *QUOTATION_MARKS_STRING = "\"";
    static constexpr int64_t MAX_INNER_AUDIO_TIMEOUT_IN_NS = 2000000000; // 2s
    static constexpr int64_t AUDIO_INTERVAL_IN_NS = 20000000;            // 20ms
    static constexpr int64_t NEG_AUDIO_INTERVAL_IN_NS = -20000000;       // 20ms
    static constexpr int32_t SELECT_TYPE_SCREEN = 0;
    static constexpr int32_t SELECT_TYPE_WINDOW = 1;
    static constexpr int32_t SELECT_TYPE_APP = 2;
};
} // namespace OHOS::Media
#endif // SCREEN_CAPTURE_SERVICE_SERVER_H
