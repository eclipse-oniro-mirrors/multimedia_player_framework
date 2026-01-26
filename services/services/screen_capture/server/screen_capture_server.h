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

#include "screen_capture_server_base.h"
#include "ui_extension_ability_connection.h"
#include "audio_data_source.h"

namespace OHOS {
namespace Media {

class ScreenCaptureServer : public std::enable_shared_from_this<ScreenCaptureServer>,
        public IScreenCaptureService, public NoCopyable {
public:
    static std::map<int32_t, std::weak_ptr<ScreenCaptureServer>> serverMap_;
    static std::map<int32_t, std::pair<int32_t, int32_t>> saUidAppUidMap_;
    static const int32_t maxSessionId_;
    static const int32_t maxAppLimit_;
    static UniqueIDGenerator gIdGenerator_;
    static std::list<int32_t> startedSessionIDList_;
    static const int32_t maxSessionPerUid_;
    static const int32_t maxSCServerDataTypePerUid_;
    static std::shared_mutex mutexServerMapRWGlobal_;
    static std::shared_mutex mutexListRWGlobal_;
    static std::shared_mutex mutexSaAppInfoMapGlobal_;
    static std::atomic<int32_t> systemScreenRecorderPid_;

    static std::shared_ptr<IScreenCaptureService> Create();
    static bool IsSAServiceCalling();
    static bool CanScreenCaptureInstanceBeCreate(int32_t appUid);
    static std::shared_ptr<IScreenCaptureService> CreateScreenCaptureNewInstance();
    static int32_t ReportAVScreenCaptureUserChoice(int32_t sessionId, const std::string &content);
    static int32_t GetRunningScreenCaptureInstancePid(std::list<int32_t> &pidList);
    static int32_t GetAVScreenCaptureConfigurableParameters(int32_t sessionId, std::string &resultStr);
    static void GetChoiceFromJson(Json::Value &root, const std::string &content, std::string key, std::string &value);
    static void GetValueFromJson(Json::Value &root, const std::string &content, std::string key, bool &value);
    static void AddScreenCaptureServerMap(int32_t sessionId, std::weak_ptr<ScreenCaptureServer> server);
    static void RemoveScreenCaptureServerMap(int32_t sessionId);
    static bool CheckScreenCaptureSessionIdLimit(int32_t curAppUid);
    static bool CheckSCServerSpecifiedDataTypeNum(int32_t curAppUid, DataType dataType);
    static void CountScreenCaptureAppNum(std::set<int32_t>& appSet);
    static bool CheckScreenCaptureAppLimit(int32_t curAppUid);
    static std::shared_ptr<ScreenCaptureServer> GetScreenCaptureServerById(int32_t id);
    static std::shared_ptr<ScreenCaptureServer> GetScreenCaptureServerByIdWithLock(int32_t id);
    static std::list<int32_t> GetStartedScreenCaptureServerPidList();
    static int32_t CountStartedScreenCaptureServerNumByPid(int32_t pid);
    static void AddStartedSessionIdList(int32_t value);
    static void RemoveStartedSessionIdList(int32_t value);
    static std::list<int32_t> GetAllStartedSessionIdList();
    static void AddSaAppInfoMap(int32_t saUid, int32_t curAppUid);
    static void RemoveSaAppInfoMap(int32_t saUid);
    static bool CheckSaUid(int32_t saUid, int32_t appUid);
    static bool IsSaUidValid(int32_t saUid, int32_t appUid);
    static bool CheckPidIsScreenRecorder(int32_t pid);
    ScreenCaptureServer();
    ~ScreenCaptureServer();

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
    int32_t PresentPicker() override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
        int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    bool GetMicWorkingState();
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t ShowCursor(bool showCursor) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    void Release() override;
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override;
    int32_t AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec) override;
    int32_t ExcludePickerWindows(std::vector<int32_t> &windowIDsVec) override;
    int32_t SetPickerMode(PickerMode pickerMode) override;
    int32_t SetScreenCaptureStrategy(ScreenCaptureStrategy strategy) override;
    int32_t SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config) override;
    int32_t UpdateSurface(sptr<Surface> surface) override;
    int32_t SetCaptureArea(uint64_t displayId, OHOS::Rect area) override;

    void SetSessionId(int32_t sessionId);
    void GetAndSetAppVersion();
    bool CheckAppVersionForUnsupport(DMError result);
    int32_t OnReceiveUserPrivacyAuthority(bool isAllowed);
    int32_t StopScreenCaptureByEvent(AVScreenCaptureStateCode stateCode);
    std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> GetWantAgent(const std::string& callingLabel,
        int32_t sessionId);
    void SystemPrivacyProtected(ScreenId& virtualScreenId, bool systemPrivacyProtectionSwitch);
    void AppPrivacyProtected(ScreenId& virtualScreenId, bool appPrivacyProtectionSwitch);
    void OnUpdateMirrorDisplay(std::vector<uint64_t> &displayIds);
    void OnWindowInfoChanged(const uint64_t &displayId);
    void OnWindowLifecycle(SCWindowLifecycleListener::SessionLifecycleEvent event);
#ifdef SUPPORT_CALL
    int32_t TelCallStateUpdated(bool isInTelCall);
    int32_t TelCallAudioStateUpdated(bool isInTelCallAudio);
#endif
    void UpdateMicrophoneEnabled();
    int32_t ReleaseMicAudioBuffer();
    int32_t ReleaseInnerAudioBuffer();
    int32_t GetInnerAudioCaptureBufferSize(size_t &size);
    int32_t GetMicAudioCaptureBufferSize(size_t &size);
    int32_t OnVoIPStatusChanged(bool isInVoIPCall);
    int32_t OnSpeakerAliveStatusChanged(bool speakerAliveStatus);
    int32_t ShowCursorInner();
    void OnDMPrivateWindowChange(bool hasPrivate);
    void SetMissionId(uint64_t missionId);
    void SetDisplayId(uint64_t displayId);
    void SetDisplayId(std::vector<uint64_t> &&displayIds);
    void SetDisplayScreenId(uint64_t displayId);
    void SetDisplayScreenId(std::vector<uint64_t> &&displayIds);
    bool IsTelInCallSkipList();
    int32_t GetAppPid();
    int32_t GetAppUid();
    void NotifyStateChange(AVScreenCaptureStateCode stateCode);
    void NotifyDisplaySelected(uint64_t displayId);
    void NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent event, ScreenCaptureRect* area);
    void NotifyUserSelected(ScreenCaptureUserSelectionInfo selectionInfo);
    int32_t SetAndCheckAppInfo(OHOS::AudioStandard::AppInfo &appInfo);
    void SetSCServerSaUid(int32_t saUid);
    int32_t GetSCServerSaUid();
    DataType GetSCServerDataType();
    AVScreenCaptureState GetSCServerCaptureState();
    bool IsSCRecorderFileWithVideo();
    std::shared_ptr<AudioCapturerWrapper> GetInnerAudioCapture();
    std::shared_ptr<AudioCapturerWrapper> GetMicAudioCapture();
    bool IsStopAcquireAudioBufferFlag();
    bool IsMicrophoneSwitchTurnOn();
    bool IsMicrophoneCaptureRunning();
    bool IsInnerCaptureRunning();
    void SetInnerAudioCapture(std::shared_ptr<AudioCapturerWrapper> innerAudioCapture);
    int32_t StopInnerAudioCapture();
    void SetWindowIdList(uint64_t windowId);
    std::vector<int32_t> GetWindowIdList();
    void OnSceneSessionManagerDied(const wptr<IRemoteObject>& remote);
    void SetDefaultDisplayIdOfWindows();
    bool IsCaptureScreen(uint64_t displayId);
    void SetCurDisplayId(uint64_t displayId);
    uint64_t GetCurDisplayId();
private:
    int32_t StartScreenCaptureInner(bool isPrivacyAuthorityEnabled);
    int32_t RegisterServerCallbacks();
    int32_t OnStartScreenCapture();
    bool IsFirstStartPidInstance(int32_t pid);
    bool FirstPidUpdatePrivacyUsingPermissionState(int32_t pid);
    void PostStartScreenCapture(bool isSuccess);
    void PostStartScreenCaptureFail();
    void PostStartScreenCaptureSuccessAction();
    int32_t InitRecorderInfo(std::shared_ptr<IRecorderService> &recorder, AudioCaptureInfo audioInfo);
    int32_t InitRecorderMix();
    int32_t InitRecorderInner();
    int32_t InitRecorder();
    OutlineShape ConvertToOutlineShape(ScreenCaptureHighlightMode mode);
    void UpdateHighlightOutline(bool isStarted);
    void SetHighlightConfigForWindowManager(bool isStarted,
        Rosen::OutlineParams &outlineParams);
    int32_t StartScreenCaptureFile();
    int32_t StartScreenCaptureStream();
    int32_t StartAudioCapture();
    std::string GenerateThreadNameByPrefix(std::string threadName);
    int32_t StartStreamInnerAudioCapture();
    int32_t StartStreamMicAudioCapture();
    int32_t StartFileInnerAudioCapture();
    int32_t StartFileMicAudioCapture();
    int32_t StartMicAudioCapture();
    int32_t StopMicAudioCapture();
    int32_t StartStreamVideoCapture();
    int32_t StartStreamHomeVideoCapture();
    int32_t StopScreenCaptureInner(AVScreenCaptureStateCode stateCode);
    void StopScreenCaptureInnerUnBind();
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
    void CloseFd();
    void ReleaseInner();
    void GetDumpFlag();
    void GetSystemUIFlag();
    int32_t SetMicrophoneOn();
    int32_t SetMicrophoneOff();

    VirtualScreenOption InitVirtualScreenOption(const std::string &name, sptr<OHOS::Surface> consumer);
    int32_t GetMissionIds(std::vector<uint64_t> &missionIds);
    int32_t MakeVirtualScreenMirrorForWindow(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirrorForHomeScreen(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirrorForSpecifiedScreen(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirror();
    int32_t CreateVirtualScreen(const std::string &name, sptr<OHOS::Surface> consumer);
    int32_t SetVirtualScreenAutoRotation();
    int32_t PrepareVirtualScreenMirror();
    void DestroyVirtualScreen();
    void ParseDisplayId(const Json::Value &displayIdJson);
    void HandleSetDisplayIdAndMissionId(Json::Value &root);

    bool CheckScreenCapturePermission();
    bool IsUserPrivacyAuthorityNeeded();
    bool UpdatePrivacyUsingPermissionState(VideoPermissionState state);
    bool CheckPrivacyWindowSkipPermission();
    int32_t RequestUserPrivacyAuthority(bool &isSkipPrivacyWindow);
    int32_t StartPrivacyWindow(const std::string &cmdStr);
    int32_t StartAuthWindow();
    void SetCaptureConfig(CaptureMode captureMode, int32_t missionId = -1); // -1 invalid
    ScreenScaleMode GetScreenScaleMode(const AVScreenCaptureFillMode &fillMode);
    int32_t HandlePopupWindowCase(Json::Value& root, const std::string &content);
    int32_t HandleStreamDataCase(Json::Value& root, const std::string &content);
    int32_t HandlePresentPickerWindowCase(Json::Value& root, const std::string &content);
    void PrepareSelectWindow(Json::Value &root);
    bool IsSkipPrivacyWindow();
    void BuildCommonParams(Json::Value &root);

#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    bool CheckCaptureSpecifiedWindowForSelectWindow();
    bool IsPickerPopUp();
    int32_t StartPicker();
#ifdef PC_STANDARD
    void SendConfigToUIParams(AAFwk::Want& want);
#elif defined(SUPPORT_PICKER_PHONE_PAD)
    void BuildPickerParams(Json::Value &root);
#endif
#endif

#ifdef PC_STANDARD
    bool IsHopper();
    int32_t MakeVirtualScreenMirrorForWindowForHopper(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirrorForHomeScreenForHopper(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    int32_t MakeVirtualScreenMirrorForSpecifiedScreenForHopper(const sptr<Rosen::Display> &defaultDisplay,
        std::vector<ScreenId> &mirrorIds);
    bool CheckCustScrRecPermission();
    void SetTimeoutScreenoffDisableLock(bool lockScreen);
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    int32_t TryStartNotification();
    int32_t TryNotificationOnPostStartScreenCapture();
#endif
    int32_t StartNotification();
    void SetupPublishRequest(NotificationRequest &request);
    void InitLiveViewContent();
    void UpdateLiveViewContent();
    void UpdateLiveViewPrivacy();
    std::shared_ptr<PixelMap> GetPixelMap(std::string path);
    std::shared_ptr<PixelMap> GetPixelMapSvg(std::string path, int32_t width, int32_t height);
    void ResSchedReportData(int64_t value, std::unordered_map<std::string, std::string> payload);
    int64_t GetCurrentMillisecond();
    void SetMetaDataReport();
    void SetMediaKitReport(const std::string &errMsg);
    void SetErrorInfo(int32_t errCode, const std::string &errMsg, StopReason stopReason, bool userAgree);
    int32_t ReStartMicForVoIPStatusSwitch();
    void RegisterPrivateWindowListener();
    void RegisterScreenConnectListener();
    uint64_t GetDisplayIdOfWindows(uint64_t displayId);
    std::string GetStringByResourceName(const char* name);
    void RefreshResConfig();
    void InitResourceManager();
    void SetSystemScreenRecorderStatus(bool status);
#ifdef SUPPORT_CALL
    int32_t OnTelCallStart();
    int32_t OnTelCallStop();
#endif
    bool DestroyPopWindow();
    bool DestroyPrivacySheet();
    void StopNotStartedScreenCapture(AVScreenCaptureStateCode stateCode);
    int32_t RegisterWindowLifecycleListener(std::vector<int32_t> windowIdList);
    int32_t UnRegisterWindowLifecycleListener();
    int32_t RegisterWindowInfoChangedListener();
    int32_t UnRegisterWindowInfoChangedListener();
    int32_t RegisterWindowRelatedListener();
    int32_t SetCaptureAreaInner(uint64_t displayId, OHOS::Rect area);
    bool CheckDisplayArea(uint64_t displayId, OHOS::Rect area);
    void PrepareUserSelectionInfo(ScreenCaptureUserSelectionInfo &selectionInfo);
    void RegisterLanguageSwitchListener();
    void OnReceiveEvent(const EventFwk::CommonEventData &data);
    void UnRegisterLanguageSwitchListener();
    int32_t HandleOriginalStreamPrivacy();
    void PublishScreenCaptureEvent(const std::string& state);
    void OnCaptureContentChanged(bool isMirrorChanged = false);
    int32_t RegisterRecordDisplayListener();
    int32_t UnRegisterRecordDisplayListener();
private:
    std::mutex mutex_;
    std::mutex cbMutex_;
    std::mutex innerMutex_;
    std::mutex inCallMutex_;
    std::mutex displayScreenIdsMutex_;
    std::shared_mutex windowIdListMutex_;
    mutable std::shared_mutex rw_lock_;
    std::shared_ptr<ScreenCaptureObserverCallBack> screenCaptureObserverCb_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    bool canvasRotation_ = false;
    bool showCursor_ = true;
    bool isMicrophoneSwitchTurnOn_ = true;
    bool isPrivacyAuthorityEnabled_ = false;
    bool showSensitiveCheckBox_ = false;
    bool checkBoxSelected_ = false;
    bool showShareSystemAudioBox_ = false;
    bool isInnerAudioBoxSelected_ = true;
    bool appPrivacyProtectionSwitch_ = true;
    bool systemPrivacyProtectionSwitch_ = true;
    std::vector<uint64_t> surfaceIdList_ = {};
    std::vector<uint8_t> surfaceTypeList_ = {};
    std::atomic<bool> stopAcquireAudioBufferFromAudio_ = false;
    AVScreenCaptureMixMode recorderFileAudioType_ = AVScreenCaptureMixMode::INVALID_MODE;

    int32_t sessionId_ = 0;
    int32_t notificationId_ = 0;
    std::string callingLabel_;
    std::string liveViewText_;
    std::string liveViewSubText_;
    std::atomic<int32_t> micCount_{0};
    float density_ = 0.0f;
    int32_t capsuleVpSize_ = 18;
    int32_t capsulePxSize_ = 0;
    int32_t saUid_ = -1;
    int32_t appVersion_ = -1;

    /* used for both CAPTURE STREAM and CAPTURE FILE */
    OHOS::AudioStandard::AppInfo appInfo_;
    bool isScreenCaptureAuthority_ = false;
    bool isPresentPicker_ = false;
    bool isPresentPickerPopWindow_ = false;
    std::string appName_ = "";
    AVScreenCaptureConfig captureConfig_;
    AVScreenCaptureAvType avType_ = AVScreenCaptureAvType::INVALID_TYPE;
    AVScreenCaptureDataMode dataMode_ = AVScreenCaptureDataMode::BUFFER_MODE;
    StatisticalEventInfo statisticalEventInfo_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    sptr<OHOS::Surface> producerSurface_ = nullptr;
    bool isConsumerStart_ = false;
    bool isDump_ = false;
    bool isSystemUI2_ = false;
    ScreenId virtualScreenId_ = SCREEN_ID_INVALID;
    std::vector<ScreenId> displayScreenIds_;
    std::vector<ScreenId> displayIds_;
    std::vector<uint64_t> missionIds_;
    std::vector<int32_t> windowIdList_ = {};
    std::atomic<ScreenId> curWindowInDisplayId_{SCREEN_ID_INVALID};
    std::atomic<AVScreenCaptureContentChangedEvent> curWindowEvent_ =
        AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
    std::atomic<SCWindowLifecycleListener::SessionLifecycleEvent> curWindowLifecycle_ =
        SCWindowLifecycleListener::SessionLifecycleEvent::FOREGROUND;
    ScreenCaptureContentFilter contentFilter_;
    AVScreenCaptureState captureState_ = AVScreenCaptureState::CREATED;
    std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent_;
    int64_t startTime_ = 0;
    sptr<UIExtensionAbilityConnection> connection_ = nullptr;
    sptr<SCWindowLifecycleListener> windowLifecycleListener_ = nullptr;
    sptr<SCDeathRecipientListener> lifecycleListenerDeathRecipient_ = nullptr;
    sptr<SCWindowInfoChangedListener> windowInfoChangedListener_ = nullptr;
    sptr<ScreenManager::IRecordDisplayListener> recordDisplayListener_ = nullptr;
    bool isRegionCapture_ = false;
    uint64_t regionDisplayId_ = 0;
    OHOS::Rect regionArea_ = {0, 0, 0, 0};

    /* used for CAPTURE STREAM */
    sptr<IBufferConsumerListener> surfaceCb_ = nullptr;
    sptr<OHOS::Surface> surface_ = nullptr;
    bool isSurfaceMode_ = false;
    std::shared_ptr<AudioCapturerWrapper> innerAudioCapture_;
    std::shared_ptr<AudioCapturerWrapper> micAudioCapture_;
    std::mutex innerAudioMutex_;

    /* used for CAPTURE FILE */
    std::shared_ptr<IRecorderService> recorder_ = nullptr;
    std::string url_;
    OutputFormatType fileFormat_ = OutputFormatType::FORMAT_DEFAULT;
    int32_t outputFd_ = -1;
    int32_t audioSourceId_ = 0;
    int32_t videoSourceId_ = 0;
    std::shared_ptr<AudioDataSource> audioSource_ = nullptr;
    /* used for DFX events */
    uint64_t instanceId_ = 0;
    std::shared_ptr<ScreenRendererAudioStateChangeCallback> captureCallback_;
    std::vector<uint64_t> skipPrivacyWindowIDsVec_;
    sptr<DisplayManager::IPrivateWindowListener> displayListener_;
    bool isCalledBySystemApp_ = false;
    Global::Resource::ResourceManager *resourceManager_ = nullptr;
    Global::Resource::ResConfig *resConfig_ = nullptr;
    OHOS::sptr<Rosen::ScreenManager::IScreenListener> screenConnectListener_ = nullptr;
    std::shared_ptr<ScreenCaptureSubscriber> subscriber_ = nullptr;

    /* used for customize picker */
    std::vector<int32_t> excludedWindowIDsVec_;
    PickerMode pickerMode_ = PickerMode::SCREEN_AND_WINDOW;
#ifdef SUPPORT_CALL
    std::atomic<bool> isInTelCall_ = false;
    std::atomic<bool> isInTelCallAudio_ = false;
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
    static constexpr const char* NOTIFICATION_SCREEN_RECORDING_TITLE_ID = "notification_screen_recording_title";
    static constexpr const char* QUOTATION_MARKS_STRING = "\"";
    static constexpr const char* NOTIFICATION_SCREEN_RECORDING_PRIVACY_ON_ID =
        "notification_screen_recording_privacy_on";
    static constexpr const char* NOTIFICATION_SCREEN_RECORDING_PRIVACY_OFF_ID =
        "notification_screen_recording_privacy_off";
    static constexpr int64_t MAX_INNER_AUDIO_TIMEOUT_IN_NS = 2000000000; // 2s
    static constexpr int64_t AUDIO_INTERVAL_IN_NS = 20000000; // 20ms
    static constexpr int64_t NEG_AUDIO_INTERVAL_IN_NS = -20000000; // 20ms
    static constexpr int32_t SELECT_TYPE_SCREEN = 0;
    static constexpr int32_t SELECT_TYPE_WINDOW = 1;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_SERVER_H
