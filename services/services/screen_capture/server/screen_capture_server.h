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

#include <mutex>
#include <cstdlib>
#include <thread>
#include <string>
#include <memory>
#include <atomic>
#include <queue>
#include <vector>
#include <chrono>

#include "audio_capturer_wrapper.h"
#include "i_screen_capture_service.h"
#include "nocopyable.h"
#include "uri_helper.h"
#include "task_queue.h"
#include "accesstoken_kit.h"
#include "privacy_kit.h"
#include "ipc_skeleton.h"
#include "screen_capture.h"
#include "audio_capturer.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#include "audio_info.h"
#include "surface.h"
#include "display_manager.h"
#include "screen_manager.h"
#include "i_recorder_service.h"
#include "recorder_server.h"
#include "notification_content.h"
#include "notification_helper.h"
#include "notification_request.h"
#include "notification_constant.h"
#include "notification_slot.h"
#include "incall_observer.h"
#include "account_observer.h"
#include "media_data_source.h"
#include "meta/meta.h"
#include "audio_stream_manager.h"
#include "screen_capture_monitor_server.h"
#include "json/json.h"
#include "tokenid_kit.h"
#include "window_manager.h"
#include "limitIdGenerator.h"

namespace OHOS {
namespace Media {
using namespace Rosen;
using namespace AudioStandard;
using namespace OHOS::Notification;
using OHOS::Security::AccessToken::PrivacyKit;

class ScreenCaptureServer;

class NotificationSubscriber : public OHOS::Notification::NotificationLocalLiveViewSubscriber {
public:
    void OnConnected() override;
    void OnDisconnected() override;
    void OnResponse(int32_t notificationId,
        OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption) override;
    void OnDied() override;
};

enum VideoPermissionState : int32_t {
    START_VIDEO = 0,
    STOP_VIDEO = 1
};

enum AVScreenCaptureState : int32_t {
    CREATED = 0,
    POPUP_WINDOW = 1,
    STARTING = 2,
    STARTED = 3,
    STOPPED = 4
};

enum AVScreenCaptureMixMode : int32_t {
    MIX_MODE = 0,
    MIC_MODE = 1,
    INNER_MODE = 2,
    INVAILD_MODE = 3
};

enum AVScreenCaptureAvType : int8_t {
    INVALID_TYPE = -1,
    AUDIO_TYPE = 0,
    VIDEO_TYPE = 1,
    AV_TYPE = 2
};

enum AVScreenCaptureDataMode : int8_t {
    BUFFER_MODE = 0,
    SUFFACE_MODE = 1,
    FILE_MODE = 2
};

enum StopReason: int8_t {
    NORMAL_STOPPED = 0,
    RECEIVE_USER_PRIVACY_AUTHORITY_FAILED = 1,
    POST_START_SCREENCAPTURE_HANDLE_FAILURE = 2,
    REQUEST_USER_PRIVACY_AUTHORITY_FAILED = 3,
    STOP_REASON_INVALID = 4
};

struct SurfaceBufferEntry {
    SurfaceBufferEntry(sptr<OHOS::SurfaceBuffer> buf, int32_t fence, int64_t timeStamp, OHOS::Rect& damage)
        : buffer(std::move(buf)), flushFence(fence), timeStamp(timeStamp), damageRect(damage) {}
    ~SurfaceBufferEntry() noexcept = default;

    sptr<OHOS::SurfaceBuffer> buffer;
    int32_t flushFence;
    int64_t timeStamp = 0;
    OHOS::Rect damageRect = {0, 0, 0, 0};
};

struct StatisticalEventInfo {
    int32_t errCode = 0;
    std::string errMsg;
    int32_t captureDuration = -1;
    bool userAgree = false;
    bool requireMic = false;
    bool enableMic = false;
    std::string videoResolution;
    StopReason stopReason = StopReason::STOP_REASON_INVALID;
    int32_t startLatency = -1;
};

enum class SCBufferMessageType {
    EXIT,
    GET_BUFFER
};

struct SCBufferMessage {
    SCBufferMessageType type;
    std::string text;
};

class ScreenCapBufferConsumerListener : public IBufferConsumerListener {
public:
    ScreenCapBufferConsumerListener(
        sptr<Surface> consumer, const std::shared_ptr<ScreenCaptureCallBack> &screenCaptureCb)
        : consumer_(consumer), screenCaptureCb_(screenCaptureCb) {}
    ~ScreenCapBufferConsumerListener();

    void OnBufferAvailable() override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence, int64_t &timestamp,
        OHOS::Rect &damage);
    int32_t ReleaseVideoBuffer();
    int32_t Release();
    void OnBufferAvailableAction();
    void StartBufferThread();
    void SurfaceBufferThreadRun();
    void StopBufferThread();

private:
    int32_t ReleaseBuffer();
    void ProcessVideoBufferCallBack();

private:
    std::mutex bufferAvailableWorkerMtx_;
    std::condition_variable bufferAvailableWorkerCv_;
    std::queue<SCBufferMessage> messageQueueSCB_;

    std::mutex mutex_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    std::atomic<bool> isSurfaceCbInThreadStopped_ {true};
    std::thread* surfaceCbInThread_ = nullptr;

    std::mutex bufferMutex_;
    std::condition_variable bufferCond_;
    std::queue<std::unique_ptr<SurfaceBufferEntry>> availBuffers_;

    static constexpr uint64_t MAX_MESSAGE_QUEUE_SIZE = 5;
    static constexpr uint32_t MAX_BUFFER_SIZE = 3;
    static constexpr uint32_t OPERATION_TIMEOUT_IN_MS = 1000; // 1000ms
};

class ScreenCaptureObserverCallBack : public InCallObserverCallBack, public AccountObserverCallBack {
public:
    explicit ScreenCaptureObserverCallBack(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~ScreenCaptureObserverCallBack() = default;
    bool StopAndRelease(AVScreenCaptureStateCode state) override;

private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};

class AudioDataSource : public IAudioDataSource {
public:
    AudioDataSource(AVScreenCaptureMixMode type, ScreenCaptureServer* screenCaptureServer) : type_(type),
        screenCaptureServer_(screenCaptureServer) {}

    int32_t ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override;
    int32_t GetSize(int64_t &size) override;
    int32_t RegisterAudioRendererEventListener(const int32_t clientPid,
        const std::shared_ptr<AudioRendererStateChangeCallback> &callback);
    int32_t UnregisterAudioRendererEventListener(const int32_t clientPid);
    void SpeakerStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    bool HasSpeakerStream(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void VoIPStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void SetAppPid(int32_t appid);
    void SetAppName(std::string appName);
    int32_t GetAppPid();
    bool GetIsInVoIPCall();
    bool GetSpeakerAliveStatus();

private:
    int32_t MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem);
    int32_t appPid_ { 0 };
    std::string appName_;
    bool speakerAliveStatus_ = true;
    std::atomic<bool> isInVoIPCall_ = false;
    std::mutex voipStatusChangeMutex_;

    void MixAudio(char** srcData, char* mixData, int channels, int bufferSize);

    AVScreenCaptureMixMode type_;
    ScreenCaptureServer* screenCaptureServer_;

    static constexpr int32_t ADS_LOG_SKIP_NUM = 1000;
};

class PrivateWindowListenerInScreenCapture : public DisplayManager::IPrivateWindowListener {
public:
    explicit PrivateWindowListenerInScreenCapture(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~PrivateWindowListenerInScreenCapture() = default;
    void OnPrivateWindow(bool hasPrivate) override;

private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};

class ScreenRendererAudioStateChangeCallback : public AudioRendererStateChangeCallback {
public:
    void OnRendererStateChange(const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void SetAudioSource(std::shared_ptr<AudioDataSource> audioSource);
    void SetAppName(std::string appName);
private:
    std::shared_ptr<AudioDataSource> audioSource_ = nullptr;
    std::string appName_;
};

class ScreenCaptureServer : public std::enable_shared_from_this<ScreenCaptureServer>,
        public IScreenCaptureService, public NoCopyable {
public:
    static std::map<int32_t, std::weak_ptr<ScreenCaptureServer>> serverMap_;
    static const int32_t maxSessionId_;
    static const int32_t maxAppLimit_;
    static UniqueIDGenerator gIdGenerator_;
    static std::list<int32_t> startedSessionIDList_;
    static const int32_t maxSessionPerUid_;
    static std::shared_mutex mutexServerMapRWGlobal_;
    static std::shared_mutex mutexListRWGlobal_;

    static std::shared_ptr<IScreenCaptureService> Create();
    static bool CanScreenCaptureInstanceBeCreate();
    static std::shared_ptr<IScreenCaptureService> CreateScreenCaptureNewInstance();
    static int32_t ReportAVScreenCaptureUserChoice(int32_t sessionId, const std::string &content);
    static int32_t GetRunningScreenCaptureInstancePid(std::list<int32_t> &pidList);
    static void GetChoiceFromJson(Json::Value &root, const std::string &content, std::string key, std::string &value);
    static void PrepareSelectWindow(Json::Value &root, std::shared_ptr<ScreenCaptureServer> &server);
    static void AddScreenCaptureServerMap(int32_t sessionId, std::weak_ptr<ScreenCaptureServer> server);
    static void RemoveScreenCaptureServerMap(int32_t sessionId);
    static bool CheckScreenCaptureSessionIdLimit(int32_t curAppUid);
    static void CountScreenCaptureAppNum(std::set<int32_t>& appSet);
    static bool CheckScreenCaptureAppLimit(int32_t curAppUid);
    static std::shared_ptr<ScreenCaptureServer> GetScreenCaptureServerByIdWithLock(int32_t id);
    static std::list<int32_t> GetStartedScreenCaptureServerPidList();
    static int32_t CountStartedScreenCaptureServerNumByPid(int32_t pid);
    static void AddStartedSessionIdList(int32_t value);
    static void RemoveStartedSessionIdList(int32_t value);
    static std::list<int32_t> GetAllStartedSessionIdList();
    ScreenCaptureServer();
    ~ScreenCaptureServer();

    int32_t SetCaptureMode(CaptureMode captureMode) override;
    int32_t SetDataType(DataType dataType) override;
    int32_t SetRecorderInfo(RecorderInfo recorderInfo) override;
    int32_t SetOutputFile(int32_t outputFd) override;
    int32_t InitAudioEncInfo(AudioEncInfo audioEncInfo) override;
    int32_t InitAudioCap(AudioCaptureInfo audioInfo) override;
    int32_t InitVideoEncInfo(VideoEncInfo videoEncInfo) override;
    int32_t InitVideoCap(VideoCaptureInfo videoInfo) override;
    int32_t StartScreenCapture(bool isPrivacyAuthorityEnabled) override;
    int32_t StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled) override;
    int32_t StopScreenCapture() override;
    int32_t SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback) override;
    int32_t AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type) override;
    int32_t AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
        int64_t &timestamp, OHOS::Rect &damage) override;
    int32_t ReleaseAudioBuffer(AudioCaptureSourceType type) override;
    int32_t ReleaseVideoBuffer() override;
    int32_t SetMicrophoneEnabled(bool isMicrophone) override;
    bool GetMicWorkingState();
    int32_t SetCanvasRotation(bool canvasRotation) override;
    int32_t ResizeCanvas(int32_t width, int32_t height) override;
    int32_t SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec) override;
    int32_t SetMaxVideoFrameRate(int32_t frameRate) override;
    void Release() override;
    int32_t ExcludeContent(ScreenCaptureContentFilter &contentFilter) override;

    void SetSessionId(int32_t sessionId);
    int32_t OnReceiveUserPrivacyAuthority(bool isAllowed);
    int32_t StopScreenCaptureByEvent(AVScreenCaptureStateCode stateCode);
    void UpdateMicrophoneEnabled();

    int32_t AcquireAudioBufferMix(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer, AVScreenCaptureMixMode type);
    int32_t ReleaseAudioBufferMix(AVScreenCaptureMixMode type);
    int32_t ReleaseMicAudioBuffer();
    int32_t ReleaseInnerAudioBuffer();
    int32_t GetInnerAudioCaptureBufferSize(size_t &size);
    int32_t GetMicAudioCaptureBufferSize(size_t &size);
    int32_t OnVoIPStatusChanged(bool isInVoIPCall);
    int32_t OnSpeakerAliveStatusChanged(bool speakerAliveStatus);
    void OnDMPrivateWindowChange(bool hasPrivate);
    void SetMissionId(uint64_t missionId);
    void SetDisplayId(uint64_t displayId);
    bool IsTelInCallSkipList();
    int32_t GetAppPid();
    int32_t GetAppUid();

private:
    int32_t StartScreenCaptureInner(bool isPrivacyAuthorityEnabled);
    int32_t RegisterServerCallbacks();
    int32_t OnStartScreenCapture();
    bool IsFirstStartPidInstance(int32_t pid);
    bool FirstPidUpdatePrivacyUsingPermissionState(int32_t pid);
    void PostStartScreenCapture(bool isSuccess);
    void PostStartScreenCaptureSuccessAction();
    int32_t InitRecorderInfo(std::shared_ptr<IRecorderService> &recorder, AudioCaptureInfo audioInfo);
    int32_t InitRecorder();
    int32_t StartScreenCaptureFile();
    int32_t StartScreenCaptureStream();
    int32_t StartAudioCapture();
    std::string GenerateThreadNameByPrefix(std::string threadName);
    int32_t StartStreamInnerAudioCapture();
    int32_t StartStreamMicAudioCapture();
    int32_t StartFileInnerAudioCapture();
    int32_t StartFileMicAudioCapture();
    int32_t StopMicAudioCapture();
    int32_t StartVideoCapture();
    int32_t StartHomeVideoCapture();
    int32_t StopScreenCaptureInner(AVScreenCaptureStateCode stateCode);
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
    int32_t SetMicrophoneOn();
    int32_t SetMicrophoneOff();

    VirtualScreenOption InitVirtualScreenOption(const std::string &name, sptr<OHOS::Surface> consumer);
    int32_t GetMissionIds(std::vector<uint64_t> &missionIds);
    int32_t MakeVirtualScreenMirror();
    int32_t CreateVirtualScreen(const std::string &name, sptr<OHOS::Surface> consumer);
    int32_t PrepareVirtualScreenMirror();
    void DestroyVirtualScreen();

    bool CheckScreenCapturePermission();
    bool IsUserPrivacyAuthorityNeeded();
    bool UpdatePrivacyUsingPermissionState(VideoPermissionState state);
    int32_t RequestUserPrivacyAuthority();
    int32_t StartPrivacyWindow();
    void SetCaptureConfig(CaptureMode captureMode, int32_t missionId = -1); // -1 invalid
#ifdef PC_STANDARD
    bool CheckCaptureSpecifiedWindowForSelectWindow();
    void SendConfigToUIParams(AAFwk::Want& want);
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    int32_t TryStartNotification();
    int32_t TryNotificationOnPostStartScreenCapture();
#endif
    int32_t StartNotification();
    std::shared_ptr<NotificationLocalLiveViewContent> GetLocalLiveViewContent();
    void UpdateLiveViewContent();
    std::shared_ptr<PixelMap> GetPixelMap(std::string path);
    std::shared_ptr<PixelMap> GetPixelMapSvg(std::string path, int32_t width, int32_t height);
    void ResSchedReportData(int64_t value, std::unordered_map<std::string, std::string> payload);
    int64_t GetCurrentMillisecond();
    void SetMetaDataReport();
    void SetErrorInfo(int32_t errCode, const std::string &errMsg, StopReason stopReason, bool userAgree);
    int32_t ReStartMicForVoIPStatusSwitch();
    void RegisterPrivateWindowListener();
    uint64_t GetDisplayIdOfWindows(uint64_t displayId);
    std::string GetStringByResourceName(const char* name);
    void RefreshResConfig();
    void InitResourceManager();

private:
    std::mutex mutex_;
    std::mutex cbMutex_;
    std::shared_ptr<ScreenCaptureObserverCallBack> screenCaptureObserverCb_ = nullptr;
    std::shared_ptr<ScreenCaptureCallBack> screenCaptureCb_ = nullptr;
    bool canvasRotation_ = false;
    bool isMicrophoneOn_ = true;
    bool isPrivacyAuthorityEnabled_ = false;

    int32_t sessionId_ = 0;
    int32_t notificationId_ = 0;
    std::string callingLabel_;
    std::string liveViewText_;
    std::atomic<int32_t> micCount_{0};
    float density_ = 0.0f;
    int32_t capsuleVpSize_ = 18;
    int32_t capsulePxSize_ = 0;

    /* used for both CAPTURE STREAM and CAPTURE FILE */
    OHOS::AudioStandard::AppInfo appInfo_;
    std::string appName_ = "";
    AVScreenCaptureConfig captureConfig_;
    AVScreenCaptureAvType avType_ = AVScreenCaptureAvType::INVALID_TYPE;
    AVScreenCaptureDataMode dataMode_ = AVScreenCaptureDataMode::BUFFER_MODE;
    StatisticalEventInfo statisticalEventInfo_;
    sptr<OHOS::Surface> consumer_ = nullptr;
    bool isConsumerStart_ = false;
    bool isDump_ = false;
    ScreenId screenId_ = SCREEN_ID_INVALID;
    std::vector<uint64_t> missionIds_;
    ScreenCaptureContentFilter contentFilter_;
    AVScreenCaptureState captureState_ = AVScreenCaptureState::CREATED;
    std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent_;
    int64_t startTime_ = 0;

    /* used for CAPTURE STREAM */
    sptr<IBufferConsumerListener> surfaceCb_ = nullptr;
    sptr<OHOS::Surface> surface_ = nullptr;
    bool isSurfaceMode_ = false;
    std::shared_ptr<AudioCapturerWrapper> innerAudioCapture_;
    std::shared_ptr<AudioCapturerWrapper> micAudioCapture_;

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
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_SERVER_H
