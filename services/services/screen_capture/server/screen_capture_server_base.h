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

#ifndef SCREEN_CAPTURE_SERVICE_SERVER_BASE_H
#define SCREEN_CAPTURE_SERVICE_SERVER_BASE_H

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
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif
#include "account_observer.h"
#include "media_data_source.h"
#include "meta/meta.h"
#include "audio_stream_manager.h"
#include "screen_capture_monitor_server.h"
#include "json/json.h"
#include "tokenid_kit.h"
#include "window_manager.h"
#include "limitIdGenerator.h"
#include "system_ability_status_change_stub.h"
#include "i_input_device_listener.h"
#include "input_manager.h"
#include "session_lifecycle_listener_stub.h"
#include "common_event_manager.h"

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
    INVALID_MODE = 3
};

enum class AVScreenCaptureMixBufferType : int32_t {
    MIX = 0,
    MIC = 1,
    INNER = 2,
    INVALID = 3
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
    int32_t StartBufferThread();
    void OnBufferAvailableAction();
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

#ifdef SUPPORT_CALL
class ScreenCaptureObserverCallBack : public InCallObserverCallBack, public AccountObserverCallBack {
#else
class ScreenCaptureObserverCallBack : public AccountObserverCallBack {
#endif
public:
    explicit ScreenCaptureObserverCallBack(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~ScreenCaptureObserverCallBack();
    bool StopAndRelease(AVScreenCaptureStateCode state) override;
    bool NotifyStopAndRelease(AVScreenCaptureStateCode state) override;
#ifdef SUPPORT_CALL
    bool TelCallStateUpdated(bool isInCall) override;
    bool NotifyTelCallStateUpdated(bool isInCall) override;
#endif
    void Release() override;
private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
    TaskQueue taskQueObserverCb_;
    std::mutex mutex_;
};

class AudioDataSource : public IAudioDataSource {
    class CacheBuffer {
    private:
        std::shared_ptr<AudioBuffer> refBuf_{nullptr};
        std::unique_ptr<uint8_t> buf_{nullptr};
    public:
        CacheBuffer() = delete;
        explicit CacheBuffer(const std::shared_ptr<AudioBuffer> &buf);
        CacheBuffer(uint8_t *buf, const int64_t &timestamp);
        int64_t timestamp{0};
        void WriteTo(const std::shared_ptr<AVMemory> &avMem, const uint32_t &len);
    };
public:
    AudioDataSource(AVScreenCaptureMixMode type, ScreenCaptureServer* screenCaptureServer) : type_(type),
        screenCaptureServer_(screenCaptureServer) {}

    int64_t GetFirstAudioTime(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState WriteInnerAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer);
    AudioDataSourceReadAtActionState WriteMicAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState WriteMixAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMix(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadWriteAudioBufferMixCore(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState HandleMicBeforeInnerSync(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState InnerMicAudioSync(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState VideoAudioSyncMixMode(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
        int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    AudioDataSourceReadAtActionState ReadAtMixMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAtMicMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAtInnerMode(std::shared_ptr<AVBuffer> buffer, uint32_t length);
    AudioDataSourceReadAtActionState ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length) override;
    AudioDataSourceReadAtActionState VideoAudioSyncInnerMode(std::shared_ptr<AVBuffer> &buffer,
        uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer);
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
    bool HasVoIPStream(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
    void SetAppPid(int32_t appid);
    void SetAppName(std::string appName);
    int32_t GetAppPid();
    bool GetIsInVoIPCall();
    bool GetSpeakerAliveStatus();
    bool IsInWaitMicSyncState();
#ifdef SUPPORT_CALL
    void TelCallAudioStateUpdate(
        const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos);
#endif
    void SetVideoFirstFramePts(int64_t firstFramePts) override;
    void SetAudioFirstFramePts(int64_t firstFramePts);
    AudioDataSourceReadAtActionState MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem);
    void HandlePastMicBuffer(std::shared_ptr<AudioBuffer> &micAudioBuffer);
    void HandleSwitchToSpeakerOptimise(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    void HandleBufferTimeStamp(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
        std::shared_ptr<AudioBuffer> &micAudioBuffer);
    ScreenCaptureServer* GetScreenCaptureServer();
private:
    void MixAudio(char** srcData, char* mixData, int channels, int bufferSize, int micBufferSize);
    AudioDataSourceReadAtActionState ReadAudioBuffer(std::shared_ptr<AVBuffer> &buffer, const uint32_t &length);
    int32_t LostFrameNum(const int64_t &timestamp);
    void FillLostBuffer(const int64_t &lostNum, const int64_t &timestamp, const uint32_t &bufferSize);
    int64_t writedFrameTime_{0};
    std::deque<CacheBuffer> audioBufferQ_;
    int32_t appPid_ { 0 };
    std::string appName_;
    bool speakerAliveStatus_ = true;
    std::atomic<bool> isInVoIPCall_ = false;
    std::mutex voipStatusChangeMutex_;
    std::atomic<int64_t> firstAudioFramePts_{-1};
    std::atomic<int64_t> firstVideoFramePts_{-1};
    std::atomic<int64_t> lastWriteAudioFramePts_{0};
    std::atomic<int64_t> lastMicAudioFramePts_{0};
    AVScreenCaptureMixBufferType lastWriteType_ = AVScreenCaptureMixBufferType::INVALID;
    int32_t stableStopInnerSwitchCount_ = 0;
    bool mixModeAddAudioMicFrame_ = false;
    bool isInWaitMicSyncState_ = false;
    AVScreenCaptureMixMode type_;
    ScreenCaptureServer* screenCaptureServer_;

    static constexpr int32_t INNER_SWITCH_MIC_REQUIRE_COUNT = 10;
    static constexpr int32_t ADS_LOG_SKIP_NUM = 1000;
    static constexpr int64_t MAX_INNER_AUDIO_TIMEOUT_IN_NS = 2000000000; // 2s
    static constexpr int64_t AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS = 10000000; // 10ms
    static constexpr int64_t AUDIO_INTERVAL_IN_NS = 21333334; // 20ms
    static constexpr int64_t NEG_AUDIO_INTERVAL_IN_NS = -21333334; // 20ms
    static constexpr int64_t SEC_TO_NS = 1000000000; // 1s
    static constexpr int64_t MAX_MIC_BEFORE_INNER_TIME_IN_NS = 40000000; // 40ms
    static constexpr int32_t FILL_AUDIO_FRAME_DURATION_IN_NS = 20000000; // 20ms
    static constexpr int32_t FILL_LOST_FRAME_COUNT_THRESHOLD = 5;
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

class ScreenConnectListenerForSC : public Rosen::ScreenManager::IScreenListener {
public:
    explicit ScreenConnectListenerForSC(uint64_t screenId, std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
        : screenId_(screenId), screenCaptureServer_(screenCaptureServer) {}
    void OnConnect(Rosen::ScreenId screenId);
    void OnDisconnect(Rosen::ScreenId screenId);
    void OnChange(Rosen::ScreenId screenId);
private:
    uint64_t screenId_ = SCREEN_ID_INVALID;
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};

class SCWindowLifecycleListener : public Rosen::SessionLifecycleListenerStub {
public:
    explicit SCWindowLifecycleListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~SCWindowLifecycleListener() override = default;
    void OnLifecycleEvent(SessionLifecycleEvent event, const LifecycleEventPayload& payload) override;
        
private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};
    
class SCDeathRecipientListener : public IRemoteObject::DeathRecipient {
public:
    using ListenerDiedHandler = std::function<void(const wptr<IRemoteObject>&)>;
    explicit SCDeathRecipientListener(ListenerDiedHandler handler) : diedHandler_(std::move(handler)) {}
    ~SCDeathRecipientListener() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) final
    {
        if (diedHandler_) {
            diedHandler_(remote);
        }
    }
    
private:
    ListenerDiedHandler diedHandler_;
};

class SCWindowInfoChangedListener : public Rosen::IWindowInfoChangedListener {
public:
    explicit SCWindowInfoChangedListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~SCWindowInfoChangedListener() override = default;
    void OnWindowInfoChanged(const std::vector<std::unordered_map<WindowInfoKey,
        WindowChangeInfoType>>& windowInfoList) override;

private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};

class ScreenCaptureSubscriber : public EventFwk::CommonEventSubscriber {
public:
    ScreenCaptureSubscriber(const EventFwk::CommonEventSubscribeInfo &subscribeInfo,
        const std::function<void(const EventFwk::CommonEventData &)> &callback)
        : EventFwk::CommonEventSubscriber(subscribeInfo), callback_(callback)
    {}

    ~ScreenCaptureSubscriber()
    {}

    void OnReceiveEvent(const EventFwk::CommonEventData &data) override
    {
        if (callback_ != nullptr) {
            callback_(data);
        }
    }

private:
    std::function<void(const EventFwk::CommonEventData &)> callback_;
};
} // namespace Media
} // namespace OHOS
#endif // SCREEN_CAPTURE_SERVICE_SERVER_BASE_H
