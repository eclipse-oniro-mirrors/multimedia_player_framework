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
class AudioDataSource;

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
    explicit ScreenConnectListenerForSC(std::vector<uint64_t> screenIds,
        std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
        : screenIds_(std::move(screenIds)), screenCaptureServer_(std::move(screenCaptureServer)) {}
    void OnConnect(Rosen::ScreenId screenId) override;
    void OnDisconnect(Rosen::ScreenId screenId) override;
    void OnChange(Rosen::ScreenId screenId) override;
private:
    std::vector<uint64_t> screenIds_;
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
