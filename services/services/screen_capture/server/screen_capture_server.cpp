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

#include "ability_connection.h"
#include "ability_manager_client.h"
#include "screen_capture_server.h"
#include "ui_extension_ability_connection.h"
#include "extension_manager_client.h"
#include "image_source.h"
#include "image_type.h"
#include "iservice_registry.h"
#include "pixel_map.h"
#include "media_log.h"
#include "media_errors.h"
#include "media_utils.h"
#include "uri_helper.h"
#include "media_dfx.h"
#include "scope_guard.h"
#include "screen_capture_listener_proxy.h"
#include "system_ability_definition.h"
#include "res_type.h"
#include "res_sched_client.h"
#include "param_wrapper.h"
#include <unistd.h>
#include <sys/stat.h>
#include "hitrace/tracechain.h"
#include "locale_config.h"
#include <sync_fence.h>
#include "parameter.h"
#include <unordered_map>
#include <algorithm>
#include <set>
#include <common/rs_common_def.h>
#include "session_manager_lite.h"
#include "window_manager_lite.h"
#include "want_agent_info.h"
#include "want_agent_helper.h"
#include "common_event_manager.h"
#ifdef PC_STANDARD
#include "power_mgr_client.h"
#include <parameters.h>
#endif

using OHOS::Rosen::DMError;

namespace {
const std::string DUMP_PATH = "/data/media/screen_capture.bin";
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServer"};
}

namespace OHOS {
namespace Media {

static const std::string MP4 = "mp4";
static const std::string M4A = "m4a";

static const std::string USER_CHOICE_ALLOW = "true";
static const std::string USER_CHOICE_DENY = "false";
static const std::string CHECK_BOX_SELECTED = "true";
static const std::string JSON_VALUE_TRUE = "true";
static const std::string BUTTON_NAME_MIC = "mic";
static const std::string BUTTON_NAME_STOP = "stop";
static const std::string ICON_PATH_CAPSULE_STOP = "/etc/screencapture/capsule_stop.svg";
static const std::string ICON_PATH_CAPSULE_STOP_2_0 = "/etc/screencapture/capsule_stop_live2.svg";
static const std::string ICON_PATH_NOTIFICATION = "/etc/screencapture/notification.png";
static const std::string ICON_PATH_MIC = "/etc/screencapture/mic.svg";
static const std::string ICON_PATH_MIC_OFF = "/etc/screencapture/mic_off.svg";
static const std::string ICON_PATH_STOP = "/etc/screencapture/light.svg";
static const std::string BACK_GROUND_COLOR = "#E84026";
static const std::string SYS_SCR_RECR_KEY = "const.multimedia.screencapture.screenrecorderbundlename";
static const std::string VIRTUAL_SCREENAME_SCREEN_CAPTRURE = "screeen_capture";
static const std::string VIRTUAL_SCREENAME_SCREEN_CAPTRURE_FILE = "screeen_capture_file";
#ifdef PC_STANDARD
static const std::string SELECT_ABILITY_NAME = "SelectWindowAbility";
static const int32_t SELECT_WINDOW_MISSION_ID_NUM_MAX = 2;
static const std::string PERM_CUST_SCR_REC = "ohos.permission.CUSTOM_SCREEN_RECORDING";
static const std::string TIMEOUT_SCREENOFF_DISABLE_LOCK = "ohos.permission.TIMEOUT_SCREENOFF_DISABLE_LOCK";
#endif
static const int32_t SVG_HEIGHT = 80;
static const int32_t SVG_WIDTH = 80;
static const int32_t WINDOW_INFO_LIST_SIZE = 1;
static const int32_t MEDIA_SERVICE_SA_ID = 3002;
static const uint32_t MIN_LINE_WIDTH = 1;
static const uint32_t MAX_LINE_WIDTH = 8;
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    static const int32_t NOTIFICATION_MAX_TRY_NUM = 3;
#endif

static const auto NOTIFICATION_SUBSCRIBER = NotificationSubscriber();
static constexpr int32_t AUDIO_CHANGE_TIME = 80000; // 80 ms
static const int32_t UNSUPPORT_ERROR_CODE_API_VERSION_ISOLATION = 20;

const int32_t ScreenCaptureServer::maxSessionId_ = 16;
const int32_t ScreenCaptureServer::maxAppLimit_ = 4;
UniqueIDGenerator ScreenCaptureServer::gIdGenerator_(ScreenCaptureServer::maxSessionId_);
std::list<int32_t> ScreenCaptureServer::startedSessionIDList_;
const int32_t ScreenCaptureServer::maxSessionPerUid_ = 4;
const int32_t ScreenCaptureServer::maxSCServerDataTypePerUid_ = 2;
std::atomic<int32_t> ScreenCaptureServer::systemScreenRecorderPid_ = -1;

std::shared_mutex ScreenCaptureServer::mutexServerMapRWGlobal_;
std::shared_mutex ScreenCaptureServer::mutexListRWGlobal_;
std::shared_mutex ScreenCaptureServer::mutexSaAppInfoMapGlobal_;

void NotificationSubscriber::OnConnected()
{
    MEDIA_LOGI("NotificationSubscriber OnConnected");
}

void NotificationSubscriber::OnDisconnected()
{
    MEDIA_LOGI("NotificationSubscriber OnDisconnected");
}

void NotificationSubscriber::OnResponse(int32_t notificationId,
                                        OHOS::sptr<OHOS::Notification::NotificationButtonOption> buttonOption)
{
    CHECK_AND_RETURN(buttonOption != nullptr);
    MEDIA_LOGI("NotificationSubscriber OnResponse notificationId : %{public}d, ButtonName : %{public}s ",
        notificationId, (buttonOption->GetButtonName()).c_str());

    std::shared_ptr<ScreenCaptureServer> server =
        ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(notificationId);
    if (server == nullptr) {
        MEDIA_LOGW("OnResponse ScreenCaptureServer not exist, notificationId : %{public}d, ButtonName : %{public}s ",
            notificationId, (buttonOption->GetButtonName()).c_str());
        return;
    }
    if (BUTTON_NAME_STOP.compare(buttonOption->GetButtonName()) == 0) {
        server->StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
        return;
    }
    if (BUTTON_NAME_MIC.compare(buttonOption->GetButtonName()) == 0) {
        server->UpdateMicrophoneEnabled();
        return;
    }
}

void NotificationSubscriber::OnDied()
{
    MEDIA_LOGI("NotificationSubscriber OnDied");
}

PrivateWindowListenerInScreenCapture::PrivateWindowListenerInScreenCapture(
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " PrivateWindowListenerInScreenCapture Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

void PrivateWindowListenerInScreenCapture::OnPrivateWindow(bool hasPrivate)
{
    MEDIA_LOGI("PrivateWindowListenerInScreenCapture hasPrivateWindow: %{public}u", hasPrivate);
    auto scrServer = screenCaptureServer_.lock();
    if (scrServer) {
        MEDIA_LOGI("Callback OnDMPrivateWindowChange hasPrivateWindow: %{public}u", hasPrivate);
        scrServer->OnDMPrivateWindowChange(hasPrivate);
    }
}

void ScreenConnectListenerForSC::OnConnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerForSC OnConnect screenId: %{public}" PRIu64, screenId);
}

void ScreenConnectListenerForSC::OnDisconnect(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerForSC OnDisconnect screenId: %{public}" PRIu64 "screenId_: %{public}" PRIu64,
        screenId, screenId_);
    auto callbackPtr = screenCaptureServer_.lock();
    if (callbackPtr && screenId == screenId_) {
        MEDIA_LOGI("ScreenConnectListenerForSC OnDisconnect NotifyCaptureContentChanged: %{public}" PRIu64, screenId_);
        callbackPtr->NotifyCaptureContentChanged(
            AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE, nullptr);
    }
}

void ScreenConnectListenerForSC::OnChange(Rosen::ScreenId screenId)
{
    MEDIA_LOGI("ScreenConnectListenerForSC OnChange screenId: %{public}" PRIu64, screenId);
}

void ScreenCaptureServer::AddScreenCaptureServerMap(int32_t sessionId,
    std::weak_ptr<ScreenCaptureServer> server)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    ScreenCaptureServer::serverMap_.insert(std::make_pair(sessionId, server));
    MEDIA_LOGI("AddScreenCaptureServerMap end, serverMap size: %{public}d.",
        static_cast<uint32_t>(ScreenCaptureServer::serverMap_.size()));
}

void ScreenCaptureServer::RemoveScreenCaptureServerMap(int32_t sessionId)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    ScreenCaptureServer::serverMap_.erase(sessionId);
    int32_t returnId = ScreenCaptureServer::gIdGenerator_.ReturnID(sessionId);
    if (returnId == -1) {
        MEDIA_LOGI("RemoveScreenCaptureServerMap returnId: %{public}d is invalid", returnId);
    }
    MEDIA_LOGI("RemoveScreenCaptureServerMap end. sessionId: %{public}d, serverMap size: %{public}d.",
        sessionId, static_cast<uint32_t>(ScreenCaptureServer::serverMap_.size()));
}

bool ScreenCaptureServer::CheckScreenCaptureSessionIdLimit(int32_t curAppUid)
{
    int32_t countForUid = 0;
    MEDIA_LOGI("CheckScreenCaptureSessionIdLimit start. curAppUid: %{public}d.", curAppUid);
    {
        std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
        for (auto iter = ScreenCaptureServer::serverMap_.begin(); iter != ScreenCaptureServer::serverMap_.end();
            iter++) {
                auto iterPtr = (iter->second).lock();
                if (iterPtr != nullptr) {
                    if (curAppUid == iterPtr->GetAppUid()) {
                        countForUid++;
                    }
                    CHECK_AND_RETURN_RET_LOG(countForUid <= ScreenCaptureServer::maxSessionPerUid_, false,
                        "Create failed, uid(%{public}d) has created too many ScreenCaptureServer instances", curAppUid);
                }
            }
    }
    MEDIA_LOGI("CheckScreenCaptureSessionIdLimit end.");
    return true;
}

bool ScreenCaptureServer::CheckSCServerSpecifiedDataTypeNum(int32_t curAppUid, DataType dataType)
{
    int32_t countForUidDataType = 0;
    MEDIA_LOGI("CheckSCServerSpecifiedDataTypeNum start. curAppUid: %{public}d, dataType: %{public}d.",
        curAppUid, dataType);
    {
        std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
        for (auto iter = ScreenCaptureServer::serverMap_.begin(); iter != ScreenCaptureServer::serverMap_.end();
            iter++) {
                auto iterPtr = (iter->second).lock();
                if (iterPtr != nullptr) {
                    if (curAppUid == iterPtr->GetAppUid() && dataType == iterPtr->GetSCServerDataType()) {
                        countForUidDataType++;
                    }
                    CHECK_AND_RETURN_RET_LOG(countForUidDataType <= ScreenCaptureServer::maxSCServerDataTypePerUid_,
                        false, "CheckSCServerSpecifiedDataTypeNum failed,"
                        "uid(%{public}d) has created too many instances of dataType(%{public}d)", curAppUid, dataType);
                }
            }
    }
    MEDIA_LOGI("CheckSCServerSpecifiedDataTypeNum end.");
    return true;
}

void ScreenCaptureServer::CountScreenCaptureAppNum(std::set<int32_t>& appSet)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    for (auto iter = ScreenCaptureServer::serverMap_.begin(); iter != ScreenCaptureServer::serverMap_.end(); iter++) {
        auto iterPtr = iter->second.lock();
        if (iterPtr != nullptr) {
            appSet.insert(iterPtr->GetAppUid());
        }
    }
}

bool ScreenCaptureServer::CheckScreenCaptureAppLimit(int32_t curAppUid)
{
    std::set<int32_t> appSet;
    CountScreenCaptureAppNum(appSet);
    MEDIA_LOGI("appSet.size(): %{public}d", static_cast<int32_t>(appSet.size()));
    if (static_cast<int32_t>(appSet.size()) > ScreenCaptureServer::maxAppLimit_) {
        return false;
    }
    return true;
}

std::shared_ptr<ScreenCaptureServer> ScreenCaptureServer::GetScreenCaptureServerById(int32_t id)
{
    auto iter = ScreenCaptureServer::serverMap_.find(id);
    if (iter == ScreenCaptureServer::serverMap_.end()) {
        return nullptr;
    }
    return (iter->second).lock();
}

std::shared_ptr<ScreenCaptureServer> ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(int32_t id)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    return GetScreenCaptureServerById(id);
}

std::list<int32_t> ScreenCaptureServer::GetStartedScreenCaptureServerPidList()
{
    std::list<int32_t> startedScreenCapturePidList{};
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        std::shared_ptr<ScreenCaptureServer> currentServer = GetScreenCaptureServerById(sessionId);
        if (currentServer != nullptr) {
            startedScreenCapturePidList.push_back(currentServer->GetAppPid() == 0 ? -1 : currentServer->GetAppPid());
        }
    }
    return startedScreenCapturePidList;
}

int32_t ScreenCaptureServer::CountStartedScreenCaptureServerNumByPid(int32_t pid)
{
    int32_t count = 0;
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        std::shared_ptr<ScreenCaptureServer> currentServer = GetScreenCaptureServerById(sessionId);
        if (currentServer != nullptr && currentServer->GetAppPid() == pid) {
            count++;
        }
    }
    return count;
}

void ScreenCaptureServer::AddStartedSessionIdList(int32_t value)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexListRWGlobal_);
    ScreenCaptureServer::startedSessionIDList_.push_back(value);
}

void ScreenCaptureServer::RemoveStartedSessionIdList(int32_t value)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexListRWGlobal_);
    ScreenCaptureServer::startedSessionIDList_.remove(value);
}

std::list<int32_t> ScreenCaptureServer::GetAllStartedSessionIdList()
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexListRWGlobal_);
    return GetStartedScreenCaptureServerPidList();
}

bool ScreenCaptureServer::CheckPidIsScreenRecorder(int32_t pid)
{
    MEDIA_LOGI("CheckPidIsScreenRecorder ScreenRecorder pid(%{public}d), input pid(%{public}d)",
        (ScreenCaptureServer::systemScreenRecorderPid_).load(), pid);
    return pid == (ScreenCaptureServer::systemScreenRecorderPid_).load();
}

void ScreenCaptureServer::OnDMPrivateWindowChange(bool hasPrivate)
{
    MEDIA_LOGI("OnDMPrivateWindowChange hasPrivateWindow: %{public}u", hasPrivate);
    NotifyStateChange(hasPrivate ?
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_ENTER_PRIVATE_SCENE :
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_EXIT_PRIVATE_SCENE);
}

void ScreenCaptureServer::SetWindowIdList(uint64_t windowId)
{
    windowIdList_.push_back(static_cast<int32_t>(windowId));
}

std::vector<int32_t> ScreenCaptureServer::GetWindowIdList()
{
    return windowIdList_;
}

uint64_t ScreenCaptureServer::GetDefaultDisplayId()
{
    return displayScreenId_;
}

void ScreenCaptureServer::SetCurDisplayId(uint64_t displayId)
{
    curWindowInDisplayId_ = displayId;
}

uint64_t ScreenCaptureServer::GetCurDisplayId()
{
    return curWindowInDisplayId_;
}

void ScreenCaptureServer::SetDefaultDisplayIdOfWindows()
{
    MEDIA_LOGI("SetDefaultDisplayIdOfWindows Start");
    sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_LOG(defaultDisplay != nullptr, "SetDefaultDisplayIdOfWindows GetDefaultDisplaySync failed");

    uint64_t defaultDisplayId = defaultDisplay->GetScreenId();
    std::unordered_map<uint64_t, uint64_t> windowDisplayIdMap;
    {
        std::shared_lock<std::shared_mutex> read_lock(rw_lock_);
        auto ret = WindowManager::GetInstance().GetDisplayIdByWindowId(missionIds_, windowDisplayIdMap);
        CHECK_AND_RETURN_LOG(ret == Rosen::WMError::WM_OK,
            "SetDefaultDisplayIdOfWindows GetDisplayIdByWindowId failed");
        MEDIA_LOGI("SetDefaultDisplayIdOfWindows GetDisplayIdByWindowId ret: %{public}d", ret);
    }
    for (const auto& pair : windowDisplayIdMap) {
        MEDIA_LOGD("SetDefaultDisplayIdOfWindows 0x%{public}06" PRIXPTR " WindowId:%{public}" PRIu64
            " in DisplayId:%{public}" PRIu64, FAKE_POINTER(this), pair.first, pair.second);
            defaultDisplayId = pair.second;
    }
    displayScreenId_ = defaultDisplayId;
    SetCurDisplayId(displayScreenId_);
    MEDIA_LOGI("SetDefaultDisplayIdOfWindows End. defaultDisplayId: %{public}" PRIu64, displayScreenId_);
}

void ScreenCaptureServer::OnSceneSessionManagerDied(const wptr<IRemoteObject>& remote)
{
    MEDIA_LOGI("OnSceneSessionManagerDied Start");
    windowLifecycleListener_ = nullptr;
    windowInfoChangedListener_ = nullptr;

    auto remoteObj = remote.promote();
    if (!remoteObj) {
        MEDIA_LOGD("invalid remote object");
        return;
    }
    remoteObj->RemoveDeathRecipient(lifecycleListenerDeathRecipient_);
    lifecycleListenerDeathRecipient_ = nullptr;
    MEDIA_LOGI("SCB Crash! Please Check!");

    int32_t ret = RegisterWindowRelatedListener();
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "OnSceneSessionManagerDied: RegisterWindowRelatedListener failed.");
    MEDIA_LOGI("OnSceneSessionManagerDied End");
}

int32_t ScreenCaptureServer::RegisterWindowLifecycleListener(std::vector<int32_t> windowIdList)
{
    MEDIA_LOGI("RegisterWindowLifecycleListener start, windowIdListSize: %{public}d",
        static_cast<int32_t>(windowIdList.size()));
    CHECK_AND_RETURN_RET_LOG(static_cast<int32_t>(windowIdList.size()) != 0, MSERR_OK,
        "windowIdList is empty");
    auto sceneSessionManager = SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION,
        "sceneSessionManager is nullptr, RegisterWindowLifecycleListener failed.");

    if (!lifecycleListenerDeathRecipient_) {
        MEDIA_LOGD("RegisterWindowLifecycleListener lifecycleListenerDeathRecipient_ is nullptr");
        auto task = [weakThis = weak_from_this()] (const wptr<IRemoteObject>& remote) {
            auto SCServer = weakThis.lock();
            if (SCServer) {
                SCServer->OnSceneSessionManagerDied(remote);
            }
        };
        lifecycleListenerDeathRecipient_ = sptr<SCDeathRecipientListener>::MakeSptr(task);

        auto listenerObject = sceneSessionManager->AsObject();
        if (listenerObject) {
            listenerObject->AddDeathRecipient(lifecycleListenerDeathRecipient_);
            MEDIA_LOGI("RegisterWindowLifecycleListener AddDeathRecipient success.");
        }
    }

    if (windowLifecycleListener_ != nullptr) {
        MEDIA_LOGI("RegisterWindowLifecycleListener windowLifecycleListener already registered");
        return MSERR_OK;
    }
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    sptr<SCWindowLifecycleListener> listener(new (std::nothrow) SCWindowLifecycleListener(screenCaptureServer));
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_INVALID_OPERATION,
        "create new windowLifecycleListener failed.");
    windowLifecycleListener_ = listener;

    Rosen::WMError ret = sceneSessionManager->RegisterSessionLifecycleListenerByIds(windowLifecycleListener_,
        windowIdList);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "RegisterSessionLifecycleListenerByIds failed.");

    MEDIA_LOGI("RegisterWindowLifecycleListener end.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::UnRegisterWindowLifecycleListener()
{
    MEDIA_LOGI("UnRegisterWindowLifecycleListener start.");
    auto sceneSessionManager = SessionManagerLite::GetInstance().GetSceneSessionManagerLiteProxy();
    CHECK_AND_RETURN_RET_LOG(sceneSessionManager != nullptr, MSERR_INVALID_OPERATION,
        "sceneSessionManager is nullptr, UnRegisterWindowLifecycleListener failed.");

    if (lifecycleListenerDeathRecipient_) {
        MEDIA_LOGD("UnRegisterWindowLifecycleListener lifecycleListenerDeathRecipient_ != nullptr");
        auto listenerObject = sceneSessionManager->AsObject();
        if (listenerObject) {
            listenerObject->RemoveDeathRecipient(lifecycleListenerDeathRecipient_);
            MEDIA_LOGI("UnRegisterWindowLifecycleListener RemoveDeathRecipient success.");
        }
        lifecycleListenerDeathRecipient_ = nullptr;
    }

    if (!windowLifecycleListener_) {
        MEDIA_LOGI("windowLifecycleListener already unregistered");
        return MSERR_OK;
    }
    Rosen::WMError ret = sceneSessionManager->UnregisterSessionLifecycleListener(windowLifecycleListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "UnRegisterWindowLifecycleListener failed.");
    windowLifecycleListener_ = nullptr;

    MEDIA_LOGI("UnRegisterWindowLifecycleListener end.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::RegisterWindowInfoChangedListener()
{
    MEDIA_LOGI("RegisterWindowInfoChangedListener start.");

    if (windowInfoChangedListener_) {
        MEDIA_LOGI("RegisterWindowInfoChangedListener: windowInfoChangedListener already registered");
        return MSERR_OK;
    }

    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    sptr<SCWindowInfoChangedListener> listener(new (std::nothrow) SCWindowInfoChangedListener(screenCaptureServer));
    CHECK_AND_RETURN_RET_LOG(listener != nullptr, MSERR_INVALID_OPERATION,
        "create new windowInfoChangedListener failed.");
    windowInfoChangedListener_ = listener;
    windowInfoChangedListener_->AddInterestInfo(Rosen::WindowInfoKey::WINDOW_ID);
    CHECK_AND_RETURN_RET_LOG(!windowIdList_.empty(), MSERR_INVALID_OPERATION,
        "windowIdList is empty, AddInterestWindowId failed.");
    windowInfoChangedListener_->AddInterestWindowId(windowIdList_.front());

    std::unordered_set<Rosen::WindowInfoKey> observedInfo;
    observedInfo.insert(Rosen::WindowInfoKey::DISPLAY_ID);
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().RegisterWindowInfoChangeCallback(
        observedInfo, windowInfoChangedListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "RegisterWindowInfoChangedListener failed.");

    MEDIA_LOGI("RegisterWindowInfoChangedListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::UnRegisterWindowInfoChangedListener()
{
    MEDIA_LOGI("UnRegisterWindowInfoChangedListener start.");

    if (!windowInfoChangedListener_) {
        MEDIA_LOGI("UnRegisterWindowInfoChangedListener: windowInfoChangedListener already unregistered");
        return MSERR_OK;
    }

    std::unordered_set<Rosen::WindowInfoKey> observedInfo;
    observedInfo.insert(Rosen::WindowInfoKey::DISPLAY_ID);
    Rosen::WMError ret = Rosen::WindowManager::GetInstance().UnregisterWindowInfoChangeCallback(
        observedInfo, windowInfoChangedListener_);
    CHECK_AND_RETURN_RET_LOG(ret == Rosen::WMError::WM_OK, MSERR_INVALID_OPERATION,
        "UnRegisterWindowInfoChangedListener failed.");
    windowInfoChangedListener_ = nullptr;

    MEDIA_LOGI("UnRegisterWindowInfoChangedListener end");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::RegisterWindowRelatedListener()
{
    int32_t ret = RegisterWindowLifecycleListener(windowIdList_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
        "RegisterWindowRelatedListener RegisterWindowLifecycleListener failed");
    ret = RegisterWindowInfoChangedListener();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
        "RegisterWindowRelatedListener RegisterWindowInfoChangedListener failed");
    return MSERR_OK;
}

void ScreenCaptureServer::NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect* area)
{
    if (screenCaptureCb_ != nullptr && captureState_ != AVScreenCaptureState::STOPPED) {
        MEDIA_LOGI("NotifyCaptureContentChanged event: %{public}d", event);
        screenCaptureCb_->OnCaptureContentChanged(event, area);
    }
}

SCWindowLifecycleListener::SCWindowLifecycleListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " SCWindowLifecycleListener Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

void SCWindowLifecycleListener::OnLifecycleEvent(SessionLifecycleEvent event, const LifecycleEventPayload& payload)
{
    MEDIA_LOGI("SCWindowLifecycleListener::OnLifecycleEvent Start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");
    switch (event) {
        case SessionLifecycleEvent::FOREGROUND: {
            MEDIA_LOGI("OnLifecycleEvent: SessionLifecycleEvent::FOREGROUND");
            if (SCServer->GetCurDisplayId() == SCServer->GetDefaultDisplayId() &&
                SCServer->GetWindowIdList().size() > 0) {
                WindowInfoOption windowInfoOption;
                std::vector<sptr<WindowInfo>> infos;
                windowInfoOption.windowId = SCServer->GetWindowIdList().front();
                Rosen::WMError ret = Rosen::WindowManager::GetInstance().ListWindowInfo(windowInfoOption, infos);
                CHECK_AND_RETURN_LOG(ret == Rosen::WMError::WM_OK && infos.size() > 0, "ListWindowInfo failed.");
                SCServer->NotifyCaptureContentChanged(
                    AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE,
                    reinterpret_cast<ScreenCaptureRect*>(&(infos.front()->windowLayoutInfo.rect)));
            }
            break;
        }
        case SessionLifecycleEvent::BACKGROUND: {
            MEDIA_LOGI("OnLifecycleEvent: SessionLifecycleEvent::BACKGROUND");
            if (SCServer->GetCurDisplayId() == SCServer->GetDefaultDisplayId()) {
                SCServer->NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE,
                    nullptr);
            }
            break;
        }
        case SessionLifecycleEvent::DESTROYED: {
            MEDIA_LOGI("OnLifecycleEvent: SessionLifecycleEvent::DESTROYED");
            SCServer->NotifyCaptureContentChanged(
                AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_UNAVAILABLE, nullptr);
            break;
        }
        default: {
            MEDIA_LOGD("OnLifecycleEvent: other event");
            break;
        }
    }
    MEDIA_LOGI("SCWindowLifecycleListener::OnLifecycleEvent End.");
}

SCWindowInfoChangedListener::SCWindowInfoChangedListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " SCWindowInfoChangedListener Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

void SCWindowInfoChangedListener::OnWindowInfoChanged(
    const std::vector<std::unordered_map<WindowInfoKey, WindowChangeInfoType>>& windowInfoList)
{
    MEDIA_LOGI("SCWindowInfoChangedListener::OnWindowInfoChanged start.");
    auto SCServer = screenCaptureServer_.lock();
    CHECK_AND_RETURN_LOG(SCServer != nullptr, "screenCaptureServer is nullptr");

    std::vector<std::unordered_map<WindowInfoKey, WindowChangeInfoType>> myWindowInfoList = windowInfoList;
    if (myWindowInfoList.size() < WINDOW_INFO_LIST_SIZE ||
        SCServer->GetWindowIdList().size() < WINDOW_INFO_LIST_SIZE) {
        MEDIA_LOGI("myWindowInfoList or windowIdList is invalid.");
        return;
    }

    MEDIA_LOGI("OnWindowInfoChanged: the displayId of interestWindowId changed!");
    auto iter = myWindowInfoList.front().find(WindowInfoKey::DISPLAY_ID);
    if (iter != myWindowInfoList.front().end()) {
        uint64_t displayId = std::get<uint64_t>(iter->second);
        MEDIA_LOGI("OnWindowInfoChanged: the curDisplayId: %{public}" PRIu64, displayId);
        SCServer->SetCurDisplayId(displayId);
        if (displayId == SCServer->GetDefaultDisplayId()) {
            MEDIA_LOGI("OnWindowInfoChanged: window back to initial display!");
            if (SCServer->GetWindowIdList().size() > 0) {
                WindowInfoOption windowInfoOption;
                std::vector<sptr<WindowInfo>> infos;
                windowInfoOption.windowId = SCServer->GetWindowIdList().front();
                Rosen::WMError ret = Rosen::WindowManager::GetInstance().ListWindowInfo(windowInfoOption, infos);
                CHECK_AND_RETURN_LOG(ret == Rosen::WMError::WM_OK && infos.size() > 0, "ListWindowInfo failed.");
                SCServer->NotifyCaptureContentChanged(
                    AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE,
                    reinterpret_cast<ScreenCaptureRect*>(&(infos.front()->windowLayoutInfo.rect)));
            }
        } else {
            MEDIA_LOGI("OnWindowInfoChanged: window switched to new display!");
            SCServer->NotifyCaptureContentChanged(
                AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE, nullptr);
        }
    } else {
        MEDIA_LOGI("OnWindowInfoChanged myWindowInfoList cannot find DISPLAY_ID_KEY");
    }
}

bool ScreenCaptureServer::CanScreenCaptureInstanceBeCreate(int32_t appUid)
{
    MEDIA_LOGI("CanScreenCaptureInstanceBeCreate start.");
    CHECK_AND_RETURN_RET_LOG(ScreenCaptureServer::serverMap_.size() <= ScreenCaptureServer::maxSessionId_, false,
        "ScreenCaptureInstanceCanBeCreate exceed ScreenCaptureServer instances limit.");
    MEDIA_LOGI("curAppUid: %{public}d", appUid);
    CHECK_AND_RETURN_RET_LOG(CheckScreenCaptureAppLimit(appUid), false,
        "CurScreenCaptureAppNum reach limit, cannot create more app.");
    return CheckScreenCaptureSessionIdLimit(appUid);
}

std::shared_ptr<IScreenCaptureService> ScreenCaptureServer::CreateScreenCaptureNewInstance()
{
    MEDIA_LOGI("CreateScreenCaptureNewInstance");
    int32_t id = ScreenCaptureServer::gIdGenerator_.GetNewID();
    CHECK_AND_RETURN_RET_LOG(id != -1, nullptr, "GetNewID failed.");
    MEDIA_LOGI("CreateScreenCaptureNewInstance newId: %{public}d", id);
    std::shared_ptr<ScreenCaptureServer> server = std::make_shared<ScreenCaptureServer>();
    CHECK_AND_RETURN_RET_LOG(server != nullptr, nullptr, "Failed to create ScreenCaptureServer.");
    server->SetSessionId(id);
    server->GetAndSetAppVersion();
    AddScreenCaptureServerMap(id, server);
    return std::static_pointer_cast<IScreenCaptureService>(server);
}

bool ScreenCaptureServer::IsSAServiceCalling()
{
    MEDIA_LOGI("ScreenCaptureServer::IsSAServiceCalling START.");
    const auto tokenId = IPCSkeleton::GetCallingTokenID();
    const auto tokenTypeFlag = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenTypeFlag == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenTypeFlag == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        MEDIA_LOGI("ScreenCaptureServer::IsSAServiceCalling true.");
        return true;
    }
    return false;
}

std::shared_ptr<IScreenCaptureService> ScreenCaptureServer::Create()
{
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        MEDIA_LOGD("ScreenCaptureServer::Create sessionId: %{public}d", sessionId);
    }
    MEDIA_LOGI("ScreenCaptureServer Create start.");
    return CreateScreenCaptureNewInstance();
}

void ScreenCaptureServer::AddSaAppInfoMap(int32_t saUid, int32_t curAppUid)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexSaAppInfoMapGlobal_);
    if (ScreenCaptureServer::saUidAppUidMap_.find(saUid) == ScreenCaptureServer::saUidAppUidMap_.end()) {
        ScreenCaptureServer::saUidAppUidMap_.insert({saUid, std::make_pair(curAppUid, 1)});
        MEDIA_LOGI("AddSaAppInfoMap insert SUCCESS! mapSize: %{public}d",
            static_cast<uint32_t>(ScreenCaptureServer::saUidAppUidMap_.size()));
    } else {
        ScreenCaptureServer::saUidAppUidMap_[saUid].second++;
    }
}

void ScreenCaptureServer::RemoveSaAppInfoMap(int32_t saUid)
{
    CHECK_AND_RETURN(saUid != -1);
    MEDIA_LOGI("RemoveSaAppInfoMap saUid: %{public}d is valid.", saUid);
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexSaAppInfoMapGlobal_);
    if (ScreenCaptureServer::saUidAppUidMap_.find(saUid) != ScreenCaptureServer::saUidAppUidMap_.end() &&
        ScreenCaptureServer::saUidAppUidMap_[saUid].second > 0) {
        ScreenCaptureServer::saUidAppUidMap_[saUid].second--;
        if (ScreenCaptureServer::saUidAppUidMap_[saUid].second == 0) {
            ScreenCaptureServer::saUidAppUidMap_.erase(saUid);
        }
    }
    MEDIA_LOGI("RemoveSaAppInfoMap END! mapSize: %{public}d",
        static_cast<uint32_t>(ScreenCaptureServer::saUidAppUidMap_.size()));
}

bool ScreenCaptureServer::CheckSaUid(int32_t saUid, int32_t appUid)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexSaAppInfoMapGlobal_);
    if (ScreenCaptureServer::saUidAppUidMap_.find(saUid) != ScreenCaptureServer::saUidAppUidMap_.end()) {
        if (ScreenCaptureServer::saUidAppUidMap_[saUid].first != appUid ||
            (ScreenCaptureServer::saUidAppUidMap_[saUid].first == appUid &&
            ScreenCaptureServer::saUidAppUidMap_[saUid].second >= ScreenCaptureServer::maxSessionPerUid_)) {
                MEDIA_LOGI("saUid Invalid! saUid: %{public}d linked with appUid: %{public}d, curAppUid: %{public}d",
                    saUid, ScreenCaptureServer::saUidAppUidMap_[saUid].first, appUid);
                return false;
            }
    }
    return true;
}

bool ScreenCaptureServer::IsSaUidValid(int32_t saUid, int32_t appUid)
{
    CHECK_AND_RETURN_RET_LOG(saUid >= 0 && appUid >= 0, false, "saUid or appUid is invalid.");
    CHECK_AND_RETURN_RET_LOG(IsSAServiceCalling(), false, "fake SAServiceCalling!");
    return CheckSaUid(saUid, appUid);
}

int32_t ScreenCaptureServer::SetAndCheckAppInfo(OHOS::AudioStandard::AppInfo &appInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SetAndCheckAppInfo(appInfo)");
    const int32_t saUid = IPCSkeleton::GetCallingUid();
    if (saUid >= 0) {
        SetSCServerSaUid(saUid);
    }
    if (!IsSaUidValid(saUid, appInfo.appUid)) {
        MEDIA_LOGI("SetAndCheckAppInfo failed, saUid-appUid exists.");
        SetSCServerSaUid(-1);
        return MSERR_INVALID_OPERATION;
    }

    appInfo_.appUid = appInfo.appUid;
    appInfo_.appPid = appInfo.appPid;
    appInfo_.appTokenId = appInfo.appTokenId;
    appInfo_.appFullTokenId = appInfo.appFullTokenId;
    appName_ = GetClientBundleName(appInfo_.appUid);
    AddSaAppInfoMap(saUid, appInfo_.appUid);
    MEDIA_LOGI("ScreenCaptureServer::SetAndCheckAppInfo end.");
    return MSERR_OK;
}

void ScreenCaptureServer::SetSCServerSaUid(int32_t saUid)
{
    saUid_ = saUid;
}

int32_t ScreenCaptureServer::GetSCServerSaUid()
{
    return saUid_;
}

int32_t ScreenCaptureServer::SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo)
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetAndCheckSaLimit START.", FAKE_POINTER(this));
    int32_t ret = SetAndCheckAppInfo(appInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetAndCheckSaLimit failed, saUid exists.");
    bool createFlag = CanScreenCaptureInstanceBeCreate(appInfo.appUid);
    if (!createFlag) {
        MEDIA_LOGI("SetAndCheckSaLimit failed, cannot create ScreenCapture Instance.");
        SetSCServerSaUid(-1);
        return MSERR_INVALID_OPERATION;
    }
    MEDIA_LOGI("SetAndCheckSaLimit SUCCESS! appUid: %{public}d, saUid: %{public}d",
        appInfo.appUid, GetSCServerSaUid());
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetAndCheckLimit()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetAndCheckLimit START.", FAKE_POINTER(this));
    bool createFlag = CanScreenCaptureInstanceBeCreate(IPCSkeleton::GetCallingUid());
    CHECK_AND_RETURN_RET_LOG(createFlag, MSERR_INVALID_OPERATION,
        "SetAndCheckLimit failed, cannot create ScreenCapture Instance.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::GetRunningScreenCaptureInstancePid(std::list<int32_t> &pidList)
{
    MEDIA_LOGI("GetRunningScreenCaptureInstancePid in");
    pidList = GetAllStartedSessionIdList();
    return MSERR_OK;
}

void ScreenCaptureServer::GetChoiceFromJson(Json::Value &root,
    const std::string &content, std::string key, std::string &value)
{
    Json::Reader reader;
    bool parsingSuccessful = reader.parse(content, root);
    if (!parsingSuccessful || root.type() != Json::objectValue) {
        MEDIA_LOGE("Error parsing the string");
        return;
    }
    const Json::Value keyJson = root[key];
    if (!keyJson.isNull() && keyJson.isString()) {
        value = keyJson.asString();
    }
}

void ScreenCaptureServer::GetValueFromJson(Json::Value &root,
    const std::string &content, const std::string key, bool &value)
{
    value = false;

    Json::Reader reader;
    bool parsingSuccessful = reader.parse(content, root);
    if (!parsingSuccessful || root.type() != Json::objectValue) {
        MEDIA_LOGE("Error parsing the string");
        return;
    }
    const Json::Value keyJson = root[key];
    if (!keyJson.isNull() && keyJson.isString()) {
        if (JSON_VALUE_TRUE.compare(keyJson.asString()) == 0) {
            value = true;
        } else {
            value = false;
        }
    }
    MEDIA_LOGI("GetValueFromJson value: %{public}d", value);
}

void ScreenCaptureServer::SetCaptureConfig(CaptureMode captureMode, int32_t missionId)
{
    captureConfig_.captureMode = captureMode;
    if (missionId != -1) { // -1 无效值
        captureConfig_.videoInfo.videoCapInfo.taskIDs = { missionId };
    } else {
        captureConfig_.videoInfo.videoCapInfo.taskIDs = {};
    }
}

void ScreenCaptureServer::PrepareSelectWindow(Json::Value &root)
{
    if (root.type() != Json::objectValue) {
        return;
    }
    const Json::Value displayIdJson = root["displayId"];
    if (!displayIdJson.isNull() && displayIdJson.isInt() && displayIdJson.asInt64() >= 0) {
        uint64_t displayId = static_cast<uint64_t>(displayIdJson.asInt64());
        MEDIA_LOGI("Report Select DisplayId: %{public}" PRIu64, displayId);
        SetDisplayId(displayId);
        // 手机模式 missionId displayId 均为-1
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_SCREEN, -1);
    }
    const Json::Value missionIdJson = root["missionId"];
    if (!missionIdJson.isNull() && missionIdJson.isInt() && missionIdJson.asInt() >= 0) {
        int32_t missionId = missionIdJson.asInt();
        MEDIA_LOGI("Report Select MissionId: %{public}d", missionId);
        SetMissionId(missionId);
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_WINDOW, missionId);
    }
    ScreenCaptureUserSelectionInfo selectionInfo = {0, static_cast<uint64_t>(0)};
    PrepareUserSelectionInfo(selectionInfo);
    NotifyUserSelected(selectionInfo);
}

int32_t ScreenCaptureServer::ReportAVScreenCaptureUserChoice(int32_t sessionId, const std::string &content)
{
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice sessionId: %{public}d, content: %{public}s",
        sessionId, content.c_str());
    std::shared_ptr<ScreenCaptureServer> server = GetScreenCaptureServerByIdWithLock(sessionId);
    CHECK_AND_RETURN_RET_LOG(server != nullptr, MSERR_UNKNOWN,
        "ReportAVScreenCaptureUserChoice failed to get instance, sessionId: %{public}d", sessionId);
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice captureState_ is %{public}d", server->captureState_);

    Json::Value root;
#ifdef PC_STANDARD
    if (server->IsPickerPopUp() && server->isPresentPicker_ && server->captureState_ == AVScreenCaptureState::STARTED) {
        return server->HandlePresentPickerWindowCase(root, content);
    }
#endif
    if (server->captureState_ == AVScreenCaptureState::POPUP_WINDOW) {
        return server->HandlePopupWindowCase(root, content);
    } else if (server->GetSCServerDataType() == DataType::ORIGINAL_STREAM &&
        server->captureState_ == AVScreenCaptureState::STARTED) {
        return server->HandleStreamDataCase(root, content);
    }
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::HandlePopupWindowCase(Json::Value& root, const std::string &content)
{
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice captureState is %{public}d", AVScreenCaptureState::POPUP_WINDOW);
    std::string choice = "false";
    GetChoiceFromJson(root, content, std::string("choice"), choice);
    GetValueFromJson(root, content, std::string("checkBoxSelected"), checkBoxSelected_);

    systemPrivacyProtectionSwitch_ = checkBoxSelected_;
    appPrivacyProtectionSwitch_ = checkBoxSelected_;
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice checkBoxSelected: %{public}d", checkBoxSelected_);

    if (showShareSystemAudioBox_) {
        GetValueFromJson(root, content, std::string("isInnerAudioBoxSelected"), isInnerAudioBoxSelected_);
    }
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice showShareSystemAudioBox: %{public}d,"
        "isInnerAudioBoxSelected: %{public}d", showShareSystemAudioBox_,
        isInnerAudioBoxSelected_);

    if (USER_CHOICE_ALLOW.compare(choice) == 0) {
        PrepareSelectWindow(root);
        int32_t ret = OnReceiveUserPrivacyAuthority(true);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
            "ReportAVScreenCaptureUserChoice user choice is true but start failed");
        MEDIA_LOGI("ReportAVScreenCaptureUserChoice user choice is true and start success");
        return MSERR_OK;
    } else if (USER_CHOICE_DENY.compare(choice) == 0) {
        return OnReceiveUserPrivacyAuthority(false);
    } else {
        MEDIA_LOGW("ReportAVScreenCaptureUserChoice user choice is not support");
    }
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::HandleStreamDataCase(Json::Value& root, const std::string &content)
{
    bool stopRecord = false;
    GetValueFromJson(root, content, std::string("stopRecording"), stopRecord);
    if (stopRecord) {
        StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
        MEDIA_LOGI("ReportAVScreenCaptureUserChoice user stop record");
        return MSERR_OK;
    }

    GetValueFromJson(root, content, std::string("appPrivacyProtectionSwitch"),
        appPrivacyProtectionSwitch_);
    GetValueFromJson(root, content, std::string("systemPrivacyProtectionSwitch"),
        systemPrivacyProtectionSwitch_);

    SystemPrivacyProtected(virtualScreenId_, systemPrivacyProtectionSwitch_);
    AppPrivacyProtected(virtualScreenId_, appPrivacyProtectionSwitch_);

    std::lock_guard<std::mutex> lock(mutex_);
    NotificationRequest request;
    UpdateLiveViewPrivacy();
    SetupPublishRequest(request);
    return NotificationHelper::PublishNotification(request);
}

int32_t ScreenCaptureServer::HandlePresentPickerWindowCase(Json::Value& root, const std::string &content)
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::string choice = "false";
    GetChoiceFromJson(root, content, std::string("choice"), choice);
    GetValueFromJson(root, content, std::string("checkBoxSelected"), checkBoxSelected_);
    systemPrivacyProtectionSwitch_ = checkBoxSelected_;
    appPrivacyProtectionSwitch_ = checkBoxSelected_;
    if (showShareSystemAudioBox_) {
        GetValueFromJson(root, content, std::string("isInnerAudioBoxSelected"), isInnerAudioBoxSelected_);
    }
    MEDIA_LOGI("HandlePresentPickerWindowCase showShareSystemAudioBox: %{public}d, isInnerAudioBoxSelected: %{public}d,"
        " dataType: %{public}d, choice: %{public}s, mode: %{public}d", showShareSystemAudioBox_,
        isInnerAudioBoxSelected_, captureConfig_.dataType, choice.c_str(), captureConfig_.captureMode);
    isPresentPickerPopWindow_ = false;
    if (choice != USER_CHOICE_ALLOW) {
        MEDIA_LOGI("ReportAVScreenCaptureUserChoice user choice is not allow or deny");
        return MSERR_OK;
    }
    HandleSetDisplayIdAndMissionId(root);
    DestroyVirtualScreen();
    int32_t ret = MSERR_OK;
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        auto consumerSurface = isSurfaceMode_ ? surface_ : producerSurface_;
        ret = CreateVirtualScreen(VIRTUAL_SCREENAME_SCREEN_CAPTRURE, consumerSurface);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen surface failed, ret: %{public}d", ret);
    } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        ret = CreateVirtualScreen(VIRTUAL_SCREENAME_SCREEN_CAPTRURE_FILE, consumer_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen file failed, ret: %{public}d", ret);
    } else {
        MEDIA_LOGE("HandlePresentPickerWindowCase dataType is invalid");
        return MSERR_UNKNOWN;
    }
    return ret;
}

void ScreenCaptureServer::HandleSetDisplayIdAndMissionId(Json::Value &root)
{
    MEDIA_LOGI("ScreenCaptureServer::HandleSetDisplayIdAndMissionId start");
    missionIds_.clear();
    UpdateHighlightOutline(false);
    const Json::Value displayIdJson = root["displayId"];
    if (!displayIdJson.isNull() && displayIdJson.isInt() && displayIdJson.asInt64() >= 0) {
        uint64_t displayId = static_cast<uint64_t>(displayIdJson.asInt64());
        MEDIA_LOGI("Report Select DisplayId: %{public}" PRIu64, displayId);
        SetDisplayId(displayId);
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_SCREEN, -1);
    }
    const Json::Value missionIdJson = root["missionId"];
    if (!missionIdJson.isNull() && missionIdJson.isInt() && missionIdJson.asInt() >= 0) {
        int32_t missionId = missionIdJson.asInt();
        MEDIA_LOGI("Report Select MissionId: %{public}d", missionId);
        SetMissionId(missionId);
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_WINDOW, missionId);
    }
    UpdateHighlightOutline(true);
    MEDIA_LOGI("ScreenCaptureServer::HandleSetDisplayIdAndMissionId end");
}

int32_t ScreenCaptureServer::PresentPicker()
{
#ifdef PC_STANDARD
    if (!IsPickerPopUp()) {
        MEDIA_LOGE("PresentPicker not support picker.");
        return MSERR_INVALID_OPERATION;
    }
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGE("PresentPicker captureState_ is not STARTED, not allowed.");
        return MSERR_INVALID_OPERATION;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PresentPicker start.", FAKE_POINTER(this));
    MediaTrace trace("ScreenCaptureServer::PresentPicker");
    std::lock_guard<std::mutex> lock(mutex_);
    isPresentPicker_ = true;
    isPresentPickerPopWindow_ = true;
    int32_t ret = StartPrivacyWindow();
    return ret;
#endif
    return MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureServer::GetAVScreenCaptureConfigurableParameters(int32_t sessionId, std::string &resultStr)
{
    MEDIA_LOGI("GetAVScreenCaptureConfigurableParameters sessionId :%{public}d",
        sessionId);
    std::shared_ptr<ScreenCaptureServer> server = GetScreenCaptureServerByIdWithLock(sessionId);
    CHECK_AND_RETURN_RET_LOG(server != nullptr, MSERR_UNKNOWN,
        "GetAVScreenCaptureConfigurableParameters failed to get instance, sessionId: %{public}d", sessionId);
    Json::Value root;
    root["appPrivacyProtectionSwitch"] = server->appPrivacyProtectionSwitch_;
    root["systemPrivacyProtectionSwitch"] = server->systemPrivacyProtectionSwitch_;
    Json::FastWriter fastWriter;
    resultStr = fastWriter.write(root);
    MEDIA_LOGI("GetAVScreenCaptureConfigurableParameters res: %{public}s", resultStr.c_str());
    return MSERR_OK;
}

int32_t ScreenCaptureServer::GetAppPid()
{
    return appInfo_.appPid;
}

int32_t ScreenCaptureServer::GetAppUid()
{
    return appInfo_.appUid;
}

DataType ScreenCaptureServer::GetSCServerDataType()
{
    return captureConfig_.dataType;
}

bool ScreenCaptureServer::IsMicrophoneSwitchTurnOn()
{
    return isMicrophoneSwitchTurnOn_;
}

bool ScreenCaptureServer::IsMicrophoneCaptureRunning()
{
    return micAudioCapture_ && micAudioCapture_->IsRecording();
}

bool ScreenCaptureServer::IsInnerCaptureRunning()
{
    return innerAudioCapture_ && innerAudioCapture_->IsRecording();
}

bool ScreenCaptureServer::IsSCRecorderFileWithVideo()
{
    return recorderFileWithVideo_.load();
}

std::shared_ptr<AudioCapturerWrapper> ScreenCaptureServer::GetInnerAudioCapture()
{
    return innerAudioCapture_;
}

void ScreenCaptureServer::SetInnerAudioCapture(std::shared_ptr<AudioCapturerWrapper> innerAudioCapture)
{
    innerAudioCapture_ = innerAudioCapture;
}

std::shared_ptr<AudioCapturerWrapper> ScreenCaptureServer::GetMicAudioCapture()
{
    return micAudioCapture_;
}

bool ScreenCaptureServer::IsStopAcquireAudioBufferFlag()
{
    return stopAcquireAudioBufferFromAudio_.load();
}

void ScreenCaptureServer::SetDisplayId(uint64_t displayId)
{
    captureConfig_.videoInfo.videoCapInfo.displayId = displayId;
}

void ScreenCaptureServer::SetMissionId(uint64_t missionId)
{
    std::unique_lock<std::shared_mutex> write_lock(rw_lock_);
    missionIds_.emplace_back(missionId);
}

AVScreenCaptureState ScreenCaptureServer::GetSCServerCaptureState()
{
    return captureState_;
}

void ScreenCaptureServer::SetMetaDataReport()
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_CODE, statisticalEventInfo_.errCode);
    meta->SetData(Tag::SCREEN_CAPTURE_ERR_MSG, statisticalEventInfo_.errMsg);
    meta->SetData(Tag::SCREEN_CAPTURE_DURATION, statisticalEventInfo_.captureDuration);
    meta->SetData(Tag::SCREEN_CAPTURE_AV_TYPE, avType_);
    meta->SetData(Tag::SCREEN_CAPTURE_DATA_TYPE, dataMode_);
    meta->SetData(Tag::SCREEN_CAPTURE_USER_AGREE, statisticalEventInfo_.userAgree);
    meta->SetData(Tag::SCREEN_CAPTURE_REQURE_MIC, statisticalEventInfo_.requireMic);
    meta->SetData(Tag::SCREEN_CAPTURE_ENABLE_MIC, statisticalEventInfo_.enableMic);
    meta->SetData(Tag::SCREEN_CAPTURE_VIDEO_RESOLUTION, statisticalEventInfo_.videoResolution);
    meta->SetData(Tag::SCREEN_CAPTURE_STOP_REASON, statisticalEventInfo_.stopReason);
    meta->SetData(Tag::SCREEN_CAPTURE_START_LATENCY, statisticalEventInfo_.startLatency);
    AppendMediaInfo(meta, instanceId_);
    ReportMediaInfo(instanceId_);
}

ScreenCaptureServer::ScreenCaptureServer()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ScreenCaptureServer Instances create", FAKE_POINTER(this));
    std::map<int32_t, std::weak_ptr<ScreenCaptureServer>> ScreenCaptureServer::serverMap_{};
    std::map<int32_t, std::pair<int32_t, int32_t>> ScreenCaptureServer::saUidAppUidMap_{};
    InitAppInfo();
    instanceId_ = OHOS::HiviewDFX::HiTraceChain::GetId().GetChainId();
    CreateMediaInfo(SCREEN_CAPTRUER, IPCSkeleton::GetCallingUid(), instanceId_);
}

ScreenCaptureServer::~ScreenCaptureServer()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ScreenCaptureServer Instances destroy", FAKE_POINTER(this));
    ReleaseInner();
    CloseFd();
}

void ScreenCaptureServer::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " sessionId: %{public}d", FAKE_POINTER(this), sessionId_);
}

void ScreenCaptureServer::GetAndSetAppVersion()
{
    appVersion_ = GetApiInfo(appInfo_.appUid);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " appVersion: %{public}d",
        FAKE_POINTER(this), appVersion_);
}

bool ScreenCaptureServer::CheckAppVersionForUnsupport(DMError result)
{
    return appVersion_ >= UNSUPPORT_ERROR_CODE_API_VERSION_ISOLATION && result == DMError::DM_ERROR_DEVICE_NOT_SUPPORT;
}

int32_t ScreenCaptureServer::SetCaptureMode(CaptureMode captureMode)
{
    MediaTrace trace("ScreenCaptureServer::SetCaptureMode");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "SetCaptureMode failed, capture is not CREATED, state:%{public}d, mode:%{public}d", captureState_, captureMode);
    MEDIA_LOGI("ScreenCaptureServer::SetCaptureMode start, captureMode:%{public}d", captureMode);
    int32_t ret = CheckCaptureMode(captureMode);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ret);
    captureConfig_.captureMode = captureMode;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCaptureMode OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetDataType(DataType dataType)
{
    MediaTrace trace("ScreenCaptureServer::SetDataType");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "SetDataType failed, capture is not CREATED, state:%{public}d, dataType:%{public}d", captureState_, dataType);
    MEDIA_LOGI("ScreenCaptureServer::SetDataType start, dataType:%{public}d", dataType);
    int32_t ret = CheckDataType(dataType);
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ret);
    captureConfig_.dataType = dataType;
    CHECK_AND_RETURN_RET_LOG(CheckSCServerSpecifiedDataTypeNum(GetAppUid(), GetSCServerDataType()),
        MSERR_INVALID_OPERATION,
        "ScreenCaptureServer: 0x%{public}06" PRIXPTR "SetDataType failed.", FAKE_POINTER(this));
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetDataType OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetRecorderInfo(RecorderInfo recorderInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "SetRecorderInfo failed, capture is not CREATED, state:%{public}d", captureState_);
    MEDIA_LOGI("ScreenCaptureServer::SetRecorderInfo start");
    url_ = recorderInfo.url;
    avType_ = AVScreenCaptureAvType::AV_TYPE;

    if (MP4.compare(recorderInfo.fileFormat) == 0) {
        fileFormat_ = OutputFormatType::FORMAT_MPEG_4;
    } else if (M4A.compare(recorderInfo.fileFormat) == 0) {
        fileFormat_ = OutputFormatType::FORMAT_M4A;
    } else {
        MEDIA_LOGE("invalid fileFormat type");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_,
            SCREEN_CAPTURE_ERR_INVALID_VAL, "invalid fileFormat type");
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetRecorderInfo OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetOutputFile(int32_t outputFd)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "SetOutputFile failed, capture is not CREATED, state:%{public}d", captureState_);
    MEDIA_LOGI("ScreenCaptureServer::SetOutputFile start");
    if (outputFd < 0) {
        MEDIA_LOGI("invalid outputFd");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_,
            SCREEN_CAPTURE_ERR_INVALID_VAL, "invalid outputFd");
        return MSERR_INVALID_VAL;
    }

    int flags = fcntl(outputFd, F_GETFL);
    if (flags == -1) {
        MEDIA_LOGE("Fail to get File Status Flags");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "Fail to get File Status Flags");
        return MSERR_INVALID_VAL;
    }
    if ((static_cast<unsigned int>(flags) & (O_RDWR | O_WRONLY)) == 0) {
        MEDIA_LOGE("File descriptor is not in read-write mode or write-only mode");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "File descriptor is not in read-write mode or write-only mode");
        return MSERR_INVALID_VAL;
    }
    CloseFd();
    MEDIA_LOGI("ScreenCaptureServer fd in, fd is %{public}d", outputFd);
    outputFd_ = dup(outputFd);
    CHECK_AND_RETURN_RET_LOG(outputFd_ >= 0, MSERR_NO_MEMORY, "dup outputFd failed");
    MEDIA_LOGI("ScreenCaptureServer fd dup, fd is %{public}d", outputFd_);
    MEDIA_LOGI("ScreenCaptureServer SetOutputFile End");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetScreenCaptureCallback(const std::shared_ptr<ScreenCaptureCallBack> &callback)
{
    MediaTrace trace("ScreenCaptureServer::SetScreenCaptureCallback");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "SetScreenCaptureCallback failed, capture is not CREATED, state:%{public}d", captureState_);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL,
        "SetScreenCaptureCallback failed, callback is nullptr, state:%{public}d", captureState_);
    MEDIA_LOGI("ScreenCaptureServer::SetScreenCaptureCallback start");
    screenCaptureCb_ = callback;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenCaptureCallback OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitAudioEncInfo(AudioEncInfo audioEncInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "InitAudioEncInfo failed, capture is not CREATED, state:%{public}d", captureState_);
    MEDIA_LOGI("ScreenCaptureServer::InitAudioEncInfo start");
    MEDIA_LOGD("audioEncInfo audioBitrate:%{public}d, audioCodecformat:%{public}d", audioEncInfo.audioBitrate,
        audioEncInfo.audioCodecformat);
    int32_t ret = CheckAudioEncInfo(audioEncInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitAudioEncInfo failed, ret:%{public}d", ret);
    captureConfig_.audioInfo.audioEncInfo = audioEncInfo;
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitVideoEncInfo(VideoEncInfo videoEncInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "InitVideoEncInfo failed, capture is not CREATED, state:%{public}d", captureState_);
    MEDIA_LOGI("ScreenCaptureServer::InitVideoEncInfo start");
    MEDIA_LOGD("videoEncInfo videoCodec:%{public}d,  videoBitrate:%{public}d, videoFrameRate:%{public}d",
        videoEncInfo.videoCodec, videoEncInfo.videoBitrate, videoEncInfo.videoFrameRate);
    int32_t ret = CheckVideoEncInfo(videoEncInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoEncInfo failed, ret:%{public}d", ret);
    captureConfig_.videoInfo.videoEncInfo = videoEncInfo;
    return MSERR_OK;
}

bool ScreenCaptureServer::CheckScreenCapturePermission()
{
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(appInfo_.appTokenId,
        "ohos.permission.CAPTURE_SCREEN");
    if (result == Security::AccessToken::PERMISSION_GRANTED) {
        MEDIA_LOGI("user have the right to access capture screen!");
        return true;
    } else {
        MEDIA_LOGE("user do not have the right to access capture screen!");
        return false;
    }
}

bool ScreenCaptureServer::IsUserPrivacyAuthorityNeeded()
{
    MediaTrace trace("ScreenCaptureServer::IsUserPrivacyAuthorityNeeded");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " IsUserPrivacyAuthorityNeeded start, appUid:%{public}d",
        FAKE_POINTER(this), appInfo_.appUid);
    if (appInfo_.appUid == ROOT_UID) {
        MEDIA_LOGI("Root user. Privacy Authority Granted automaticly");
        return false;
    }
    return true;
}

int32_t ScreenCaptureServer::CheckCaptureMode(CaptureMode captureMode)
{
    MEDIA_LOGD("CheckCaptureMode start, captureMode:%{public}d", captureMode);
    if ((captureMode > CAPTURE_SPECIFIED_WINDOW) || (captureMode < CAPTURE_HOME_SCREEN)) {
        MEDIA_LOGE("invalid captureMode:%{public}d", captureMode);
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGD("ScreenCaptureServer CheckCaptureMode OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckDataType(DataType dataType)
{
    MEDIA_LOGD("CheckDataType start, dataType:%{public}d", dataType);
    if ((dataType > DataType::CAPTURE_FILE) || (dataType < DataType::ORIGINAL_STREAM)) {
        MEDIA_LOGE("invalid dataType:%{public}d", dataType);
        return MSERR_INVALID_VAL;
    }
    if (dataType == DataType::ENCODED_STREAM) {
        MEDIA_LOGE("not supported dataType:%{public}d", dataType);
        return MSERR_UNSUPPORT;
    }
    MEDIA_LOGD("ScreenCaptureServer CheckDataType OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckAudioCapParam(const AudioCaptureInfo &audioCapInfo)
{
    MEDIA_LOGD("CheckAudioCapParam sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d",
        audioCapInfo.audioSampleRate, audioCapInfo.audioChannels, audioCapInfo.audioSource, audioCapInfo.state);
    std::vector<AudioSamplingRate> supportedSamplingRates = AudioStandard::AudioCapturer::GetSupportedSamplingRates();
    bool foundSupportSample = false;
    for (auto iter = supportedSamplingRates.begin(); iter != supportedSamplingRates.end(); ++iter) {
        if (static_cast<AudioSamplingRate>(audioCapInfo.audioSampleRate) == *iter) {
            foundSupportSample = true;
        }
    }
    if (!foundSupportSample) {
        MEDIA_LOGE("invalid audioSampleRate:%{public}d", audioCapInfo.audioSampleRate);
        return MSERR_UNSUPPORT;
    }

    std::vector<AudioChannel> supportedChannelList = AudioStandard::AudioCapturer::GetSupportedChannels();
    bool foundSupportChannel = false;
    for (auto iter = supportedChannelList.begin(); iter != supportedChannelList.end(); ++iter) {
        if (static_cast<AudioChannel>(audioCapInfo.audioChannels) == *iter) {
            foundSupportChannel = true;
        }
    }
    if (!foundSupportChannel) {
        MEDIA_LOGE("invalid audioChannels:%{public}d", audioCapInfo.audioChannels);
        return MSERR_UNSUPPORT;
    }

    if ((audioCapInfo.audioSource <= SOURCE_INVALID) || (audioCapInfo.audioSource > APP_PLAYBACK)) {
        MEDIA_LOGE("invalid audioSource:%{public}d", audioCapInfo.audioSource);
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGD("ScreenCaptureServer CheckAudioCapParam OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckVideoCapParam(const VideoCaptureInfo &videoCapInfo)
{
    MEDIA_LOGD("CheckVideoCapParam width:%{public}d, height:%{public}d, source:%{public}d, state:%{public}d",
        videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight, videoCapInfo.videoSource, videoCapInfo.state);
    if ((videoCapInfo.videoFrameWidth <= 0) || (videoCapInfo.videoFrameWidth > VIDEO_FRAME_WIDTH_MAX)) {
        MEDIA_LOGE("videoCapInfo Width is invalid, videoFrameWidth:%{public}d, videoFrameHeight:%{public}d",
            videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight);
        return MSERR_INVALID_VAL;
    }
    if ((videoCapInfo.videoFrameHeight <= 0) || (videoCapInfo.videoFrameHeight > VIDEO_FRAME_HEIGHT_MAX)) {
        MEDIA_LOGE("videoCapInfo Height is invalid, videoFrameWidth:%{public}d, videoFrameHeight:%{public}d",
            videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight);
        return MSERR_INVALID_VAL;
    }

    if (videoCapInfo.videoSource != VIDEO_SOURCE_SURFACE_RGBA) {
        MEDIA_LOGE("videoSource is invalid");
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGD("ScreenCaptureServer CheckVideoCapParam OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckAudioEncParam(const AudioEncInfo &audioEncInfo)
{
    MEDIA_LOGD("CheckAudioEncParam audioBitrate:%{public}d, audioCodecformat:%{public}d",
        audioEncInfo.audioBitrate, audioEncInfo.audioCodecformat);
    if ((audioEncInfo.audioCodecformat >= AudioCodecFormat::AUDIO_CODEC_FORMAT_BUTT) ||
        (audioEncInfo.audioCodecformat < AudioCodecFormat::AUDIO_DEFAULT)) {
        MEDIA_LOGE("invalid AudioCodecFormat:%{public}d", audioEncInfo.audioCodecformat);
        return MSERR_INVALID_VAL;
    }
    if (audioEncInfo.audioBitrate < AUDIO_BITRATE_MIN || audioEncInfo.audioBitrate > AUDIO_BITRATE_MAX) {
        MEDIA_LOGE("invalid audioBitrate:%{public}d", audioEncInfo.audioBitrate);
        return MSERR_INVALID_VAL;
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckVideoEncParam(const VideoEncInfo &videoEncInfo)
{
    MEDIA_LOGD("CheckVideoEncParam videoCodec:%{public}d, videoBitrate:%{public}d, videoFrameRate:%{public}d",
        videoEncInfo.videoCodec, videoEncInfo.videoBitrate, videoEncInfo.videoFrameRate);
    if ((videoEncInfo.videoCodec >= VideoCodecFormat::VIDEO_CODEC_FORMAT_BUTT) ||
        (videoEncInfo.videoCodec < VideoCodecFormat::VIDEO_DEFAULT)) {
        MEDIA_LOGE("invalid VideoCodecFormat:%{public}d", videoEncInfo.videoCodec);
        return MSERR_INVALID_VAL;
    }
    if (videoEncInfo.videoBitrate < VIDEO_BITRATE_MIN || videoEncInfo.videoBitrate > VIDEO_BITRATE_MAX) {
        MEDIA_LOGE("invalid videoBitrate:%{public}d", videoEncInfo.videoBitrate);
        return MSERR_INVALID_VAL;
    }
    if (videoEncInfo.videoFrameRate < VIDEO_FRAME_RATE_MIN || videoEncInfo.videoFrameRate > VIDEO_FRAME_RATE_MAX) {
        MEDIA_LOGE("invalid videoFrameRate:%{public}d", videoEncInfo.videoFrameRate);
        return MSERR_INVALID_VAL;
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckAudioCapInfo(AudioCaptureInfo &audioCapInfo)
{
    MEDIA_LOGD("ScreenCaptureServer CheckAudioCapInfo start, audioChannels:%{public}d, "
        "audioSampleRate:%{public}d, audioSource:%{public}d, state:%{public}d.",
        audioCapInfo.audioChannels, audioCapInfo.audioSampleRate, audioCapInfo.audioSource, audioCapInfo.state);
    if (audioCapInfo.audioChannels == 0 && audioCapInfo.audioSampleRate == 0) {
        MEDIA_LOGD("audioCap IGNORED sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d",
            audioCapInfo.audioSampleRate, audioCapInfo.audioChannels, audioCapInfo.audioSource, audioCapInfo.state);
        audioCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
        return MSERR_OK;
    }
    MEDIA_LOGD("CheckAudioCapParam S sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d",
        audioCapInfo.audioSampleRate, audioCapInfo.audioChannels, audioCapInfo.audioSource, audioCapInfo.state);
    int32_t ret = CheckAudioCapParam(audioCapInfo);
    audioCapInfo.state = ret == MSERR_OK ? AVScreenCaptureParamValidationState::VALIDATION_VALID :
        AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    MEDIA_LOGD("CheckAudioCapParam E sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d",
        audioCapInfo.audioSampleRate, audioCapInfo.audioChannels, audioCapInfo.audioSource, audioCapInfo.state);
    MEDIA_LOGD("ScreenCaptureServer CheckAudioCapInfo end.");
    return ret;
}

int32_t ScreenCaptureServer::CheckVideoCapInfo(VideoCaptureInfo &videoCapInfo)
{
    MEDIA_LOGD("CheckVideoCapInfo start, videoFrameWidth:%{public}d, videoFrameHeight:%{public}d, "
        "videoSource:%{public}d, state:%{public}d.", videoCapInfo.videoFrameWidth,
        videoCapInfo.videoFrameHeight, videoCapInfo.videoSource, videoCapInfo.state);
    if (videoCapInfo.videoFrameWidth == 0 && videoCapInfo.videoFrameHeight == 0) {
        MEDIA_LOGD("videoCap IGNORED width:%{public}d, height:%{public}d, source:%{public}d, state:%{public}d",
            videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight, videoCapInfo.videoSource, videoCapInfo.state);
        videoCapInfo.state = AVScreenCaptureParamValidationState::VALIDATION_IGNORE;
        return MSERR_OK;
    }
    MEDIA_LOGD("CheckVideoCapParam S width:%{public}d, height:%{public}d, source:%{public}d, state:%{public}d",
        videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight, videoCapInfo.videoSource, videoCapInfo.state);
    int32_t ret = CheckVideoCapParam(videoCapInfo);
    videoCapInfo.state = ret == MSERR_OK ? AVScreenCaptureParamValidationState::VALIDATION_VALID :
        AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    MEDIA_LOGD("CheckVideoCapParam E width:%{public}d, height:%{public}d, source:%{public}d, state:%{public}d",
        videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight, videoCapInfo.videoSource, videoCapInfo.state);
    MEDIA_LOGD("ScreenCaptureServer CheckVideoCapInfo end.");
    return ret;
}

int32_t ScreenCaptureServer::CheckAudioEncInfo(AudioEncInfo &audioEncInfo)
{
    MEDIA_LOGD("ScreenCaptureServer CheckAudioEncInfo start.");
    int32_t ret = CheckAudioEncParam(audioEncInfo);
    audioEncInfo.state = ret == MSERR_OK ? AVScreenCaptureParamValidationState::VALIDATION_VALID :
        AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    MEDIA_LOGD("ScreenCaptureServer CheckAudioEncInfo end, state: %{public}d.", audioEncInfo.state);
    return ret;
}

int32_t ScreenCaptureServer::CheckVideoEncInfo(VideoEncInfo &videoEncInfo)
{
    MEDIA_LOGD("ScreenCaptureServer CheckVideoEncInfo start.");
    int32_t ret = CheckVideoEncParam(videoEncInfo);
    videoEncInfo.state = ret == MSERR_OK ? AVScreenCaptureParamValidationState::VALIDATION_VALID :
        AVScreenCaptureParamValidationState::VALIDATION_INVALID;
    MEDIA_LOGD("ScreenCaptureServer CheckVideoEncInfo end, state: %{public}d.", videoEncInfo.state);
    return ret;
}

int32_t ScreenCaptureServer::CheckAllParams()
{
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CheckAllParams start, dataType:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType);
    int32_t ret = CheckDataType(captureConfig_.dataType);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CheckAllParams CheckDataType failed, ret:%{public}d", ret);

    ret = CheckCaptureMode(captureConfig_.captureMode);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CheckAllParams CheckCaptureMode failed, ret:%{public}d", ret);

    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        if (isSurfaceMode_) {
            dataMode_ = AVScreenCaptureDataMode::SUFFACE_MODE;
        } else {
            dataMode_ = AVScreenCaptureDataMode::BUFFER_MODE;
        }
        return CheckCaptureStreamParams();
    }
    if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        dataMode_ = AVScreenCaptureDataMode::FILE_MODE;
        return CheckCaptureFileParams();
    }
    return MSERR_INVALID_VAL;
}

int32_t ScreenCaptureServer::CheckCaptureStreamParams()
{
    // For original stream:
    // 1. Any of innerCapInfo/videoCapInfo should be not invalid and should not be both ignored
    // 2. micCapInfo should not be invalid
    // 3. For surface mode, videoCapInfo should be valid
    CheckAudioCapInfo(captureConfig_.audioInfo.micCapInfo);
    CheckAudioCapInfo(captureConfig_.audioInfo.innerCapInfo);
    CheckVideoCapInfo(captureConfig_.videoInfo.videoCapInfo);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CheckCaptureStreamParams start, isSurfaceMode:%{public}s,"
        " videoCapInfo.state:%{public}d, innerCapInfo.state:%{public}d.", FAKE_POINTER(this),
        isSurfaceMode_ ? "true" : "false", captureConfig_.videoInfo.videoCapInfo.state,
        captureConfig_.audioInfo.innerCapInfo.state);
    if (captureConfig_.audioInfo.micCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        isMicrophoneSwitchTurnOn_ = false;
    }
    if (isSurfaceMode_) {
        // surface mode, surface must not nullptr and videoCapInfo must valid.
        if (surface_ == nullptr ||
            captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_VALID) {
            FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
                "video Cap state fault, videoCapInfo is invalid");
            return MSERR_INVALID_VAL;
        }
    }
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID ||
        captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID) {
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "audio inner cap or video cap state invalid");
        return MSERR_INVALID_VAL;
    }
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_IGNORE &&
        captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "audio inner cap or video cap state ignore");
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CheckCaptureStreamParams OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CheckCaptureFileParams()
{
    // For capture file:
    // 1. All of innerCapInfo/videoCapInfo/audioEncInfo/videoEncInfo should be be valid
    // 2. micCapInfo should not be invalid
    CheckAudioCapInfo(captureConfig_.audioInfo.micCapInfo);
    CheckAudioCapInfo(captureConfig_.audioInfo.innerCapInfo);
    CheckAudioEncInfo(captureConfig_.audioInfo.audioEncInfo);
    CheckVideoCapInfo(captureConfig_.videoInfo.videoCapInfo);
    if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        CheckVideoEncInfo(captureConfig_.videoInfo.videoEncInfo);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CheckCaptureFileParams start, "
        "innerCapInfo.state:%{public}d, videoCapInfo.state:%{public}d, audioEncInfo.state:%{public}d, "
        "videoEncInfo.state:%{public}d, micCapInfo.state:%{public}d.", FAKE_POINTER(this),
        captureConfig_.audioInfo.innerCapInfo.state, captureConfig_.videoInfo.videoCapInfo.state,
        captureConfig_.audioInfo.audioEncInfo.state, captureConfig_.videoInfo.videoEncInfo.state,
        captureConfig_.audioInfo.micCapInfo.state);

    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID ||
        captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID ||
        captureConfig_.audioInfo.audioEncInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID ||
        captureConfig_.videoInfo.videoEncInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID) {
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "innerCap audioEnc videoCap videoEnc state invalid");
        return MSERR_INVALID_VAL;
    }
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_INVALID) {
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "audio mic cap state invalid");
        return MSERR_INVALID_VAL;
    }
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        return MSERR_OK;
    }
    const AudioCaptureInfo &micCapInfo = captureConfig_.audioInfo.micCapInfo;
    const AudioCaptureInfo &innerCapInfo = captureConfig_.audioInfo.innerCapInfo;
    if (micCapInfo.audioSampleRate == innerCapInfo.audioSampleRate &&
        micCapInfo.audioChannels == innerCapInfo.audioChannels) {
        return MSERR_OK;
    }
    MEDIA_LOGE("CheckCaptureFileParams failed, inner and mic param not consistent");
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
        "CheckCaptureFileParams failed, inner and mic param not consistent");
    return MSERR_INVALID_VAL;
}

// Should call in ipc thread
void ScreenCaptureServer::InitAppInfo()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitAppInfo start.", FAKE_POINTER(this));
    appInfo_.appTokenId = IPCSkeleton::GetCallingTokenID();
    appInfo_.appFullTokenId = IPCSkeleton::GetCallingFullTokenID();
    appInfo_.appUid = IPCSkeleton::GetCallingUid();
    appInfo_.appPid = IPCSkeleton::GetCallingPid();
    appName_ = GetClientBundleName(appInfo_.appUid);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitAppInfo end.", FAKE_POINTER(this));
}

int64_t ScreenCaptureServer::GetCurrentMillisecond()
{
    std::chrono::system_clock::duration duration = std::chrono::system_clock::now().time_since_epoch();
    int64_t time = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    return time;
}

void ScreenCaptureServer::SetErrorInfo(int32_t errCode, const std::string &errMsg, StopReason stopReason,
    bool userAgree)
{
    statisticalEventInfo_.errCode = errCode;
    statisticalEventInfo_.errMsg = errMsg;
    statisticalEventInfo_.stopReason = stopReason;
    statisticalEventInfo_.userAgree = userAgree;
}

bool ScreenCaptureServer::CheckPrivacyWindowSkipPermission()
{
    MEDIA_LOGI("ScreenCaptureServer::CheckPrivacyWindowSkipPermission() START.");
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(appInfo_.appTokenId,
        "ohos.permission.EXEMPT_CAPTURE_SCREEN_AUTHORIZE");
    if (result == Security::AccessToken::PERMISSION_GRANTED) {
        MEDIA_LOGI("CheckPrivacyWindowSkipPermission: user have the right to skip privacywindow");
        return true;
    }
    MEDIA_LOGD("CheckPrivacyWindowSkipPermission: user do not have the right to skip privacywindow");
    return false;
}

int32_t ScreenCaptureServer::RequestUserPrivacyAuthority(bool &isSkipPrivacyWindow)
{
    MediaTrace trace("ScreenCaptureServer::RequestUserPrivacyAuthority");
    // If Root is treated as whitelisted, how to guarantee RequestUserPrivacyAuthority function by TDD cases.
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " RequestUserPrivacyAuthority start.", FAKE_POINTER(this));

    if (isPrivacyAuthorityEnabled_) {
        isSkipPrivacyWindow = IsSkipPrivacyWindow();
        if (isSkipPrivacyWindow) {
            MEDIA_LOGI("ScreenCaptureServer::RequestUserPrivacyAuthority skip privacy window");
            return MSERR_OK;
        }
        return StartPrivacyWindow();
    }

    MEDIA_LOGI("privacy notification window not support, go on to check CAPTURE_SCREEN permission");
    return CheckScreenCapturePermission() ? MSERR_OK : MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureServer::OnReceiveUserPrivacyAuthority(bool isAllowed)
{
    // Should callback be running in seperate thread?
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("OnReceiveUserPrivacyAuthority start, isAllowed:%{public}d, state:%{public}d", isAllowed, captureState_);
    if (screenCaptureCb_ == nullptr) {
        MEDIA_LOGE("OnReceiveUserPrivacyAuthority failed, screenCaptureCb is nullptr, state:%{public}d", captureState_);
        captureState_ = AVScreenCaptureState::STOPPED;
        SetErrorInfo(MSERR_UNKNOWN, "OnReceiveUserPrivacyAuthority failed, screenCaptureCb is nullptr",
            StopReason::RECEIVE_USER_PRIVACY_AUTHORITY_FAILED, IsUserPrivacyAuthorityNeeded());
        return MSERR_UNKNOWN;
    }

    if (captureState_ != AVScreenCaptureState::POPUP_WINDOW) {
        MEDIA_LOGE("OnReceiveUserPrivacyAuthority failed, capture is not POPUP_WINDOW");
        screenCaptureCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
            AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
        return MSERR_UNKNOWN;
    }
    if (!isAllowed) {
        captureState_ = AVScreenCaptureState::CREATED;
        screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_CANCELED);
        return MSERR_UNKNOWN;
    }
    int32_t ret = OnStartScreenCapture();
    PostStartScreenCapture(ret == MSERR_OK);
    return ret;
}

int32_t ScreenCaptureServer::StartAudioCapture()
{
    int32_t ret = MSERR_UNKNOWN;
    if (isMicrophoneSwitchTurnOn_) {
        ret = StartStreamMicAudioCapture();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StartAudioCapture StartStreamMicAudioCapture failed");
        }
    }
    ret = StartStreamInnerAudioCapture();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("StartStreamInnerAudioCapture failed");
        StopMicAudioCapture();
        return ret;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

std::string ScreenCaptureServer::GenerateThreadNameByPrefix(std::string threadName)
{
    return threadName + std::to_string(sessionId_);
}

int32_t ScreenCaptureServer::StartStreamInnerAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamInnerAudioCapture start, dataType:%{public}d,"
        " innerCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.innerCapInfo.state);
    std::shared_ptr<AudioCapturerWrapper> innerCapture;
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartAudioCaptureInner");
        innerCapture = std::make_shared<AudioCapturerWrapper>(captureConfig_.audioInfo.innerCapInfo, screenCaptureCb_,
            std::string(GenerateThreadNameByPrefix("OS_SInnAd")), contentFilter_);
        int32_t ret = innerCapture->Start(appInfo_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartAudioCapture innerCapture failed");
    }
    innerAudioCapture_ = innerCapture;
    if (showShareSystemAudioBox_ && !isInnerAudioBoxSelected_ && innerAudioCapture_) {
        MEDIA_LOGI("StartStreamInnerAudioCapture set isMute");
        innerAudioCapture_->SetIsMute(true);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamInnerAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartStreamMicAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamMicAudioCapture start, dataType:%{public}d, "
        "micCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.micCapInfo.state);
    std::shared_ptr<AudioCapturerWrapper> micCapture;
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartAudioCaptureMic");
        ScreenCaptureContentFilter contentFilterMic;
        micCapture = std::make_shared<AudioCapturerWrapper>(captureConfig_.audioInfo.micCapInfo, screenCaptureCb_,
            std::string(GenerateThreadNameByPrefix("OS_SMicAd")), contentFilterMic);
        int32_t ret = micCapture->Start(appInfo_);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StartStreamMicAudioCapture failed");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return ret;
        }
    }
    micAudioCapture_ = micCapture;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamMicAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartFileInnerAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileInnerAudioCapture start, dataType:%{public}d, "
        "innerCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.innerCapInfo.state);
    CHECK_AND_RETURN_RET(!IsInnerCaptureRunning(), MSERR_OK); // prevent repeat start
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartFileInnerAudioCaptureInner");
        std::lock_guard<std::mutex> lock(innerAudioMutex_);
        innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
            captureConfig_.audioInfo.innerCapInfo, screenCaptureCb_,
            std::string(GenerateThreadNameByPrefix("OS_FInnAd")), contentFilter_);
        int32_t ret = MSERR_UNKNOWN;
        CHECK_AND_RETURN_RET_LOG(audioSource_ != nullptr, ret, "audioSource_ is nullptr");
        if (!audioSource_->GetSpeakerAliveStatus() || audioSource_->GetIsInVoIPCall() ||
            !IsMicrophoneCaptureRunning()) {
            ret = innerAudioCapture_->Start(appInfo_);
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileInnerAudioCapture failed");
        }
    }
    if (showShareSystemAudioBox_ && !isInnerAudioBoxSelected_ && innerAudioCapture_) {
        MEDIA_LOGI("StartFileInnerAudioCapture set isMute");
        innerAudioCapture_->SetIsMute(true);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileInnerAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartFileMicAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileMicAudioCapture start, dataType:%{public}d, "
        "micCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.micCapInfo.state);
    CHECK_AND_RETURN_RET(!IsMicrophoneCaptureRunning(), MSERR_OK); // prevent repeat start
#ifdef SUPPORT_CALL
    if (InCallObserver::GetInstance().IsInCall(false) && !IsTelInCallSkipList()) {
        MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " skip creating micAudioCapture", FAKE_POINTER(this));
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
        return MSERR_OK;
    }
#endif
    std::shared_ptr<AudioCapturerWrapper> micCapture;
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartFileMicAudioCaptureInner");
        ScreenCaptureContentFilter contentFilterMic;
        micCapture = std::make_shared<AudioCapturerWrapper>(captureConfig_.audioInfo.micCapInfo, screenCaptureCb_,
            std::string(GenerateThreadNameByPrefix("OS_FMicAd")), contentFilterMic);
        if (audioSource_) {
            micCapture->SetIsInVoIPCall(audioSource_->GetIsInVoIPCall());
        }
        int32_t ret = micCapture->Start(appInfo_);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StartFileMicAudioCapture micCapture failed");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return ret;
        }
    }
    micAudioCapture_ = micCapture;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileMicAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartScreenCaptureStream()
{
    MediaTrace trace("ScreenCaptureServer::StartScreenCaptureStream");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartScreenCaptureStream start, dataType:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType);
    CHECK_AND_RETURN_RET(captureConfig_.dataType == DataType::ORIGINAL_STREAM, MSERR_INVALID_OPERATION);
    int32_t ret = StartAudioCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartAudioCapture failed, ret:%{public}d, dataType:%{public}d",
        ret, captureConfig_.dataType);

    ret = StartStreamVideoCapture();
    if (ret != MSERR_OK) {
        StopAudioCapture();
        MEDIA_LOGE("StartScreenCaptureStream failed");
        return ret;
    }
    MEDIA_LOGI("StartScreenCaptureStream success");
    return ret;
}

int32_t ScreenCaptureServer::StartScreenCaptureFile()
{
    CHECK_AND_RETURN_RET(captureConfig_.dataType == DataType::CAPTURE_FILE, MSERR_INVALID_OPERATION);

    MEDIA_LOGI("StartScreenCaptureFile S");
    int32_t ret = InitRecorder();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitRecorder failed, ret:%{public}d, dataType:%{public}d",
        ret, captureConfig_.dataType);

    ON_SCOPE_EXIT(0) {
        if (recorder_ != nullptr) {
            recorder_->Release();
            recorder_ = nullptr;
            consumer_ = nullptr;
        }
    };
    std::string virtualScreenName = "screen_capture_file";
    ret = CreateVirtualScreen(virtualScreenName, consumer_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen failed, ret:%{public}d, dataType:%{public}d",
        ret, captureConfig_.dataType);

    ON_SCOPE_EXIT(1) {
        DestroyVirtualScreen();
    };

    if (isMicrophoneSwitchTurnOn_) {
        int32_t retMic = StartFileMicAudioCapture();
        if (retMic != MSERR_OK) {
            MEDIA_LOGE("StartScreenCaptureFile StartFileMicAudioCapture failed");
            // not return, if start mic capture failed, inner capture will be started
        }
    }
    int32_t retInner = StartFileInnerAudioCapture();
    CHECK_AND_RETURN_RET_LOG(retInner == MSERR_OK, retInner, "StartFileInnerAudioCapture failed, ret:%{public}d,"
        "dataType:%{public}d", retInner, captureConfig_.dataType);
    MEDIA_LOGI("StartScreenCaptureFile RecorderServer S");
    ret = recorder_->Start();
    if (ret != MSERR_OK) {
        StopAudioCapture();
        MEDIA_LOGE("StartScreenCaptureFile recorder start failed");
    }
    MEDIA_LOGI("StartScreenCaptureFile RecorderServer E");
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "recorder failed, ret:%{public}d, dataType:%{public}d",
        ret, captureConfig_.dataType);
    CANCEL_SCOPE_EXIT_GUARD(1);
    CANCEL_SCOPE_EXIT_GUARD(0);

    MEDIA_LOGI("StartScreenCaptureFile E");
    return ret;
}

int32_t ScreenCaptureServer::OnStartScreenCapture()
{
    MediaTrace trace("ScreenCaptureServer::OnStartScreenCapture");
    MEDIA_LOGI("OnStartScreenCapture start, dataType:%{public}d", captureConfig_.dataType);
    captureState_ = AVScreenCaptureState::STARTING;
    int32_t ret = MSERR_UNSUPPORT;
    PublishScreenCaptureEvent("start");
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        ret = StartScreenCaptureStream();
    } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        ret = StartScreenCaptureFile();
    }
    if (ret == MSERR_OK) {
        int64_t endTime = GetCurrentMillisecond();
        statisticalEventInfo_.startLatency = static_cast<int32_t>(endTime - startTime_);
        MEDIA_LOGI("OnStartScreenCapture start success, dataType:%{public}d", captureConfig_.dataType);
    } else {
        MEDIA_LOGE("OnStartScreenCapture start failed, dataType:%{public}d", captureConfig_.dataType);
        statisticalEventInfo_.startLatency = -1; // latency -1 means invalid
    }
    return ret;
}

void ScreenCaptureServer::UpdateHighlightOutline(bool isStarted)
{
    MEDIA_LOGI("UpdateHighlightOutline enter");
    if (captureConfig_.captureMode == CaptureMode::CAPTURE_SPECIFIED_WINDOW &&
        (captureConfig_.highlightConfig.lineThickness >= MIN_LINE_WIDTH &&
        captureConfig_.highlightConfig.lineThickness <= MAX_LINE_WIDTH)) {
        Rosen::OutlineParams outlineParams;
        outlineParams.type_ = OutlineType::OUTLINE_FOR_WINDOW;
        SetHighlightConfigForWindowManager(isStarted, outlineParams);
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        sptr<IRemoteObject> media_server = samgr->GetSystemAbility(MEDIA_SERVICE_SA_ID);
        Rosen::WMError res = WindowManager::GetInstance().UpdateOutline(media_server, outlineParams);
        if (res == Rosen::WMError::WM_OK) {
            MEDIA_LOGI("UpdateHighlightOutline sussess");
        } else {
            MEDIA_LOGE("UpdateHighlightOutline failed:%{public}d", res);
        }
    }
}

void ScreenCaptureServer::SetHighlightConfigForWindowManager(bool isStarted,
    Rosen::OutlineParams &outlineParams)
{
    MEDIA_LOGI("SetHighlightConfigForWindowManager enter");
    if (isStarted) {
        outlineParams.persistentIds_.reserve(missionIds_.size());
        std::transform(missionIds_.begin(), missionIds_.end(), std::back_inserter(outlineParams.persistentIds_),
            [](uint64_t id) {
                uint64_t maxInt32 = std::numeric_limits<int32_t>::max();
                if (id > maxInt32) {
                    MEDIA_LOGE("SetHighlightConfigForWindowManager, windowId is an incorrect value");
                }
                return static_cast<int32_t>(id);
            });
        outlineParams.outlineStyleParams_.outlineColor_ = captureConfig_.highlightConfig.lineColor;
        outlineParams.outlineStyleParams_.outlineWidth_ = captureConfig_.highlightConfig.lineThickness;
        outlineParams.outlineStyleParams_.outlineShape_ =
            ConvertToOutlineShape(captureConfig_.highlightConfig.mode);
    } else {
        outlineParams.persistentIds_.clear();
        outlineParams.outlineStyleParams_.outlineColor_ = OUTLINE_COLOR_DEFAULT;
        outlineParams.outlineStyleParams_.outlineWidth_ = OUTLINE_WIDTH_DEFAULT;
        outlineParams.outlineStyleParams_.outlineShape_ = OutlineShape::OUTLINE_SHAPE_FOUR_CORNERS;
    }
    MEDIA_LOGI("SetHighlightConfigForWindowManager, isStarted:%{public}s, lineColor:0x%{public}x,"
        " lineThickness:%{public}dvp, mode:%{public}d", isStarted ? "true" : "false",
        outlineParams.outlineStyleParams_.outlineColor_, outlineParams.outlineStyleParams_.outlineWidth_,
        outlineParams.outlineStyleParams_.outlineShape_);
}

OutlineShape ScreenCaptureServer::ConvertToOutlineShape(ScreenCaptureHighlightMode mode)
{
    switch (mode) {
        case ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED:
            return OutlineShape::OUTLINE_SHAPE_RECTANGLE;
        case ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CORNER_WRAP:
            return OutlineShape::OUTLINE_SHAPE_FOUR_CORNERS;
        default:
            return OutlineShape::OUTLINE_SHAPE_END;
    }
}

void ScreenCaptureServer::ResSchedReportData(int64_t value, std::unordered_map<std::string, std::string> payload)
{
    payload["uid"] = std::to_string(appInfo_.appUid);
    payload["pid"] = std::to_string(appInfo_.appPid);
    uint32_t type = ResourceSchedule::ResType::RES_TYPE_REPORT_SCREEN_CAPTURE;
    ResourceSchedule::ResSchedClient::GetInstance().ReportData(type, value, payload);
}

void ScreenCaptureServer::RegisterPrivateWindowListener()
{
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    displayListener_ = new PrivateWindowListenerInScreenCapture(screenCaptureServer);
    DisplayManager::GetInstance().RegisterPrivateWindowListener(displayListener_);
}

void ScreenCaptureServer::RegisterScreenConnectListener()
{
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    screenConnectListener_ = sptr<ScreenConnectListenerForSC>::MakeSptr(displayScreenId_, screenCaptureServer);
    MEDIA_LOGI("RegisterScreenConnectListener screenId: %{public}" PRIu64, displayScreenId_);
    ScreenManager::GetInstance().RegisterScreenListener(screenConnectListener_);
}

void ScreenCaptureServer::PostStartScreenCaptureSuccessAction()
{
    std::unordered_map<std::string, std::string> payload;
    int64_t value = ResourceSchedule::ResType::ScreenCaptureStatus::START_SCREEN_CAPTURE;
    ResSchedReportData(value, payload);
    captureState_ = AVScreenCaptureState::STARTED;
    AddStartedSessionIdList(this->sessionId_);
    MEDIA_LOGI("sessionId: %{public}d is pushed, now the size of startedSessionIDList_ is: %{public}d",
        this->sessionId_, static_cast<uint32_t>(ScreenCaptureServer::startedSessionIDList_.size()));
    SetSystemScreenRecorderStatus(true);
    ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureStarted(appInfo_.appPid);
    NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    if (displayScreenId_ != SCREEN_ID_INVALID) {
        NotifyDisplaySelected(displayScreenId_);
    }
}

bool ScreenCaptureServer::IsFirstStartPidInstance(int32_t pid)
{
    std::list<int32_t> pidList{};
    ScreenCaptureServer::GetRunningScreenCaptureInstancePid(pidList);
    std::list<int32_t>::iterator iter = find(pidList.begin(), pidList.end(), pid);
    if (iter == pidList.end()) {
        MEDIA_LOGD("ScreenCaptureServer::IsFirstStartPidInstance firstPid: %{public}d", pid);
        return true;
    }
    MEDIA_LOGD("ScreenCaptureServer::IsFirstStartPidInstance pid: %{public}d exists", pid);
    return false;
}

bool ScreenCaptureServer::FirstPidUpdatePrivacyUsingPermissionState(int32_t pid)
{
    if (IsFirstStartPidInstance(pid)) {
        return UpdatePrivacyUsingPermissionState(START_VIDEO);
    }
    return true;
}

void ScreenCaptureServer::NotifyStateChange(AVScreenCaptureStateCode stateCode)
{
    if (screenCaptureCb_ != nullptr) {
        MEDIA_LOGD("NotifyStateChange stateCode: %{public}d", stateCode);
        screenCaptureCb_->OnStateChange(stateCode);
    }
}

void ScreenCaptureServer::NotifyDisplaySelected(uint64_t displayId)
{
    if (screenCaptureCb_ != nullptr) {
        MEDIA_LOGD("NotifyDisplaySelected displayId: (%{public}" PRIu64 ")", displayId);
        screenCaptureCb_->OnDisplaySelected(displayId);
    }
}

void ScreenCaptureServer::PrepareUserSelectionInfo(ScreenCaptureUserSelectionInfo &selectionInfo)
{
    MEDIA_LOGI("PrepareUserSelectionInfo start");
    if (captureConfig_.captureMode == CaptureMode::CAPTURE_SPECIFIED_WINDOW) {
        selectionInfo.selectType = SELECT_TYPE_WINDOW;
        sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
        CHECK_AND_RETURN_LOG(defaultDisplay != nullptr, "PrepareUserSelectionInfo GetDefaultDisplaySync failed");
        selectionInfo.displayId = GetDisplayIdOfWindows(defaultDisplay->GetScreenId());
    } else {
        selectionInfo.selectType = SELECT_TYPE_SCREEN;
        selectionInfo.displayId = captureConfig_.videoInfo.videoCapInfo.displayId;
    }
}

void ScreenCaptureServer::NotifyUserSelected(ScreenCaptureUserSelectionInfo selectionInfo)
{
    if (screenCaptureCb_ != nullptr) {
        MEDIA_LOGI("NotifyUserSelected displayId: %{public}" PRIu64 ", selectType: %{public}d",
            selectionInfo.displayId, selectionInfo.selectType);
        screenCaptureCb_->OnUserSelected(selectionInfo);
    }
}

void ScreenCaptureServer::PostStartScreenCapture(bool isSuccess)
{
    CHECK_AND_RETURN(screenCaptureCb_ != nullptr);
    MediaTrace trace("ScreenCaptureServer::PostStartScreenCapture.");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture start, isSuccess:%{public}s, "
        "dataType:%{public}d.", FAKE_POINTER(this), isSuccess ? "true" : "false", captureConfig_.dataType);
    if (isSuccess) {
        MEDIA_LOGI("PostStartScreenCapture handle success");
#ifdef PC_STANDARD
        SetTimeoutScreenoffDisableLock(false);
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
        if (isPrivacyAuthorityEnabled_ &&
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
                .compare(appName_) != 0 && !isScreenCaptureAuthority_) {
            if (TryNotificationOnPostStartScreenCapture() == MSERR_UNKNOWN) {
                return;
            }
        }
#endif
        if (!FirstPidUpdatePrivacyUsingPermissionState(appInfo_.appPid)) {
            MEDIA_LOGE("UpdatePrivacyUsingPermissionState START failed, dataType:%{public}d", captureConfig_.dataType);
            captureState_ = AVScreenCaptureState::STARTED;
            screenCaptureCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
                AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
            StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
            return;
        }
        MEDIA_LOGI("PostStartScreenCaptureSuccessAction START.");
        UpdateHighlightOutline(true);
        PostStartScreenCaptureSuccessAction();
    } else {
        PostStartScreenCaptureFail();
        return;
    }
    RegisterPrivateWindowListener();
    RegisterScreenConnectListener();
    RegisterLanguageSwitchListener();
    std::shared_lock<std::shared_mutex> read_lock(rw_lock_);
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW && missionIds_.size() == 1) {
        SetWindowIdList(missionIds_.front());
        SetDefaultDisplayIdOfWindows();
        RegisterWindowRelatedListener();
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture end.", FAKE_POINTER(this));
}

void ScreenCaptureServer::PostStartScreenCaptureFail()
{
    MEDIA_LOGE("PostStartScreenCapture handle failure");
    if (isPrivacyAuthorityEnabled_) {
        screenCaptureCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
            AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
    }
    StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
    isPrivacyAuthorityEnabled_ = false;
    isSurfaceMode_ = false;
    captureState_ = AVScreenCaptureState::STOPPED;
    SetErrorInfo(MSERR_UNKNOWN, "PostStartScreenCapture handle failure",
        StopReason::POST_START_SCREENCAPTURE_HANDLE_FAILURE, IsUserPrivacyAuthorityNeeded());
}

#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
int32_t ScreenCaptureServer::TryStartNotification()
{
    int32_t tryTimes;
    for (tryTimes = 1; tryTimes <= NOTIFICATION_MAX_TRY_NUM; tryTimes++) {
        int32_t ret = StartNotification();
        if (ret == MSERR_OK) {
            break;
        }
    }
    return tryTimes;
}

int32_t ScreenCaptureServer::TryNotificationOnPostStartScreenCapture()
{
    int32_t tryTimes = TryStartNotification();
    if (tryTimes > NOTIFICATION_MAX_TRY_NUM) {
        captureState_ = AVScreenCaptureState::STARTED;
        if (screenCaptureCb_ != nullptr) {
            screenCaptureCb_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
                AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
        }
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
        return MSERR_UNKNOWN;
    }
    return MSERR_OK;
}
#endif

void ScreenCaptureServer::RegisterLanguageSwitchListener()
{
    MEDIA_LOGI("ScreenCaptureServer::RegisterLanguageSwitchListener");
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) == 0) {
        return;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent("usual.event.LOCALE_CHANGED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto onReceiveEvent = std::bind(&ScreenCaptureServer::OnReceiveEvent, this, std::placeholders::_1);
    subscriber_ = std::make_shared<ScreenCaptureSubscriber>(
        subscribeInfo, onReceiveEvent);
    if (subscriber_ == nullptr) {
        MEDIA_LOGE("RegisterLanguageSwitchListener subscriber_ is null");
        return;
    }
    EventFwk::CommonEventManager::SubscribeCommonEvent(subscriber_);
}

void ScreenCaptureServer::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    MEDIA_LOGI("ScreenCaptureServer::OnReceiveEvent");
    NotificationRequest request;
    UpdateLiveViewContent();
    SetupPublishRequest(request);
    NotificationHelper::PublishNotification(request);
}

void ScreenCaptureServer::UnRegisterLanguageSwitchListener()
{
    MEDIA_LOGI("ScreenCaptureServer::UnRegisterLanguageSwitchListener");
    if (subscriber_ == nullptr) {
        MEDIA_LOGE("UnRegisterLanguageSwitchListener subscriber_ is null");
        return;
    }
    EventFwk::CommonEventManager::UnSubscribeCommonEvent(subscriber_);
}

int32_t ScreenCaptureServer::InitAudioCap(AudioCaptureInfo audioInfo)
{
    MediaTrace trace("ScreenCaptureServer::InitAudioCap");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitAudioCap start, audioChannels:%{public}d, "
        "audioSampleRate:%{public}d, audioSource:%{public}d, state:%{public}d.", FAKE_POINTER(this),
        audioInfo.audioChannels, audioInfo.audioSampleRate, audioInfo.audioSource, audioInfo.state);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "InitAudioCap failed, capture is not CREATED, state:%{public}d", captureState_);

    int ret = CheckAudioCapInfo(audioInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitAudioCap CheckAudioCapInfo failed, audioSource:%{public}d",
        audioInfo.audioSource);
    if (audioInfo.audioSource == AudioCaptureSourceType::SOURCE_DEFAULT ||
        audioInfo.audioSource == AudioCaptureSourceType::MIC) {
        captureConfig_.audioInfo.micCapInfo = audioInfo;
        statisticalEventInfo_.requireMic = true;
    } else if (audioInfo.audioSource == AudioCaptureSourceType::ALL_PLAYBACK ||
        audioInfo.audioSource == AudioCaptureSourceType::APP_PLAYBACK) {
        captureConfig_.audioInfo.innerCapInfo = audioInfo;
        avType_ = (avType_ == AVScreenCaptureAvType::INVALID_TYPE) ? AVScreenCaptureAvType::AUDIO_TYPE :
            AVScreenCaptureAvType::AV_TYPE;
#ifdef PC_STANDARD
        showShareSystemAudioBox_ = true;
        MEDIA_LOGI("InitAudioCap set showShareSystemAudioBox true.");
#endif
    }
    MEDIA_LOGI("InitAudioCap success sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d,"
        "showShareSystemAudioBox:%{public}d", audioInfo.audioSampleRate, audioInfo.audioChannels,
        audioInfo.audioSource, audioInfo.state, showShareSystemAudioBox_);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitVideoCap(VideoCaptureInfo videoInfo)
{
    MediaTrace trace("ScreenCaptureServer::InitVideoCap");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION,
        "InitVideoCap failed, capture is not CREATED, state:%{public}d", captureState_);

    int ret = CheckVideoCapInfo(videoInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoCap CheckVideoCapInfo failed");
    captureConfig_.videoInfo.videoCapInfo = videoInfo;
    avType_ = (avType_ == AVScreenCaptureAvType::AUDIO_TYPE) ? AVScreenCaptureAvType::AV_TYPE :
        AVScreenCaptureAvType::VIDEO_TYPE;
    statisticalEventInfo_.videoResolution = std::to_string(videoInfo.videoFrameWidth) + " * " +
        std::to_string(videoInfo.videoFrameHeight);
    MEDIA_LOGI("InitVideoCap success width:%{public}d, height:%{public}d, source:%{public}d, state:%{public}d",
        videoInfo.videoFrameWidth, videoInfo.videoFrameHeight, videoInfo.videoSource, videoInfo.state);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitRecorderInfo(std::shared_ptr<IRecorderService> &recorder, AudioCaptureInfo audioInfo)
{
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, MSERR_UNKNOWN, "init InitRecorderInfo failed");
    int32_t ret = MSERR_OK;
    if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        ret = recorder_->SetVideoSource(captureConfig_.videoInfo.videoCapInfo.videoSource, videoSourceId_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetVideoSource failed");
    }
    ret = recorder->SetOutputFormat(fileFormat_); // Change to REC_CONFIGURED
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetOutputFormat failed");
    ret = recorder->SetAudioEncoder(audioSourceId_, captureConfig_.audioInfo.audioEncInfo.audioCodecformat);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioEncoder failed");
    ret = recorder->SetAudioSampleRate(audioSourceId_, audioInfo.audioSampleRate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioSampleRate failed");
    ret = recorder->SetAudioChannels(audioSourceId_, audioInfo.audioChannels);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioChannels failed");
    ret = recorder->SetAudioEncodingBitRate(audioSourceId_, captureConfig_.audioInfo.audioEncInfo.audioBitrate);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioEncodingBitRate failed");
    if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        ret = recorder->SetVideoEncoder(videoSourceId_, captureConfig_.videoInfo.videoEncInfo.videoCodec);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetVideoEncoder failed");
        ret = recorder->SetVideoSize(videoSourceId_, captureConfig_.videoInfo.videoCapInfo.videoFrameWidth,
            captureConfig_.videoInfo.videoCapInfo.videoFrameHeight);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetVideoSize failed");
        ret = recorder->SetVideoFrameRate(videoSourceId_, captureConfig_.videoInfo.videoEncInfo.videoFrameRate);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetVideoFrameRate failed");
        ret = recorder->SetVideoEncodingBitRate(videoSourceId_, captureConfig_.videoInfo.videoEncInfo.videoBitrate);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetVideoEncodingBitRate failed");
        ret = recorder->SetVideoEnableBFrame(videoSourceId_, captureConfig_.strategy.enableBFrame);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("recorder SetVideoEnableBFrame failed");
            // continue, do not return error
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitRecorderMix()
{
    int32_t ret = MSERR_OK;
    MEDIA_LOGI("InitRecorder prepare to SetAudioDataSource");
    audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, this);
    captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
    audioSource_->SetAppPid(appInfo_.appPid);
    audioSource_->SetAppName(appName_);
    captureCallback_->SetAppName(appName_);
    captureCallback_->SetAudioSource(audioSource_);
    audioSource_->RegisterAudioRendererEventListener(appInfo_.appPid, captureCallback_);
    ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
    recorderFileAudioType_ = AVScreenCaptureMixMode::MIX_MODE;
    return ret;
}

int32_t ScreenCaptureServer::InitRecorderInner()
{
    int32_t ret = MSERR_OK;
    isMicrophoneSwitchTurnOn_ = false;
    MEDIA_LOGI("InitRecorder prepare to SetAudioSource inner");
    audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, this);
    ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
    recorderFileAudioType_ = AVScreenCaptureMixMode::INNER_MODE;
    return ret;
}

int32_t ScreenCaptureServer::InitRecorder()
{
    CHECK_AND_RETURN_RET_LOG(outputFd_ > 0, MSERR_INVALID_OPERATION, "the outputFd is invalid");
    MEDIA_LOGI("InitRecorder start");
    MediaTrace trace("ScreenCaptureServer::InitRecorder");
    recorder_ = Media::RecorderServer::Create();
    CHECK_AND_RETURN_RET_LOG(recorder_ != nullptr, MSERR_UNKNOWN, "init Recoder failed");
    ON_SCOPE_EXIT(0) {
        recorder_->Release();
    };
    int32_t ret;
    AudioCaptureInfo audioInfo;
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID &&
        captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        ret = InitRecorderMix();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        ret = InitRecorderInner();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.micCapInfo;
        MEDIA_LOGI("InitRecorder prepare to SetAudioSource mic");
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, this);
        ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
        recorderFileAudioType_ = AVScreenCaptureMixMode::MIC_MODE;
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioDataSource failed");
    } else {
        MEDIA_LOGE("InitRecorder not VALIDATION_VALID");
        return MSERR_UNKNOWN;
    }
    MEDIA_LOGI("InitRecorder recorder SetAudioDataSource ret:%{public}d", ret);
    ret = InitRecorderInfo(recorder_, audioInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "InitRecorderInfo failed");
    ret = recorder_->SetOutputFile(outputFd_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetOutputFile failed");
    ret = recorder_->Prepare();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "recorder Prepare failed");
    if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        recorderFileWithVideo_.store(true);
        consumer_ = recorder_->GetSurface(videoSourceId_);
        CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_UNKNOWN, "recorder GetSurface failed");
    }
    CANCEL_SCOPE_EXIT_GUARD(0);
    MEDIA_LOGI("InitRecorder success");
    return MSERR_OK;
}

bool ScreenCaptureServer::UpdatePrivacyUsingPermissionState(VideoPermissionState state)
{
    MediaTrace trace("ScreenCaptureServer::UpdatePrivacyUsingPermissionState");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " UpdatePrivacyUsingPermissionState start, "
        "state: %{public}d, uid: %{public}d", FAKE_POINTER(this), state, appInfo_.appUid);
    if (!IsUserPrivacyAuthorityNeeded()) {
        MEDIA_LOGI("Using Permission Ignored. state: %{public}d, uid: %{public}d", state, appInfo_.appUid);
        return true;
    }

    int res = 0;
    if (state == START_VIDEO) {
        res = PrivacyKit::StartUsingPermission(appInfo_.appTokenId, "ohos.permission.CAPTURE_SCREEN", appInfo_.appPid);
        if (res != 0) {
            MEDIA_LOGE("start using perm error");
            return false;
        }
        res = PrivacyKit::AddPermissionUsedRecord(appInfo_.appTokenId, "ohos.permission.CAPTURE_SCREEN", 1, 0);
        if (res != 0) {
            MEDIA_LOGE("add screen capture record error: %{public}d", res);
            return false;
        }
    } else if (state == STOP_VIDEO) {
        res = PrivacyKit::StopUsingPermission(appInfo_.appTokenId, "ohos.permission.CAPTURE_SCREEN", appInfo_.appPid);
        if (res != 0) {
            MEDIA_LOGE("stop using perm error");
            return false;
        }
    }
    return true;
}

int32_t ScreenCaptureServer::StartScreenCaptureInner(bool isPrivacyAuthorityEnabled)
{
    MEDIA_LOGI("StartScreenCaptureInner S, appUid:%{public}d, appPid:%{public}d, isPrivacyAuthorityEnabled:%{public}d"
        ", isSurfaceMode:%{public}d, dataType:%{public}d", appInfo_.appUid, appInfo_.appPid, isPrivacyAuthorityEnabled,
        isSurfaceMode_, captureConfig_.dataType);
    MediaTrace trace("ScreenCaptureServer::StartScreenCaptureInner");
    
    int32_t ret = RegisterServerCallbacks();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterServerCallbacks failed");

    ret = CheckAllParams();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartScreenCaptureInner failed, invalid params");

    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(display != nullptr, MSERR_UNKNOWN, "GetDefaultDisplaySync failed");
    density_ = display->GetVirtualPixelRatio();

    GetSystemUIFlag();
    appName_ = GetClientBundleName(appInfo_.appUid);
    callingLabel_ = GetBundleResourceLabel(appName_);
    MEDIA_LOGD("StartScreenCaptureInner callingLabel: %{public}s", callingLabel_.c_str());

    isPrivacyAuthorityEnabled_ = isPrivacyAuthorityEnabled;
    captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    isScreenCaptureAuthority_ = CheckPrivacyWindowSkipPermission();

    if (GetSCServerDataType() == DataType::ORIGINAL_STREAM) {
        showSensitiveCheckBox_ = true;
        checkBoxSelected_ = true;
    }
    MEDIA_LOGI("StartScreenCaptureInner showSensitiveCheckBox: %{public}d, checkBoxSelected: %{public}d",
        showSensitiveCheckBox_, checkBoxSelected_);

    if (!isScreenCaptureAuthority_ && IsUserPrivacyAuthorityNeeded()) {
        bool isSkipPrivacyWindow = false;
        ret = RequestUserPrivacyAuthority(isSkipPrivacyWindow);
        if (ret != MSERR_OK) {
            captureState_ = AVScreenCaptureState::STOPPED;
            SetErrorInfo(ret, "StartScreenCaptureInner RequestUserPrivacyAuthority failed",
                StopReason::REQUEST_USER_PRIVACY_AUTHORITY_FAILED, IsUserPrivacyAuthorityNeeded());
            MEDIA_LOGE("StartScreenCaptureInner RequestUserPrivacyAuthority failed");
            return ret;
        }

        if (isPrivacyAuthorityEnabled_ && !isSkipPrivacyWindow) {
            MEDIA_LOGI("Wait for user interactions to ALLOW/DENY capture");
            return MSERR_OK;
        }
        MEDIA_LOGI("privacy notification window not support, app has CAPTURE_SCREEN permission and go on");
    } else {
        MEDIA_LOGI("Privacy Authority granted automatically and go on"); // for root and skip permission
    }

    ret = OnStartScreenCapture();
    PostStartScreenCapture(ret == MSERR_OK);

    MEDIA_LOGI("StartScreenCaptureInner E, appUid:%{public}d, appPid:%{public}d", appInfo_.appUid, appInfo_.appPid);
    return ret;
}

void ScreenCaptureServer::PublishScreenCaptureEvent(const std::string& state)
{
    AAFwk::Want want;
    want.SetAction("usual.event.SCREEN_SHARE");
    want.SetParam("screenCaptureState", state);
    want.SetParam("screenCaptureUid", appInfo_.appUid);
    want.SetParam("screenCaptureSessionId", sessionId_);
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        want.SetParam("screenCaptureType", std::string("originalStream"));
    } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        want.SetParam("screenCaptureType", std::string("captureFile"));
    }
    EventFwk::CommonEventPublishInfo commonEventPublishInfo;
    commonEventPublishInfo.SetSubscriberType(EventFwk::SubscriberType::SYSTEM_SUBSCRIBER_TYPE);
    EventFwk::CommonEventData commonData {want};
    EventFwk::CommonEventManager::PublishCommonEvent(commonData, commonEventPublishInfo);
    MEDIA_LOGI("ohos.permission.SHARE_SCREEN publish, uid: %{public}d, type: %{public}d, sessionId: %{public}d",
        appInfo_.appUid, captureConfig_.dataType, sessionId_);
}

bool ScreenCaptureServer::IsTelInCallSkipList()
{
    MEDIA_LOGI("ScreenCaptureServer::IsTelInCallSkipList isCalledBySystemApp : %{public}d", isCalledBySystemApp_);
    if (isCalledBySystemApp_ &&
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.hiviewcarebundlename"]
            .compare(appName_) == 0) {
        MEDIA_LOGI("ScreenCaptureServer::IsTelInCallSkipList true");
        return true;
    }
    return false;
}

int32_t ScreenCaptureServer::RegisterServerCallbacks()
{
    std::weak_ptr<ScreenCaptureServer> wpScreenCaptureServer(shared_from_this());
    screenCaptureObserverCb_ = std::make_shared<ScreenCaptureObserverCallBack>(wpScreenCaptureServer);
#ifdef SUPPORT_CALL
    uint64_t tokenId = IPCSkeleton::GetCallingFullTokenID();
    isCalledBySystemApp_ = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    MEDIA_LOGI("ScreenCaptureServer::RegisterServerCallbacks isCalledBySystemApp: %{public}d", isCalledBySystemApp_);
    if (!captureConfig_.strategy.keepCaptureDuringCall && InCallObserver::GetInstance().IsInCall(true) &&
        !IsTelInCallSkipList()) {
        MEDIA_LOGI("ScreenCaptureServer Start InCall Abort");
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNSUPPORT,
            "ScreenCaptureServer Start InCall Abort");
        return MSERR_UNSUPPORT;
    }
    MEDIA_LOGI("ScreenCaptureServer Start RegisterScreenCaptureCallBack");
    InCallObserver::GetInstance().RegisterInCallObserverCallBack(screenCaptureObserverCb_);
#endif
    AccountObserver::GetInstance().RegisterAccountObserverCallBack(screenCaptureObserverCb_);
    return MSERR_OK;
}

#ifdef PC_STANDARD
bool ScreenCaptureServer::CheckCaptureSpecifiedWindowForSelectWindow()
{
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW &&
        captureConfig_.videoInfo.videoCapInfo.taskIDs.size() < SELECT_WINDOW_MISSION_ID_NUM_MAX) {
            return true;
    }
    return false;
}

void ScreenCaptureServer::SendConfigToUIParams(AAFwk::Want& want)
{
    want.SetParam("displayId", static_cast<int32_t>(captureConfig_.videoInfo.videoCapInfo.displayId));
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_SCREEN) {
        MEDIA_LOGI("CAPTURE_SPECIFIED_SCREEN, displayId: %{public}" PRId64 " missionId is dropped.",
            captureConfig_.videoInfo.videoCapInfo.displayId);
        captureConfig_.videoInfo.videoCapInfo.taskIDs = {};
        want.SetParam("missionId", -1); // -1 无效值
    } else if (CheckCaptureSpecifiedWindowForSelectWindow() &&
        captureConfig_.videoInfo.videoCapInfo.taskIDs.size() == 1) {
        MEDIA_LOGI("CAPTURE_SPECIFIED_WINDOW, missionId: %{public}d",
            *(captureConfig_.videoInfo.videoCapInfo.taskIDs.begin()));
        want.SetParam("missionId", *(captureConfig_.videoInfo.videoCapInfo.taskIDs.begin()));
    } else if (CheckCaptureSpecifiedWindowForSelectWindow() &&
        captureConfig_.videoInfo.videoCapInfo.taskIDs.size() == 0) {
        want.SetParam("missionId", -1); // -1 无效值
    }
}
#endif

std::string ScreenCaptureServer::BuildCommandString()
{
    std::string comStr = "{\"ability.want.params.uiExtensionType\":\"sys/commonUI\",\"sessionId\":\"";
    comStr += std::to_string(sessionId_);
    comStr += "\",\"callerUid\":\"";
    comStr += std::to_string(appInfo_.appUid);
    comStr += "\",\"appLabel\":\"";
    comStr += callingLabel_;
    comStr += "\",\"showSensitiveCheckBox\":\"";
    comStr += std::to_string(showSensitiveCheckBox_);
    comStr += "\",\"checkBoxSelected\":\"";
    comStr += std::to_string(checkBoxSelected_);
    comStr += "\"}";
    return comStr;
}

int32_t ScreenCaptureServer::StartPrivacyWindow()
{
    std::string comStr = BuildCommandString();

    AAFwk::Want want;
    ErrCode ret = ERR_INVALID_VALUE;
#ifdef PC_STANDARD
    if (IsPickerPopUp()) {
        isRegionCapture_ = false;
        AppExecFwk::ElementName element("",
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"],
            SELECT_ABILITY_NAME); // DeviceID
        want.SetElement(element);
        want.SetParam("params", comStr);
        want.SetParam("appLabel", callingLabel_);
        want.SetParam("sessionId", sessionId_);
        want.SetParam("showSensitiveCheckBox", showSensitiveCheckBox_);
        want.SetParam("checkBoxSelected", checkBoxSelected_);
        want.SetParam("showShareSystemAudioBox", showShareSystemAudioBox_);
        want.SetParam("excludedWindowIDs", ScreenCaptureServer::JoinInt32Vector(excludedWindowIDsVec_));
        want.SetParam("pickerMode", static_cast<int>(pickerMode_));
        SendConfigToUIParams(want);
        ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        MEDIA_LOGI("StartAbility end %{public}d, DeviceType : PC", ret);
    } else {
        showShareSystemAudioBox_ = false;
        want.SetElementName(GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"],
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionabilityname"]);
        connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(comStr));
        ret = OHOS::AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_,
            nullptr, -1);
        MEDIA_LOGI("ConnectServiceExtensionAbility end %{public}d, DeviceType : PC", ret);
    }
#else
    want.SetElementName(GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"],
                        GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionabilityname"]);
    connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(comStr));
    ret = OHOS::AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_,
        nullptr, -1);
    MEDIA_LOGI("ConnectServiceExtensionAbility end %{public}d, Device : Phone", ret);
#endif
    return ret;
}

std::string ScreenCaptureServer::JoinInt32Vector(const std::vector<int32_t>& vec, const std::string& separator)
{
    if (vec.empty()) {
        return "";
    }

    std::ostringstream oss;
    oss << vec[0];

    for (size_t i = 1; i < vec.size(); ++i) {
        oss << separator << vec[i];
    }

    return oss.str();
}

int32_t ScreenCaptureServer::StartNotification()
{
    int32_t result = NotificationHelper::SubscribeLocalLiveViewNotification(NOTIFICATION_SUBSCRIBER);
    MEDIA_LOGD("StartNotification, result %{public}d", result);
    NotificationRequest request;
    InitLiveViewContent();
    notificationId_ = sessionId_;
    SetupPublishRequest(request);
    result = NotificationHelper::PublishNotification(request);
    MEDIA_LOGI("StartNotification uid %{public}d, result %{public}d", AV_SCREEN_CAPTURE_SESSION_UID, result);
    return result;
}

std::string ScreenCaptureServer::GetStringByResourceName(const char* name)
{
    std::string resourceContext;
    CHECK_AND_RETURN_RET_LOG(resourceManager_ != nullptr, resourceContext, "resourceManager is null");
    if (strcmp(name, NOTIFICATION_SCREEN_RECORDING_TITLE_ID) == 0 ||
        strcmp(name, NOTIFICATION_SCREEN_RECORDING_PRIVACY_ON_ID) == 0 ||
        strcmp(name, NOTIFICATION_SCREEN_RECORDING_PRIVACY_OFF_ID) == 0) {
        resourceManager_->GetStringByName(name, resourceContext);
        MEDIA_LOGD("get NOTIFICATION_SCREEN_RECORDING_TITLE_ID: %{public}s", resourceContext.c_str());
    } else {
        MEDIA_LOGE("resource name is error.");
    }
    return resourceContext;
}

void ScreenCaptureServer::RefreshResConfig()
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language, status);
    if (status != U_ZERO_ERROR) {
        MEDIA_LOGE("forLanguageTag failed, errCode:%{public}d", status);
    }
    if (resConfig_) {
        resConfig_->SetLocaleInfo(locale.getLanguage(), locale.getScript(), locale.getCountry());
        if (resourceManager_) {
            resourceManager_->UpdateResConfig(*resConfig_);
        }
    }
}

void ScreenCaptureServer::InitResourceManager()
{
    if (resourceManager_ == nullptr) {
        resourceManager_ = Global::Resource::GetSystemResourceManagerNoSandBox();
    }
    if (resConfig_ == nullptr) {
        resConfig_ = Global::Resource::CreateResConfig();
    }
    RefreshResConfig();
}

void ScreenCaptureServer::InitLiveViewContent()
{
    localLiveViewContent_ =
        std::make_shared<NotificationLocalLiveViewContent>();
    localLiveViewContent_->SetType(1);
    UpdateLiveViewContent();
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);
    NotificationLocalLiveViewButton basicButton;
    basicButton.addSingleButtonName(BUTTON_NAME_STOP);
    std::shared_ptr<PixelMap> pixelMapStopSpr = GetPixelMapSvg(ICON_PATH_STOP, SVG_HEIGHT, SVG_WIDTH);
    basicButton.addSingleButtonIcon(pixelMapStopSpr);
    localLiveViewContent_->SetButton(basicButton);
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
}

void ScreenCaptureServer::UpdateLiveViewContent()
{
    InitResourceManager();
    std::string recordingScreenTitleStr = GetStringByResourceName(NOTIFICATION_SCREEN_RECORDING_TITLE_ID);
    std::string from = "%s";
    std::string to = QUOTATION_MARKS_STRING + callingLabel_ + QUOTATION_MARKS_STRING;
    size_t startPos = recordingScreenTitleStr.find(from);
    if (startPos != std::string::npos) {
        recordingScreenTitleStr.replace(startPos, from.length(), to);
        liveViewText_ = recordingScreenTitleStr;
    }
    MEDIA_LOGD("UpdateLiveViewContent liveViewText: %{public}s", liveViewText_.c_str());
    NotificationCapsule capsule;
    capsule.SetBackgroundColor(BACK_GROUND_COLOR);
    capsulePxSize_ = static_cast<int32_t>(capsuleVpSize_ * density_);
    std::shared_ptr<PixelMap> pixelMapCapSpr;
    if (isSystemUI2_) {
        pixelMapCapSpr = GetPixelMapSvg(ICON_PATH_CAPSULE_STOP_2_0, capsulePxSize_, capsulePxSize_);
    } else {
        pixelMapCapSpr = GetPixelMapSvg(ICON_PATH_CAPSULE_STOP, capsulePxSize_, capsulePxSize_);
    }
    capsule.SetIcon(pixelMapCapSpr);
    CHECK_AND_RETURN_LOG(localLiveViewContent_ != nullptr, "localLiveViewContent_ is null");
    if (GetSCServerDataType() == DataType::ORIGINAL_STREAM) {
        localLiveViewContent_->SetTitle(liveViewText_);
        UpdateLiveViewPrivacy();
        MEDIA_LOGI("UpdateLiveViewContent additionalText: %{public}s", liveViewSubText_.c_str());
        capsule.SetTitle(callingLabel_);
    } else {
        localLiveViewContent_->SetText(liveViewText_);
        NotificationTime countTime;
        countTime.SetIsCountDown(false);
        countTime.SetIsPaused(false);
        countTime.SetIsInTitle(true);
        countTime.SetInitialTime(1);
        localLiveViewContent_->SetTime(countTime);
        localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);
    }
    localLiveViewContent_->SetCapsule(capsule);
}

void ScreenCaptureServer::UpdateLiveViewPrivacy()
{
    CHECK_AND_RETURN_LOG(localLiveViewContent_ != nullptr, "localLiveViewContent_ is null");
    if (!systemPrivacyProtectionSwitch_ && !appPrivacyProtectionSwitch_) {
        liveViewSubText_ = GetStringByResourceName(NOTIFICATION_SCREEN_RECORDING_PRIVACY_OFF_ID);
    } else {
        liveViewSubText_ = GetStringByResourceName(NOTIFICATION_SCREEN_RECORDING_PRIVACY_ON_ID);
    }
    localLiveViewContent_->SetText(liveViewSubText_);
}

std::shared_ptr<PixelMap> ScreenCaptureServer::GetPixelMap(std::string path)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/png";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(path, opts, errorCode);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "GetPixelMap CreateImageSource failed");
    DecodeOptions decodeOpts;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    std::shared_ptr<PixelMap> pixelMapSpr = std::move(pixelMap);
    return pixelMapSpr;
}

std::shared_ptr<PixelMap> ScreenCaptureServer::GetPixelMapSvg(std::string path, int32_t width, int32_t height)
{
    uint32_t errorCode = 0;
    SourceOptions opts;
    opts.formatHint = "image/svg+xml";
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(path, opts, errorCode);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "GetPixelMapSvg CreateImageSource failed");
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize.width = width;
    decodeOpts.desiredSize.height = height;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, errorCode);
    std::shared_ptr<PixelMap> pixelMapSpr = std::move(pixelMap);
    return pixelMapSpr;
}

void ScreenCaptureServer::UpdateMicrophoneEnabled()
{
    UpdateLiveViewContent();
    NotificationRequest request;

    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(localLiveViewContent_);

    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request.SetNotificationId(notificationId_);
    request.SetContent(content);
    request.SetCreatorUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetOwnerUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetUnremovable(true);
    request.SetInProgress(true);

    std::shared_ptr<PixelMap> pixelMapTotalSpr;
    if (isSystemUI2_) {
        pixelMapTotalSpr = GetPixelMapSvg(ICON_PATH_CAPSULE_STOP_2_0, capsulePxSize_, capsulePxSize_);
    } else {
        pixelMapTotalSpr = GetPixelMapSvg(ICON_PATH_CAPSULE_STOP, capsulePxSize_, capsulePxSize_);
    }
    request.SetLittleIcon(pixelMapTotalSpr);
    request.SetBadgeIconStyle(NotificationRequest::BadgeStyle::LITTLE);

    int32_t result = NotificationHelper::PublishNotification(request);
    MEDIA_LOGI("Screencapture service UpdateMicrophoneEnabled uid %{public}d, result %{public}d",
        AV_SCREEN_CAPTURE_SESSION_UID, result);
    micCount_.store(micCount_.load() + 1);
}

void ScreenCaptureServer::GetSystemUIFlag()
{
    const std::string systemUITag = "persist.systemui.live2";
    std::string systemUI2;
    int32_t systemUIRes = OHOS::system::GetStringParameter(systemUITag, systemUI2, "false");
    if (systemUIRes != 0) {
        MEDIA_LOGI("Failed to get systemUI flag, Res: %{public}d", systemUIRes);
        isSystemUI2_ = false;
    } else {
        isSystemUI2_ = (systemUI2 == "true");
        MEDIA_LOGI("get systemUI flag, Res: %{public}d, isSystemUI2_: %{public}d", systemUIRes, isSystemUI2_);
    }
}

void ScreenCaptureServer::GetDumpFlag()
{
    const std::string dumpTag = "sys.media.screenCapture.dump.enable";
    std::string dumpEnable;
    int32_t dumpRes = OHOS::system::GetStringParameter(dumpTag, dumpEnable, "false");
    isDump_ = (dumpEnable == "true");
    MEDIA_LOGI("get dump flag, dumpRes: %{public}d, isDump_: %{public}d", dumpRes, isDump_);
}

int32_t ScreenCaptureServer::StartScreenCapture(bool isPrivacyAuthorityEnabled)
{
    MediaTrace trace("ScreenCaptureServer::StartScreenCapture");
    std::lock_guard<std::mutex> lock(mutex_);
    startTime_ = GetCurrentMillisecond();
    statisticalEventInfo_.enableMic = isMicrophoneSwitchTurnOn_;
    GetDumpFlag();
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartScreenCapture start, "
        "isPrivacyAuthorityEnabled:%{public}s, captureState:%{public}d.",
        FAKE_POINTER(this), isPrivacyAuthorityEnabled ? "true" : "false", captureState_);
    CHECK_AND_RETURN_RET_LOG(
        captureState_ == AVScreenCaptureState::CREATED || captureState_ == AVScreenCaptureState::STOPPED,
        MSERR_INVALID_OPERATION, "StartScreenCapture failed, not in CREATED or STOPPED, state:%{public}d",
        captureState_);
    MEDIA_LOGI("StartScreenCapture isPrivacyAuthorityEnabled:%{public}d", isPrivacyAuthorityEnabled);
    isSurfaceMode_ = false;
    return StartScreenCaptureInner(isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureServer::StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(
        captureState_ == AVScreenCaptureState::CREATED || captureState_ == AVScreenCaptureState::STOPPED,
        MSERR_INVALID_OPERATION, "StartScreenCaptureWithSurface failed, not in CREATED or STOPPED, state:%{public}d",
        captureState_);
    MEDIA_LOGI("StartScreenCaptureWithSurface isPrivacyAuthorityEnabled:%{public}d", isPrivacyAuthorityEnabled);
    if (surface == nullptr) {
        MEDIA_LOGE("surface is nullptr");
        return MSERR_INVALID_OPERATION;
    }
    surface_ = surface;
    isSurfaceMode_ = true;
    dataMode_ = AVScreenCaptureDataMode::SUFFACE_MODE;
    return StartScreenCaptureInner(isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureServer::StartStreamVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StartStreamVideoCapture");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamVideoCapture start, state:%{public}d, "
        "dataType:%{public}d, isSurfaceMode:%{public}s.", FAKE_POINTER(this),
        captureConfig_.videoInfo.videoCapInfo.state, captureConfig_.dataType, isSurfaceMode_ ? "true" : "false");
    if (captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        MEDIA_LOGI("StartStreamVideoCapture is ignored");
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET_LOG(
        captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID,
        MSERR_INVALID_VAL, "StartStreamVideoCapture failed, invalid param, dataType:%{public}d",
        captureConfig_.dataType);

    int32_t ret = StartStreamHomeVideoCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
        "StartStreamHomeVideoCapture failed, isSurfaceMode:%{public}d, dataType:%{public}d",
        isSurfaceMode_, captureConfig_.dataType);
    MEDIA_LOGI("StartStreamVideoCapture end.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartStreamHomeVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StartStreamHomeVideoCapture");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamHomeVideoCapture start, "
        "isSurfaceMode: %{public}s.", FAKE_POINTER(this), isSurfaceMode_ ? "true" : "false");
    std::string virtualScreenName = "screen_capture";
    if (isSurfaceMode_) {
        int32_t ret = CreateVirtualScreen(virtualScreenName, surface_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "create virtual screen with input surface failed");
        return MSERR_OK;
    }

    ON_SCOPE_EXIT(0) {
        DestroyVirtualScreen();
        if (consumer_ != nullptr && surfaceCb_ != nullptr) {
            consumer_->UnregisterConsumerListener();
        }
        consumer_ = nullptr;
        if (surfaceCb_ != nullptr) {
            (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->StopBufferThread();
            (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->Release();
            surfaceCb_ = nullptr;
        }
    };
    consumer_ = OHOS::Surface::CreateSurfaceAsConsumer();
    CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_UNKNOWN, "CreateSurfaceAsConsumer failed");
    MEDIA_LOGI("ScreenCaptureServer consumer_ BUFFER_USAGE_CPU_READ BUFFER_USAGE_MEM_MMZ_CACHE S");
    consumer_->SetDefaultUsage(BUFFER_USAGE_CPU_READ | BUFFER_USAGE_MEM_MMZ_CACHE);
    MEDIA_LOGI("ScreenCaptureServer consumer_ BUFFER_USAGE_CPU_READ BUFFER_USAGE_MEM_MMZ_CACHE E");
    auto producer = consumer_->GetProducer();
    CHECK_AND_RETURN_RET_LOG(producer != nullptr, MSERR_UNKNOWN, "GetProducer failed");
    producerSurface_ = OHOS::Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(producerSurface_ != nullptr, MSERR_UNKNOWN, "CreateSurfaceAsProducer failed");
    surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(consumer_, screenCaptureCb_);
    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_UNKNOWN, "MakeSptr surfaceCb_ failed");
    consumer_->RegisterConsumerListener(surfaceCb_);
    MEDIA_LOGD("StartStreamHomeVideoCapture producerSurface_: %{public}" PRIu64, producerSurface_->GetUniqueId());
    int32_t ret = CreateVirtualScreen(virtualScreenName, producerSurface_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "create virtual screen without input surface failed");
    CANCEL_SCOPE_EXIT_GUARD(0);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamHomeVideoCapture OK.", FAKE_POINTER(this));
    MEDIA_LOGI("ScreenCaptureServer:StartStreamHomeVideoCapture surfaceCb_: 0x%{public}06" PRIXPTR,
        FAKE_POINTER(surfaceCb_.GetRefPtr()));
    if (!isSurfaceMode_) {
        ret = (static_cast<ScreenCapBufferConsumerListener*>(surfaceCb_.GetRefPtr()))->StartBufferThread();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "start buffer thread failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetVirtualScreenAutoRotation()
{
    CHECK_AND_RETURN_RET(captureConfig_.dataType == DataType::ORIGINAL_STREAM, MSERR_INVALID_OPERATION);
    MEDIA_LOGI("config strategy canvasFollowRotation %{public}d", captureConfig_.strategy.canvasFollowRotation);
    auto setAutoRotationRet = ScreenManager::GetInstance().SetVirtualScreenAutoRotation(virtualScreenId_,
        captureConfig_.strategy.canvasFollowRotation);
    MEDIA_LOGI("SetVirtualScreenAutoRotation setAutoRotationRet %{public}d", setAutoRotationRet);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CreateVirtualScreen(const std::string &name, sptr<OHOS::Surface> consumer)
{
    MediaTrace trace("ScreenCaptureServer::CreateVirtualScreen");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " CreateVirtualScreen Start", FAKE_POINTER(this));
    isConsumerStart_ = false;
    VirtualScreenOption virScrOption = InitVirtualScreenOption(name, consumer);
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (display != nullptr) {
        MEDIA_LOGI("get displayInfo width:%{public}d,height:%{public}d, density:%{public}f", display->GetWidth(),
                   display->GetHeight(), display->GetVirtualPixelRatio());
        virScrOption.density_ = display->GetVirtualPixelRatio();
    }
    std::shared_lock<std::shared_mutex> read_lock(rw_lock_);
    if (missionIds_.size() > 0 && captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        virScrOption.missionIds_ = missionIds_;
    } else if (captureConfig_.videoInfo.videoCapInfo.taskIDs.size() > 0 &&
        captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        GetMissionIds(missionIds_);
        virScrOption.missionIds_ = missionIds_;
    }
    virtualScreenId_ = ScreenManager::GetInstance().CreateVirtualScreen(virScrOption);
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ >= 0, MSERR_UNKNOWN, "CreateVirtualScreen failed, invalid screenId");
    SetVirtualScreenAutoRotation();
    CHECK_AND_RETURN_RET_LOG(HandleOriginalStreamPrivacy() == MSERR_OK,
        MSERR_UNKNOWN, "SetScreenSkipProtectedWindow failed");
    if (!showCursor_) {
        MEDIA_LOGI("CreateVirtualScreen without cursor");
        int32_t ret = ShowCursorInner();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("CreateVirtualScreen SetVirtualScreenBlackList failed");
        }
    }
    MEDIA_LOGI("CreateVirtualScreen success, screenId: %{public}" PRIu64, virtualScreenId_);
    return PrepareVirtualScreenMirror();
}

int32_t ScreenCaptureServer::HandleOriginalStreamPrivacy()
{
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        if (checkBoxSelected_) {
            MEDIA_LOGI("CreateVirtualScreen checkBoxSelected: %{public}d", checkBoxSelected_);
            std::vector<ScreenId> screenIds;
            screenIds.push_back(virtualScreenId_);
            auto ret = ScreenManager::GetInstance().SetScreenSkipProtectedWindow(screenIds, true);
            CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK || ret == DMError::DM_ERROR_DEVICE_NOT_SUPPORT,
                MSERR_UNKNOWN, "0x%{public}06" PRIXPTR " SetScreenSkipProtectedWindow failed, ret: %{public}d",
                FAKE_POINTER(this), ret);
            MEDIA_LOGI("0x%{public}06" PRIXPTR " SetScreenSkipProtectedWindow success", FAKE_POINTER(this));
            AppPrivacyProtected(virtualScreenId_, true);
        } else {
            AppPrivacyProtected(virtualScreenId_, false);
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::PrepareVirtualScreenMirror()
{
    for (size_t i = 0; i < contentFilter_.windowIDsVec.size(); i++) {
        MEDIA_LOGD("After CreateVirtualScreen windowIDsVec value :%{public}" PRIu64, contentFilter_.windowIDsVec[i]);
    }
    SetScreenScaleMode();
    Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(virtualScreenId_, contentFilter_.windowIDsVec,
        surfaceIdList_, surfaceTypeList_);
    MEDIA_LOGI("PrepareVirtualScreenMirror screenId: %{public}" PRIu64, virtualScreenId_);
    auto screen = ScreenManager::GetInstance().GetScreenById(virtualScreenId_);
    if (screen == nullptr) {
        MEDIA_LOGE("GetScreenById failed");
        DestroyVirtualScreen();
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
            "GetScreenById failed");
        return MSERR_UNKNOWN;
    }
    if (canvasRotation_) {
        SetCanvasRotationInner();
    }
    SkipPrivacyModeInner();
    int32_t ret = MakeVirtualScreenMirror();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("MakeVirtualScreenMirror failed");
        DestroyVirtualScreen();
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
            "MakeVirtualScreenMirror failed");
        return MSERR_UNKNOWN;
    }
    isConsumerStart_ = true;
    return MSERR_OK;
}

uint64_t ScreenCaptureServer::GetDisplayIdOfWindows(uint64_t displayId)
{
    uint64_t defaultDisplayIdValue = displayId;
    std::shared_lock<std::shared_mutex> read_lock(rw_lock_);
    if (missionIds_.size() > 0) {
        std::unordered_map<uint64_t, uint64_t> windowDisplayIdMap;
        auto ret = WindowManager::GetInstance().GetDisplayIdByWindowId(missionIds_, windowDisplayIdMap);
        MEDIA_LOGI("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR
            "GetWindowDisplayIds ret:%{public}d", FAKE_POINTER(this), ret);
        for (const auto& pair : windowDisplayIdMap) {
            MEDIA_LOGD("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR " WindowId:%{public}" PRIu64
                " in DisplayId:%{public}" PRIu64, FAKE_POINTER(this), pair.first, pair.second);
            defaultDisplayIdValue = pair.second;
        }
        MEDIA_LOGI("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR
            " For Specific Window %{public}" PRIu64, FAKE_POINTER(this), defaultDisplayIdValue);
    }
    return defaultDisplayIdValue;
}

#ifdef PC_STANDARD
bool ScreenCaptureServer::CheckCustScrRecPermission()
{
    MEDIA_LOGI("Verify custom screen recording permission");
    CHECK_AND_RETURN_RET_LOG(Security::AccessToken::AccessTokenKit::VerifyAccessToken(
        appInfo_.appTokenId, PERM_CUST_SCR_REC) == Security::AccessToken::PERMISSION_GRANTED,
        false, "Verify custom screen recording failed");
    auto ret = PrivacyKit::AddPermissionUsedRecord(appInfo_.appTokenId, PERM_CUST_SCR_REC, 1, 0);
    TRUE_LOG(ret != 0, MEDIA_LOGE, "Add screen capture record error: %{public}d", ret);
    return true;
}

bool ScreenCaptureServer::IsHopper()
{
    std::string foldScreenFlag = system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
    if (foldScreenFlag.empty()) {
        MEDIA_LOGI("foldscreen type is empty");
        return false;
    }
    MEDIA_LOGI("foldscreen type is %{public}s", foldScreenFlag.c_str());
    return foldScreenFlag[0] == '5';
}

int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForWindowForHopper(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    ScreenId mirrorGroup = defaultDisplay->GetScreenId();
    uint64_t defaultDisplayId = GetDisplayIdOfWindows(defaultDisplay->GetScreenId());
    DMError ret = ScreenManager::GetInstance().MakeMirrorForRecord(defaultDisplayId, mirrorIds, mirrorGroup);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, captureMode:%{public}d, ret:%{public}d", captureConfig_.captureMode, ret);
    MEDIA_LOGI("MakeVirtualScreenMirror window screen success, screenId:%{public}" PRIu64, defaultDisplayId);
    displayScreenId_ = defaultDisplayId;
    return MSERR_OK;
}

bool ScreenCaptureServer::IsPickerPopUp()
{
    if (captureConfig_.strategy.pickerPopUp == AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE) {
        return true;
    }
    if (captureConfig_.strategy.pickerPopUp == AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_DISABLE) {
        return false;
    }
    return !isRegionCapture_ &&
           (captureConfig_.captureMode == CAPTURE_SPECIFIED_SCREEN || CheckCaptureSpecifiedWindowForSelectWindow());
}

void ScreenCaptureServer::SetTimeoutScreenoffDisableLock(bool lockScreen)
{
    MEDIA_LOGI("SetTimeoutScreenoffDisableLock Start lockScreen %{public}d", lockScreen);
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(appInfo_.appTokenId,
        TIMEOUT_SCREENOFF_DISABLE_LOCK);
    if (result != Security::AccessToken::PERMISSION_GRANTED) {
        MEDIA_LOGI("user have not the TIMEOUT_SCREENOFF_DISABLE_LOCK!");
        return;
    }
    auto powerErrors = OHOS::PowerMgr::PowerMgrClient::GetInstance()
                                .LockScreenAfterTimingOutWithAppid(sessionId_, lockScreen);
    if (powerErrors == OHOS::PowerMgr::PowerErrors::ERR_OK) {
        MEDIA_LOGI("SetTimeoutScreenoffDisableLock success");
    } else {
        MEDIA_LOGE("SetTimeoutScreenoffDisableLock error %{public}d", powerErrors);
    }
}
#endif

int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForWindow(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    ScreenId mirrorGroup = defaultDisplay->GetScreenId();
    uint64_t defaultDisplayId = GetDisplayIdOfWindows(defaultDisplay->GetScreenId());
    DMError ret = ScreenManager::GetInstance().MakeMirror(defaultDisplayId, mirrorIds, mirrorGroup);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, captureMode:%{public}d, ret:%{public}d", captureConfig_.captureMode, ret);
    MEDIA_LOGI("MakeVirtualScreenMirror window screen success, screenId:%{public}" PRIu64, defaultDisplayId);
    displayScreenId_ = defaultDisplayId;
    return MSERR_OK;
}

int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForHomeScreen(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    ScreenId mirrorGroup = defaultDisplay->GetScreenId();
    MEDIA_LOGI("MakeVirtualScreenMirror DefaultDisplay, screenId:%{public}" PRIu64, mirrorGroup);
    DMError ret = ScreenManager::GetInstance().MakeMirror(defaultDisplay->GetScreenId(), mirrorIds, mirrorGroup);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, captureMode:%{public}d, ret:%{public}d", captureConfig_.captureMode, ret);
    displayScreenId_ = defaultDisplay->GetScreenId();
    MEDIA_LOGI("MakeVirtualScreenMirror default screen success, screenId:%{public}" PRIu64,
        defaultDisplay->GetScreenId());
    return MSERR_OK;
}

#ifdef PC_STANDARD
int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForHomeScreenForHopper(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    ScreenId mirrorGroup = defaultDisplay->GetScreenId();
    MEDIA_LOGI("MakeVirtualScreenMirror DefaultDisplay, screenId:%{public}" PRIu64, mirrorGroup);
    DMError ret = ScreenManager::GetInstance().MakeMirrorForRecord(defaultDisplay->GetScreenId(), mirrorIds,
        mirrorGroup);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeMirrorForRecord failed, captureMode:%{public}d, ret:%{public}d", captureConfig_.captureMode, ret);
    displayScreenId_ = defaultDisplay->GetScreenId();
    MEDIA_LOGI("MakeVirtualScreenMirror default screen success, screenId:%{public}" PRIu64,
        defaultDisplay->GetScreenId());
    return MSERR_OK;
}
#endif

int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForSpecifiedScreen(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    CHECK_AND_RETURN_RET_LOG(screens.size() > 0, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed to GetAllScreens, ret:%{public}d", ret);
    for (uint32_t i = 0; i < screens.size() ; i++) {
        if (screens[i]->GetId() == captureConfig_.videoInfo.videoCapInfo.displayId) {
            ScreenId mirrorGroup = defaultDisplay->GetScreenId();
            ret = ScreenManager::GetInstance().MakeMirror(screens[i]->GetId(), mirrorIds, mirrorGroup);
            CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
                "MakeVirtualScreenMirror failed to MakeMirror for CAPTURE_SPECIFIED_SCREEN, ret:%{public}d", ret);
            displayScreenId_ = screens[i]->GetId();
            MEDIA_LOGI("MakeVirtualScreenMirror extend screen success, screenId:%{public}" PRIu64,
                captureConfig_.videoInfo.videoCapInfo.displayId);
            return MSERR_OK;
        }
    }
    MEDIA_LOGE("MakeVirtualScreenMirror failed to find screenId:%{public}" PRIu64,
        captureConfig_.videoInfo.videoCapInfo.displayId);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "MakeVirtualScreenMirror failed to find screenId");
    return MSERR_UNKNOWN;
}

#ifdef PC_STANDARD
int32_t ScreenCaptureServer::MakeVirtualScreenMirrorForSpecifiedScreenForHopper(sptr<Rosen::Display> defaultDisplay,
    std::vector<ScreenId> mirrorIds)
{
    std::vector<Rosen::DisplayId> allDisplayIds = Rosen::DisplayManager::GetInstance().GetAllDisplayIds();
    CHECK_AND_RETURN_RET_LOG(allDisplayIds.size() > 0, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed to GetAllDisplayIds, allDisplayIds is empty");
    for (uint32_t i = 0; i < allDisplayIds.size() ; i++) {
        if (allDisplayIds[i] == captureConfig_.videoInfo.videoCapInfo.displayId) {
            ScreenId mirrorGroup = defaultDisplay->GetScreenId();
            DMError ret = ScreenManager::GetInstance().MakeMirrorForRecord(allDisplayIds[i], mirrorIds, mirrorGroup);
            CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
                "MakeVirtualScreenMirror failed to MakeMirrorForRecord for CAPTURE_SPECIFIED_SCREEN, ret:%{public}d",
                ret);
            displayScreenId_ = allDisplayIds[i];
            MEDIA_LOGI("MakeVirtualScreenMirrorForHopper extend screen success, displayId:%{public}" PRIu64,
                captureConfig_.videoInfo.videoCapInfo.displayId);
            return MSERR_OK;
        }
    }
    MEDIA_LOGE("MakeVirtualScreenMirror failed to find displayId:%{public}" PRIu64,
        captureConfig_.videoInfo.videoCapInfo.displayId);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "MakeVirtualScreenMirror failed to find displayId");
    return MSERR_UNKNOWN;
}
#endif

int32_t ScreenCaptureServer::MakeVirtualScreenMirror()
{
    MediaTrace trace("ScreenCaptureServer::MakeVirtualScreenMirror");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " MakeVirtualScreenMirror start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, invalid screenId");
    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(virtualScreenId_);
    sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(defaultDisplay != nullptr, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror GetDefaultDisplaySync failed");
    if (isRegionCapture_) {
        return SetCaptureAreaInner(regionDisplayId_, regionArea_);
    }
#ifdef PC_STANDARD
    if (IsHopper() && captureConfig_.strategy.enableDeviceLevelCapture == false) {
        if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
            return MakeVirtualScreenMirrorForWindowForHopper(defaultDisplay, mirrorIds);
        }
        if (captureConfig_.captureMode != CAPTURE_SPECIFIED_SCREEN) {
            return MakeVirtualScreenMirrorForHomeScreenForHopper(defaultDisplay, mirrorIds);
        }
        return MakeVirtualScreenMirrorForSpecifiedScreenForHopper(defaultDisplay, mirrorIds);
    }
#endif
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        return MakeVirtualScreenMirrorForWindow(defaultDisplay, mirrorIds);
    }
    if (captureConfig_.captureMode != CAPTURE_SPECIFIED_SCREEN) {
        return MakeVirtualScreenMirrorForHomeScreen(defaultDisplay, mirrorIds);
    }
    return MakeVirtualScreenMirrorForSpecifiedScreen(defaultDisplay, mirrorIds);
}

void ScreenCaptureServer::DestroyVirtualScreen()
{
    MediaTrace trace("ScreenCaptureServer::DestroyVirtualScreen");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " DestroyVirtualScreen start.", FAKE_POINTER(this));
    if (virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID) {
        if (isConsumerStart_) {
            std::vector<ScreenId> screenIds;
            screenIds.push_back(virtualScreenId_);
            ScreenManager::GetInstance().StopMirror(screenIds);
        }
        ScreenManager::GetInstance().DestroyVirtualScreen(virtualScreenId_);
        virtualScreenId_ = SCREEN_ID_INVALID;
        isConsumerStart_ = false;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " DestroyVirtualScreen end.", FAKE_POINTER(this));
}

void ScreenCaptureServer::CloseFd()
{
    MediaTrace trace("ScreenCaptureServer::CloseFd");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CloseFd, fd is %{public}d", FAKE_POINTER(this),
        outputFd_);
    if (outputFd_ >= 0) {
        (void)::close(outputFd_);
        outputFd_ = -1;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " CloseFd end.", FAKE_POINTER(this));
}

VirtualScreenOption ScreenCaptureServer::InitVirtualScreenOption(const std::string &name, sptr<OHOS::Surface> consumer)
{
    MediaTrace trace("ScreenCaptureServer::InitVirtualScreenOption");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitVirtualScreenOption start, name:%{public}s.",
        FAKE_POINTER(this), name.c_str());
    VirtualScreenOption virScrOption = {
        .name_ = name,
        .width_ = captureConfig_.videoInfo.videoCapInfo.videoFrameWidth,
        .height_ = captureConfig_.videoInfo.videoCapInfo.videoFrameHeight,
        .density_ = 0,
        .surface_ = consumer,
        .flags_ = captureConfig_.strategy.strategyForPrivacyMaskMode,
        .isForShot_ = true,
        .missionIds_ = {},
        .virtualScreenType_ = VirtualScreenType::SCREEN_RECORDING,
    };
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitVirtualScreenOption end.", FAKE_POINTER(this));
    return virScrOption;
}

int32_t ScreenCaptureServer::GetMissionIds(std::vector<uint64_t> &missionIds)
{
    int32_t size = static_cast<int32_t>(captureConfig_.videoInfo.videoCapInfo.taskIDs.size());
    std::list<int32_t> taskIDListTemp = captureConfig_.videoInfo.videoCapInfo.taskIDs;
    for (int32_t i = 0; i < size; i++) {
        int32_t taskId = taskIDListTemp.front();
        taskIDListTemp.pop_front();
        MEDIA_LOGD("ScreenCaptureServer::GetMissionIds taskId : %{public}s", std::to_string(taskId).c_str());
        uint64_t uintNum = static_cast<uint64_t>(taskId);
        missionIds.push_back(uintNum);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type)
{
    MediaTrace trace("ScreenCaptureServer::AcquireAudioBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireAudioBuffer start, state:%{public}d, "
        "type:%{public}d.", FAKE_POINTER(this), captureState_, type);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "AcquireAudioBuffer failed, capture is not STARTED, state:%{public}d, type:%{public}d", captureState_, type);

    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        IsMicrophoneCaptureRunning()) {
        return micAudioCapture_->AcquireAudioBuffer(audioBuffer);
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        IsInnerCaptureRunning()) {
        return innerAudioCapture_->AcquireAudioBuffer(audioBuffer);
    }
    MEDIA_LOGE("AcquireAudioBuffer failed, source type not support, type:%{public}d", type);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "AcquireAudioBuffer failed, source type not support");
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    MediaTrace trace("ScreenCaptureServer::ReleaseAudioBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ReleaseAudioBuffer start, state:%{public}d, "
        "type:%{public}d.", FAKE_POINTER(this), captureState_, type);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "ReleaseAudioBuffer failed, capture is not STARTED, state:%{public}d, type:%{public}d", captureState_, type);

    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        IsMicrophoneCaptureRunning()) {
        return micAudioCapture_->ReleaseAudioBuffer();
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        IsInnerCaptureRunning()) {
        return innerAudioCapture_->ReleaseAudioBuffer();
    }
    MEDIA_LOGE("ReleaseAudioBuffer failed, source type not support, type:%{public}d", type);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "ReleaseAudioBuffer failed, source type not support");
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::ReleaseInnerAudioBuffer()
{
    CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture_ is nullptr");
    int32_t ret = innerAudioCapture_->ReleaseAudioBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture ReleaseAudioBuffer failed");
    return ret;
}

int32_t ScreenCaptureServer::ReleaseMicAudioBuffer()
{
    CHECK_AND_RETURN_RET_LOG(micAudioCapture_, MSERR_UNKNOWN, "micAudioCapture_ is nullptr");
    int32_t ret = micAudioCapture_->ReleaseAudioBuffer();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "micAudioCapture ReleaseAudioBuffer failed");
    return ret;
}

int32_t ScreenCaptureServer::GetInnerAudioCaptureBufferSize(size_t &size)
{
    if (innerAudioCapture_ == nullptr) {
        MEDIA_LOGE("innerAudioCapture_ is nullptr");
        return MSERR_UNKNOWN;
    }
    int32_t ret = innerAudioCapture_->GetBufferSize(size);
    return ret;
}

int32_t ScreenCaptureServer::GetMicAudioCaptureBufferSize(size_t &size)
{
    if (micAudioCapture_ == nullptr) {
        MEDIA_LOGE("micAudioCapture_ is nullptr");
        return MSERR_UNKNOWN;
    }
    int32_t ret = micAudioCapture_->GetBufferSize(size);
    return ret;
}

int32_t ScreenCaptureServer::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
                                                int64_t &timestamp, OHOS::Rect &damage)
{
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer start, state:%{public}d, "
        "fence:%{public}d, timestamp:%{public}" PRId64, FAKE_POINTER(this), captureState_, fence, timestamp);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "AcquireVideoBuffer failed, capture is not STARTED, state:%{public}d", captureState_);

    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_NO_MEMORY, "AcquireVideoBuffer failed, callback is nullptr");
    (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->
        AcquireVideoBuffer(surfaceBuffer, fence, timestamp, damage);
    if (isDump_ && surfaceBuffer != nullptr) {
        void* addr = surfaceBuffer->GetVirAddr();
        uint32_t bufferSize = surfaceBuffer->GetSize();
        FILE *desFile = fopen(DUMP_PATH.c_str(), "wb+");
        if (desFile && addr != nullptr) {
            (void)fwrite(addr, 1, bufferSize, desFile);
            (void)fclose(desFile);
        } else if (desFile) {
            (void)fclose(desFile);
        }
    }
    if (surfaceBuffer != nullptr) {
        MEDIA_LOGD("getcurrent surfaceBuffer info, size:%{public}u", surfaceBuffer->GetSize());
        return MSERR_OK;
    }
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "AcquireVideoBuffer fault");
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer end.", FAKE_POINTER(this));
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::ReleaseVideoBuffer()
{
    MediaTrace trace("ScreenCaptureServer::ReleaseVideoBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer start, state:%{public}d.",
        FAKE_POINTER(this), captureState_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "ReleaseVideoBuffer failed, capture is not STARTED, state:%{public}d", captureState_);

    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_NO_MEMORY, "ReleaseVideoBuffer failed, callback is nullptr");
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer end.", FAKE_POINTER(this));
    return (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->ReleaseVideoBuffer();
}

int32_t ScreenCaptureServer::ExcludeContent(ScreenCaptureContentFilter &contentFilter)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ != AVScreenCaptureState::STOPPED, MSERR_INVALID_OPERATION,
        "ExcludeContent failed, capture is STOPPED");

    MEDIA_LOGI("ScreenCaptureServer::ExcludeContent start");
    contentFilter_ = contentFilter;
    if (captureState_ == AVScreenCaptureState::STARTED) {
        Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(virtualScreenId_, contentFilter_.windowIDsVec,
            surfaceIdList_, surfaceTypeList_);
    }
    int32_t ret = MSERR_OK;
    if (innerAudioCapture_ != nullptr) {
        ret = innerAudioCapture_->UpdateAudioCapturerConfig(contentFilter_);
    }

    // For the moment, not support:
    // For STREAM, should call AudioCapturer interface to make effect when start
    // For CAPTURE FILE, should call Recorder interface to make effect when start
    if (ret != MSERR_OK) {
        MEDIA_LOGE("ScreenCaptureServer::ExcludeContent UpdateAudioCapturerConfig failed");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNSUPPORT,
            "ExcludeContent failed, UpdateAudioCapturerConfig failed");
    }
    return ret;
}

int32_t ScreenCaptureServer::ExcludePickerWindows(std::vector<int32_t> &windowIDsVec)
{
#ifdef PC_STANDARD
    MEDIA_LOGD("ScreenCaptureServer::ExcludePickerWindows start");
    excludedWindowIDsVec_.clear();
    for (auto id : windowIDsVec) {
        excludedWindowIDsVec_.push_back(id);
    }
    MEDIA_LOGD("ScreenCaptureServer::ExcludePickerWindows end");
    return MSERR_OK;
#else
    (void)windowIDsVec;
    return MSERR_INVALID_OPERATION;
#endif
}

int32_t ScreenCaptureServer::SetPickerMode(PickerMode pickerMode)
{
#ifdef PC_STANDARD
    MEDIA_LOGD("ScreenCaptureServer::SetPickerMode");
    pickerMode_ = pickerMode;
    return MSERR_OK;
#else
    (void)pickerMode;
    return MSERR_INVALID_OPERATION;
#endif
}

int32_t ScreenCaptureServer::SetCaptureArea(uint64_t displayId, OHOS::Rect area)
{
    MediaTrace trace("ScreenCaptureServer::SetCaptureArea");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(CheckDisplayArea(displayId, area), MSERR_INVALID_VAL,
        "Check region area failed, invalid input area.");
    isRegionCapture_ = true;
    regionDisplayId_ = displayId;
    regionArea_ = area;
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGI("ScreenCaptureServer::SetCaptureArea, virtual screen not created, return ok");
        return MSERR_OK;
    }
    return SetCaptureAreaInner(regionDisplayId_, regionArea_);
}

int32_t ScreenCaptureServer::SetCaptureAreaInner(uint64_t displayId, OHOS::Rect area)
{
    MediaTrace trace("ScreenCaptureServer::SetCaptureAreaInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCaptureAreaInner start, state:%{public}d.",
        FAKE_POINTER(this), captureState_);
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
        "SetCaptureAreaInner failed virtual screen not init");
    ScreenId regionScreenId;
    DMRect regionAreaIn;
    DMRect regionAreaOut;
    regionAreaIn.posX_ = area.x;
    regionAreaIn.posY_ = area.y;
    regionAreaIn.width_ = static_cast<uint32_t>(area.w);
    regionAreaIn.height_ = static_cast<uint32_t>(area.h);
    auto ret = Rosen::DisplayManager::GetInstance().GetScreenAreaOfDisplayArea(
        displayId, regionAreaIn, regionScreenId, regionAreaOut);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_INVALID_OPERATION,
        "GetScreenAreaOfDisplayArea error: %{public}d", ret);
    MEDIA_LOGI("SetCaptureAreaInner after, displayId: %{public}" PRIu64, regionScreenId);
    MEDIA_LOGI("SetCaptureAreaInner after, x:%{public}d, y:%{public}d, w:%{public}d, h:%{public}d",
        regionAreaOut.posX_, regionAreaOut.posY_, regionAreaOut.width_, regionAreaOut.height_);

    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(virtualScreenId_);
    ret = ScreenManager::GetInstance().MakeMirror(regionScreenId, mirrorIds, regionAreaOut, regionScreenId);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeMirror with region error: %{public}d", ret);
    displayScreenId_ = displayId;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCaptureAreaInner end, state:%{public}d.",
        FAKE_POINTER(this), captureState_);
    return MSERR_OK;
}

bool ScreenCaptureServer::CheckDisplayArea(uint64_t displayId, OHOS::Rect area)
{
    MEDIA_LOGI("CheckDisplayArea input displayId: %{public}" PRIu64, displayId);
    sptr<Display> targetDisplay = Rosen::DisplayManager::GetInstance().GetDisplayById(displayId);
    CHECK_AND_RETURN_RET_LOG(targetDisplay != nullptr, false,
        "CheckDisplayArea failed to get target display, no displayId: %{public}" PRIu64, displayId);
    auto screenWidth = targetDisplay->GetWidth();
    auto screenHeight = targetDisplay->GetHeight();
    MEDIA_LOGI("CheckDisplayArea display with width: %{public}d, height:%{public}d", screenWidth, screenHeight);
    if (static_cast<int64_t>(area.x) + area.w > screenWidth || static_cast<int64_t>(area.y) + area.h > screenHeight) {
        MEDIA_LOGE("CheckDisplayArea input area out of range");
        return false;
    }
    MEDIA_LOGI("CheckDisplayArea success");
    return true;
}

int32_t ScreenCaptureServer::SetMicrophoneEnabled(bool isMicrophone)
{
    MediaTrace trace("ScreenCaptureServer::SetMicrophoneEnabled");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetMicrophoneEnabled isMicrophoneSwitchTurnOn_:"
        "%{public}d, new isMicrophone:%{public}d", FAKE_POINTER(this), isMicrophoneSwitchTurnOn_, isMicrophone);
    int32_t ret = MSERR_UNKNOWN;
    if (isMicrophone) {
        statisticalEventInfo_.enableMic = true;
    }
    if (captureState_ != AVScreenCaptureState::STARTED) {
        isMicrophoneSwitchTurnOn_ = isMicrophone;
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET_LOG(captureConfig_.audioInfo.micCapInfo.state ==
        AVScreenCaptureParamValidationState::VALIDATION_VALID, MSERR_OK, "No Microphone Config");
    if (isMicrophone) {
        ret = SetMicrophoneOn();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOn failed");
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNMUTED_BY_USER);
    } else {
        ret = SetMicrophoneOff();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOff failed");
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_MUTED_BY_USER);
    }
    isMicrophoneSwitchTurnOn_ = isMicrophone;
    // For CAPTURE FILE, should call Recorder interface to make effect
    MEDIA_LOGI("SetMicrophoneEnabled OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMicrophoneOn()
{
#ifdef SUPPORT_CALL
    if (InCallObserver::GetInstance().IsInCall(true) && !IsTelInCallSkipList()) {
        MEDIA_LOGE("Try SetMicrophoneOn But In Call");
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
        return MSERR_UNKNOWN;
    }
#endif
    int32_t ret = MSERR_UNKNOWN;
    if (!micAudioCapture_) {
        if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
            ret = StartStreamMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOn StartStreamMicAudioCapture failed");
        } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
            ret = StartFileMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileMicAudioCapture failed");
        }
    } else if (micAudioCapture_->IsStop()) {
        ret = micAudioCapture_->Start(appInfo_); // Resume
        if (ret != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture Resume failed");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return ret;
        }
    } else if (!micAudioCapture_->IsRecording()) {
        MEDIA_LOGE("AudioCapturerState invalid");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMicrophoneOff()
{
    int32_t ret = MSERR_UNKNOWN;
    if (recorderFileAudioType_ == AVScreenCaptureMixMode::MIX_MODE && innerAudioCapture_
        && !IsInnerCaptureRunning()) {
        ret = innerAudioCapture_->Start(appInfo_); // Resume
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Start failed");
    }
    if (IsMicrophoneCaptureRunning()) {
        usleep(AUDIO_CHANGE_TIME);
        MEDIA_LOGI("Microphone Pause");
        ret = StopMicAudioCapture(); // Pause
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "micAudioCapture Pause failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::OnSpeakerAliveStatusChanged(bool speakerAliveStatus)
{
    int32_t ret = MSERR_UNKNOWN;
    std::lock_guard<std::mutex> lock(innerAudioMutex_);
    CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture_ is nullptr");
    if (!speakerAliveStatus && recorderFileAudioType_ == AVScreenCaptureMixMode::MIX_MODE &&
        innerAudioCapture_->IsStop()) { // back to headset
        ret = innerAudioCapture_->Start(appInfo_); // Resume
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Resume failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ReStartMicForVoIPStatusSwitch()
{
    int32_t ret = MSERR_OK;
    usleep(AUDIO_CHANGE_TIME);
    StopMicAudioCapture();
    if (isMicrophoneSwitchTurnOn_) {
#ifdef SUPPORT_CALL
        if (InCallObserver::GetInstance().IsInCall(true) && !IsTelInCallSkipList()) {
            MEDIA_LOGE("Try ReStartMicForVoIPStatusSwitch But In Call");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return MSERR_UNKNOWN;
        }
#endif
        ret = StartMicAudioCapture();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("OnVoIPStatusChanged StartMicAudioCapture failed, ret: %{public}d", ret);
        }
    }
    return ret;
}

int32_t ScreenCaptureServer::OnVoIPStatusChanged(bool isInVoIPCall)
{
    MEDIA_LOGI("OnVoIPStatusChanged, isInVoIPCall:%{public}d", isInVoIPCall);
    if (isInVoIPCall) {
        CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture is nullptr");
        if (recorderFileAudioType_ == AVScreenCaptureMixMode::MIX_MODE && innerAudioCapture_->IsStop()) {
            int32_t ret = innerAudioCapture_->Start(appInfo_); // Resume
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "OnVoIPStatusChanged innerAudioCapture Resume failed");
        }
    }
    return ReStartMicForVoIPStatusSwitch();
}

#ifdef SUPPORT_CALL
int32_t ScreenCaptureServer::TelCallStateUpdated(bool isInTelCall)
{
    if (!captureConfig_.strategy.keepCaptureDuringCall && isInTelCall) {
        StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
        Release();
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET(captureState_ == AVScreenCaptureState::STARTED, MSERR_OK);
    if (isInTelCall_.load() == isInTelCall) {
        return MSERR_OK;
    }
    isInTelCall_.store(isInTelCall);
    if (isInTelCall) {
        return OnTelCallStart();
    }
    return OnTelCallStop();
}

int32_t ScreenCaptureServer::TelCallAudioStateUpdated(bool isInTelCallAudio)
{
    CHECK_AND_RETURN_RET(captureState_ == AVScreenCaptureState::STARTED, MSERR_OK);
    if (IsTelInCallSkipList() || isInTelCallAudio_.load() == isInTelCallAudio) {
        return MSERR_OK;
    }
    isInTelCallAudio_.store(isInTelCallAudio);
    if (isInTelCallAudio) {
        return OnTelCallStart();
    }
    return OnTelCallStop();
}

int32_t ScreenCaptureServer::OnTelCallStart()
{
    std::lock_guard<std::mutex> lock(inCallMutex_);
    MEDIA_LOGI("OnTelCallStart InTelCall:%{public}d, Audio:%{public}d", isInTelCall_.load(), isInTelCallAudio_.load());
    int32_t ret = MSERR_OK;
    if (!isInTelCall_.load() && !isInTelCallAudio_.load()) {
        return ret;
    }
    if (recorderFileAudioType_ == AVScreenCaptureMixMode::MIX_MODE && innerAudioCapture_ && !IsInnerCaptureRunning()) {
        ret = innerAudioCapture_->Start(appInfo_); // Resume
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "tel innerAudioCapture Start failed");
    }
    if (micAudioCapture_) {
        micAudioCapture_->SetIsInTelCall(true);
        if (IsMicrophoneCaptureRunning()) {
            usleep(AUDIO_CHANGE_TIME);
            ret = StopMicAudioCapture(); // Pause
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "micAudioCapture Pause failed");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::OnTelCallStop()
{
    MEDIA_LOGI("OnTelCallStop InTelCall:%{public}d, Audio:%{public}d", isInTelCall_.load(), isInTelCallAudio_.load());
    int32_t ret = MSERR_OK;
    if (isInTelCall_.load() || isInTelCallAudio_.load()) {
        return ret;
    }
    if (micAudioCapture_) {
        micAudioCapture_->SetIsInTelCall(false);
        if (isMicrophoneSwitchTurnOn_ && micAudioCapture_->IsStop()) {
            ret = micAudioCapture_->Start(appInfo_); // Resume
            if (ret != MSERR_OK) {
                MEDIA_LOGE("micAudioCapture Resume failed");
                NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
                return ret;
            }
        }
    }
    if (!micAudioCapture_ && isMicrophoneSwitchTurnOn_) {
        if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
            ret = StartStreamMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOn StartStreamMicAudioCapture failed");
        } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
            ret = StartFileMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileMicAudioCapture failed");
        }
    }
    return MSERR_OK;
}
#endif

int32_t ScreenCaptureServer::SetCanvasRotation(bool canvasRotation)
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotation");
    std::lock_guard<std::mutex> lock(mutex_);
    canvasRotation_ = canvasRotation;
    MEDIA_LOGI("ScreenCaptureServer::SetCanvasRotation, canvasRotation:%{public}d", canvasRotation);
    CHECK_AND_RETURN_RET(captureState_ == AVScreenCaptureState::STARTED, MSERR_OK);  // Before Start
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotation end.", FAKE_POINTER(this));
    return SetCanvasRotationInner();
}

int32_t ScreenCaptureServer::SetCanvasRotationInner()
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotationInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotationInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SetCanvasRotation failed virtual screen not init");
    auto ret = ScreenManager::GetInstance().SetVirtualMirrorScreenCanvasRotation(virtualScreenId_, canvasRotation_);
    if (CheckAppVersionForUnsupport(ret)) {
        MEDIA_LOGE("SetVirtualMirrorScreenCanvasRotation failed, ret: %{public}d", ret);
        return MSERR_UNSUPPORT;
    }
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_INVALID_OPERATION,
                             "SetVirtualMirrorScreenCanvasRotation failed, ret: %{public}d", ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotationInner OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ShowCursor(bool showCursor)
{
    MediaTrace trace("ScreenCaptureServer::ShowCursor");
    std::lock_guard<std::mutex> lock(mutex_);
    if (showCursor == showCursor_) {
        return MSERR_OK;
    }
    showCursor_ = showCursor;
    MEDIA_LOGI("ScreenCaptureServer::ShowCursor, showCursor:%{public}d", showCursor_);
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGI("ScreenCaptureServer::ShowCursor, virtual screen not created, return ok.");
        return MSERR_OK;
    }
    return ShowCursorInner();
}

int32_t ScreenCaptureServer::ShowCursorInner()
{
    MediaTrace trace("ScreenCaptureServer::ShowCursorInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ShowCursorInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
        "ShowCursorInner failed, virtual screen not init");
    surfaceIdList_ = {};
    if (!showCursor_) {
        MEDIA_LOGI("ScreenCaptureServer 0x%{public}06" PRIXPTR " ShowCursorInner not show cursor", FAKE_POINTER(this));
        surfaceTypeList_ = {};
        Rosen::RSSurfaceNodeType surfaceNodeType = OHOS::Rosen::RSSurfaceNodeType::CURSOR_NODE;
        surfaceTypeList_.push_back(static_cast<uint8_t>(surfaceNodeType));
    } else {
        MEDIA_LOGI("ScreenCaptureServer 0x%{public}06" PRIXPTR " ShowCursorInner, show cursor", FAKE_POINTER(this));
        surfaceTypeList_ = {};
    }
    Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(virtualScreenId_, contentFilter_.windowIDsVec,
        surfaceIdList_, surfaceTypeList_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ShowCursorInner OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ResizeCanvas(int32_t width, int32_t height)
{
    MediaTrace trace("ScreenCaptureServer::ResizeCanvas");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::ResizeCanvas start, Width:%{public}d, Height:%{public}d", width, height);
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGE("ResizeCanvas captureState_ invalid, captureState_:%{public}d", captureState_);
        return MSERR_INVALID_OPERATION;
    }
    if ((width <= 0) || (width > VIDEO_FRAME_WIDTH_MAX)) {
        MEDIA_LOGE("ResizeCanvas Width is invalid, Width:%{public}d, Height:%{public}d", width, height);
        return MSERR_INVALID_VAL;
    }
    if ((height <= 0) || (height > VIDEO_FRAME_HEIGHT_MAX)) {
        MEDIA_LOGE("ResizeCanvas Height is invalid, Width:%{public}d, Height:%{public}d", width, height);
        return MSERR_INVALID_VAL;
    }
    if (captureConfig_.dataType != DataType::ORIGINAL_STREAM) {
        MEDIA_LOGE("ResizeCanvas dataType invalid, dataType:%{public}d", captureConfig_.dataType);
        return MSERR_INVALID_OPERATION;
    }

    auto resizeRet = ScreenManager::GetInstance().ResizeVirtualScreen(virtualScreenId_, width, height);
    MEDIA_LOGI("ScreenCaptureServer::ResizeCanvas, ResizeVirtualScreen end, ret: %{public}d ", resizeRet);
    if (CheckAppVersionForUnsupport(resizeRet)) {
        MEDIA_LOGE("ResizeCanvas failed, resizeRet: %{public}d", resizeRet);
        return MSERR_UNSUPPORT;
    }
    CHECK_AND_RETURN_RET_LOG(resizeRet == DMError::DM_OK, MSERR_INVALID_OPERATION, "ResizeVirtualScreen failed");

    return MSERR_OK;
}

int32_t ScreenCaptureServer::UpdateSurface(sptr<Surface> surface)
{
    if (!isSurfaceMode_) {
        return MSERR_INVALID_OPERATION;
    }
    MediaTrace trace("ScreenCaptureServer::UpdateSurface");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::UpdateSurface start");
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGE("UpdateSurface captureState_ invalid, captureState_:%{public}d", captureState_);
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_OPERATION, "UpdateSurface failed, invalid param");

    auto res = ScreenManager::GetInstance().SetVirtualScreenSurface(virtualScreenId_, surface);
    MEDIA_LOGI("UpdateSurface, ret: %{public}d ", res);
    CHECK_AND_RETURN_RET_LOG(res == DMError::DM_OK, MSERR_UNSUPPORT, "UpdateSurface failed");
    surface_ = surface;

    return MSERR_OK;
}

int32_t ScreenCaptureServer::SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec)
{
    MediaTrace trace("ScreenCaptureServer::SkipPrivacyMode");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SkipPrivacyMode, windowIDsVec size:%{public}d",
        static_cast<int32_t>(windowIDsVec.size()));
    for (size_t i = 0; i < windowIDsVec.size(); i++) {
        MEDIA_LOGD("SkipPrivacyMode windowIDsVec value :%{public}" PRIu64, windowIDsVec[i]);
    }
    skipPrivacyWindowIDsVec_.assign(windowIDsVec.begin(), windowIDsVec.end());
    CHECK_AND_RETURN_RET(captureState_ == AVScreenCaptureState::STARTED, MSERR_OK); // Before Start
    return SkipPrivacyModeInner();
}

int32_t ScreenCaptureServer::SkipPrivacyModeInner()
{
    MediaTrace trace("ScreenCaptureServer::SkipPrivacyModeInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SkipPrivacyModeInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SkipPrivacyMode failed virtual screen not init");
    auto ret = Rosen::DisplayManager::GetInstance().SetVirtualScreenSecurityExemption(virtualScreenId_,
        appInfo_.appPid, skipPrivacyWindowIDsVec_);
    if (CheckAppVersionForUnsupport(ret)) {
        MEDIA_LOGE("SetVirtualScreenSecurityExemption failed, ret: %{public}d", ret);
        return MSERR_UNSUPPORT;
    }
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_INVALID_OPERATION,
        "SkipPrivacyModeInner failed, ret: %{public}d", ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SkipPrivacyModeInner OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMaxVideoFrameRate(int32_t frameRate)
{
    MediaTrace trace("ScreenCaptureServer::SetMaxVideoFrameRate");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SetMaxVideoFrameRate start, frameRate:%{public}d", frameRate);
    if (captureState_ != AVScreenCaptureState::STARTED) {
        MEDIA_LOGE("SetMaxVideoFrameRate captureState_ invalid, captureState_:%{public}d", captureState_);
        return MSERR_INVALID_OPERATION;
    }
    if (frameRate <= 0) {
        MEDIA_LOGE("SetMaxVideoFrameRate frameRate is invalid, frameRate:%{public}d", frameRate);
        return MSERR_INVALID_VAL;
    }

    uint32_t actualRefreshRate = 0;
    auto res = ScreenManager::GetInstance().SetVirtualScreenMaxRefreshRate(virtualScreenId_,
        static_cast<uint32_t>(frameRate), actualRefreshRate);
    if (CheckAppVersionForUnsupport(res)) {
        MEDIA_LOGE("SetVirtualScreenMaxRefreshRate failed, res: %{public}d", res);
        return MSERR_UNSUPPORT;
    }
    CHECK_AND_RETURN_RET_LOG(res == DMError::DM_OK, MSERR_INVALID_OPERATION, "SetMaxVideoFrameRate failed");

    MEDIA_LOGI("ScreenCaptureServer::SetMaxVideoFrameRate end, frameRate:%{public}d, actualRefreshRate:%{public}u",
        frameRate, actualRefreshRate);
    return MSERR_OK;
}

ScreenScaleMode ScreenCaptureServer::GetScreenScaleMode(const AVScreenCaptureFillMode &fillMode)
{
    MEDIA_LOGI("ScreenCaptureServer::GetScreenScaleMode in, fillMode: %{public}d", fillMode);
    static const std::map<AVScreenCaptureFillMode, ScreenScaleMode> modeMap = {
        {PRESERVE_ASPECT_RATIO, ScreenScaleMode::UNISCALE_MODE},
        {SCALE_TO_FILL, ScreenScaleMode::FILL_MODE}
    };
    ScreenScaleMode scaleMode = ScreenScaleMode::UNISCALE_MODE;
    auto iter = modeMap.find(fillMode);
    if (iter != modeMap.end()) {
        scaleMode = iter->second;
    }
    MEDIA_LOGI("ScreenCaptureServer::GetScreenScaleMode succeed, scaleMode: %{public}d", scaleMode);
    return scaleMode;
}

int32_t ScreenCaptureServer::SetScreenScaleMode()
{
    MediaTrace trace("ScreenCaptureServer::SetScreenScaleMode");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenScaleMode start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SetScreenScaleMode failed virtual screen not init");
    auto ret = ScreenManager::GetInstance().SetVirtualMirrorScreenScaleMode(
        virtualScreenId_, GetScreenScaleMode(captureConfig_.strategy.fillMode));
    if (ret != DMError::DM_OK) {
        MEDIA_LOGW("SetScreenScaleMode failed, ret: %{public}d", ret);
        return static_cast<int32_t>(ret);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenScaleMode OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopAudioCapture start.", FAKE_POINTER(this));
    StopMicAudioCapture();
    StopInnerAudioCapture();
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopAudioCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartMicAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartMicAudioCapture start, dataType:%{public}d, "
        "micCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.micCapInfo.state);
#ifdef SUPPORT_CALL
    if (InCallObserver::GetInstance().IsInCall(true) && !IsTelInCallSkipList()) {
        MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " skip creating micAudioCapture", FAKE_POINTER(this));
        NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
        return MSERR_OK;
    }
#endif
    CHECK_AND_RETURN_RET_NOLOG(micAudioCapture_ != nullptr, MSERR_OK);
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartMicAudioCapture");
        if (audioSource_) {
            micAudioCapture_->SetIsInVoIPCall(audioSource_->GetIsInVoIPCall());
        }
        int32_t ret = micAudioCapture_->Start(appInfo_);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StartMicAudioCapture failed");
            NotifyStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return ret;
        }
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartMicAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopInnerAudioCapture()
{
    int32_t ret = MSERR_OK;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopInnerAudioCapture start.", FAKE_POINTER(this));
    if (innerAudioCapture_ != nullptr) {
        MediaTrace trace("ScreenCaptureServer::StopInnerAudioCapture");
        ret = innerAudioCapture_->Stop();
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopInnerAudioCapture end.", FAKE_POINTER(this));
    return ret;
}

int32_t ScreenCaptureServer::StopMicAudioCapture()
{
    int32_t ret = MSERR_OK;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopMicAudioCapture start.", FAKE_POINTER(this));
    if (micAudioCapture_ != nullptr) {
        MediaTrace trace("ScreenCaptureServer::StopAudioCaptureMic");
        ret = micAudioCapture_->Stop();
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopMicAudioCapture end.", FAKE_POINTER(this));
    return ret;
}

int32_t ScreenCaptureServer::StopVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StopVideoCapture");
    MEDIA_LOGI("StopVideoCapture");
    if ((virtualScreenId_ < 0) || ((consumer_ == nullptr) && !isSurfaceMode_) || !isConsumerStart_) {
        MEDIA_LOGI("StopVideoCapture IGNORED, video capture not start");
        if (surfaceCb_ != nullptr) {
            (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->StopBufferThread();
            (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->Release();
            surfaceCb_ = nullptr;
        }
        return MSERR_OK;
    }

    DestroyVirtualScreen();
    if (consumer_ != nullptr) {
        consumer_->UnregisterConsumerListener();
        consumer_ = nullptr;
    }

    if (surfaceCb_ != nullptr) {
        (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->StopBufferThread();
        (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->Release();
        surfaceCb_ = nullptr;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopVideoCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopScreenCaptureRecorder()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCaptureRecorder S", FAKE_POINTER(this));
    MediaTrace trace("ScreenCaptureServer::StopScreenCaptureRecorder");
    int32_t ret = MSERR_OK;
    if (recorder_ != nullptr) {
        stopAcquireAudioBufferFromAudio_.store(true);
        if (recorderFileAudioType_ == AVScreenCaptureMixMode::MIX_MODE &&
            audioSource_ && audioSource_->IsInWaitMicSyncState() &&
            IsInnerCaptureRunning()) {
            int64_t currentAudioTime;
            innerAudioCapture_->GetCurrentAudioTime(currentAudioTime);
            MEDIA_LOGI("0x%{public}06" PRIXPTR " UseUpAllLeftBuffer currentAudioTime: %{public}" PRId64,
                FAKE_POINTER(this), currentAudioTime);
            innerAudioCapture_->UseUpAllLeftBufferUntil(currentAudioTime);
        }
        ret = recorder_->Stop(false);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StopScreenCaptureRecorder recorder stop failed, ret:%{public}d", ret);
        }
        DestroyVirtualScreen();
        recorder_->Release();
        recorder_ = nullptr;
        StopAudioCapture();
    }
    showCursor_ = true;
    surfaceIdList_ = {};
    surfaceTypeList_ = {};
    captureCallback_ = nullptr;
    isConsumerStart_ = false;
    return ret;
}

int32_t ScreenCaptureServer::StopScreenCaptureByEvent(AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCaptureByEvent S", FAKE_POINTER(this));
    MediaTrace trace("ScreenCaptureServer::StopScreenCaptureByEvent");
    if (captureState_ == AVScreenCaptureState::STOPPED) {
        MEDIA_LOGI("StopScreenCaptureByEvent repeat, capture is STOPPED.");
        return MSERR_OK;
    }
    return StopScreenCaptureInner(stateCode);
}

void ScreenCaptureServer::SetSystemScreenRecorderStatus(bool status)
{
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) != 0) {
        return;
    }
    if (status) {
        (ScreenCaptureServer::systemScreenRecorderPid_).store(appInfo_.appPid);
        ScreenCaptureMonitorServer::GetInstance()->SetSystemScreenRecorderStatus(true);
    } else {
        ScreenCaptureMonitorServer::GetInstance()->SetSystemScreenRecorderStatus(false);
    }
}

int32_t ScreenCaptureServer::StopScreenCaptureInner(AVScreenCaptureStateCode stateCode)
{
    std::unique_lock<std::mutex> lock(innerMutex_);
    MediaTrace trace("ScreenCaptureServer::StopScreenCaptureInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopScreenCaptureInner start, stateCode:%{public}d.",
        FAKE_POINTER(this), stateCode);
    if (screenCaptureCb_ != nullptr) {
        (static_cast<ScreenCaptureListenerCallback *>(screenCaptureCb_.get()))->Stop();
    }
    if (audioSource_ && audioSource_->GetAppPid() > 0) { // DataType::CAPTURE_FILE
        audioSource_->UnregisterAudioRendererEventListener(audioSource_->GetAppPid());
    }
    DisplayManager::GetInstance().UnregisterPrivateWindowListener(displayListener_);
    if (captureState_ == AVScreenCaptureState::CREATED || captureState_ == AVScreenCaptureState::POPUP_WINDOW ||
        captureState_ == AVScreenCaptureState::STARTING) {
        StopNotStartedScreenCapture(stateCode);
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET(captureState_ != AVScreenCaptureState::STOPPED, MSERR_OK);
    if (isPresentPickerPopWindow_) {
        DestroyPopWindow();
        isPresentPickerPopWindow_ = false;
    }
    int32_t ret = MSERR_OK;
    DestroyPrivacySheet();
    if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        ret = StopScreenCaptureRecorder();
    } else if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        int32_t retAudio = StopAudioCapture();
        int32_t retVideo = StopVideoCapture();
        ret = (retAudio == MSERR_OK && retVideo == MSERR_OK) ? MSERR_OK : MSERR_STOP_FAILED;
    } else {
        MEDIA_LOGW("StopScreenCaptureInner unsupport and ignore");
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, ret, "state:%{public}d", captureState_);
    SetErrorInfo(MSERR_OK, "normal stopped", StopReason::NORMAL_STOPPED, IsUserPrivacyAuthorityNeeded());
    PostStopScreenCapture(stateCode);
#ifdef SUPPORT_CALL
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(screenCaptureObserverCb_);
#endif
    AccountObserver::GetInstance().UnregisterAccountObserverCallBack(screenCaptureObserverCb_);
    if (screenCaptureObserverCb_) {
        lock.unlock();
        screenCaptureObserverCb_->Release();
        lock.lock();
    }
    StopScreenCaptureInnerUnBind();
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopScreenCaptureInner end.", FAKE_POINTER(this));
    return ret;
}

void ScreenCaptureServer::StopScreenCaptureInnerUnBind()
{
    ScreenManager::GetInstance().UnregisterScreenListener(screenConnectListener_);
    UnRegisterWindowLifecycleListener();
    UnRegisterWindowInfoChangedListener();
    UnRegisterLanguageSwitchListener();
    PublishScreenCaptureEvent("stop");
}

void ScreenCaptureServer::StopNotStartedScreenCapture(AVScreenCaptureStateCode stateCode)
{
    DestroyPopWindow();
    captureState_ = AVScreenCaptureState::STOPPED;
    SetSystemScreenRecorderStatus(false);
    ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureFinished(appInfo_.appPid);
    if (screenCaptureCb_ != nullptr && stateCode != AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID) {
        screenCaptureCb_->OnStateChange(stateCode);
    }
    isSurfaceMode_ = false;
    surface_ = nullptr;
    SetErrorInfo(MSERR_OK, "normal stopped", StopReason::NORMAL_STOPPED, IsUserPrivacyAuthorityNeeded());
}

bool ScreenCaptureServer::DestroyPrivacySheet()
{
    // start ability, tell ability to destroy pop window
    MEDIA_LOGI("DestroyPrivacySheet start.");
    AAFwk::Want want;

    std::string bundleName = GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"];
    if (bundleName.empty()) {
        MEDIA_LOGE("Failed to get screenrecorder bundlename.");
        return false;
    }
    AppExecFwk::ElementName element("", bundleName, "PrivacyControlAbility");

    want.SetElement(element);
    want.SetParam("appLabel", callingLabel_);
    want.SetParam("sessionId", sessionId_);
    want.SetParam("terminateSelf", true);
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
    MEDIA_LOGI("DestroyPrivacySheet StartAbility end %{public}d", ret);
    if (ret != ERR_OK) {
        MEDIA_LOGE("Failed to start ability to destroy privacy sheet, error code : %{public}d", ret);
    }

    return ret == ERR_OK;
}

bool ScreenCaptureServer::DestroyPopWindow()
{
    if (captureState_ != AVScreenCaptureState::POPUP_WINDOW && !isPresentPickerPopWindow_) {
        MEDIA_LOGI("window not pop up, no need to destroy.");
        return true;
    }
#ifdef PC_STANDARD
    if (IsPickerPopUp()) {
        MEDIA_LOGI("DestroyPopWindow end, type: picker, deviceType: PC.");
        ErrCode ret = ERR_INVALID_VALUE;
        AAFwk::Want want;
        AppExecFwk::ElementName element("",
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"],
            SELECT_ABILITY_NAME); // DeviceID
        want.SetElement(element);
        want.SetParam("appLabel", callingLabel_);
        want.SetParam("sessionId", sessionId_);
        want.SetParam("terminateSelf", true); // inform picker to terminateSelf
        SendConfigToUIParams(want);
        ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        MEDIA_LOGI("Destroy picker end %{public}d, DeviceType: PC", ret);
        return ret == ERR_OK;
    } else {
        if (connection_ != nullptr) {
            MEDIA_LOGI("DestroyPopWindow close dialog, deviceType: PC.");
            return connection_->CloseDialog();
        }
    }
#else
    if (connection_ != nullptr) {
        MEDIA_LOGI("DestroyPopWindow close dialog, deviceType: Phone.");
        return connection_->CloseDialog();
    }
#endif
    return true;
}

bool ScreenCaptureServer::IsLastStartedPidInstance(int32_t pid)
{
    MEDIA_LOGI("ScreenCaptureServer::IsLastStartedPidInstance START.");
    if (CountStartedScreenCaptureServerNumByPid(pid) != 1) {
        MEDIA_LOGD("pid: %{public}d exists more than one instance.", pid);
        return false;
    }
    return true;
}

bool ScreenCaptureServer::LastPidUpdatePrivacyUsingPermissionState(int32_t pid)
{
    if (IsLastStartedPidInstance(pid)) {
        return UpdatePrivacyUsingPermissionState(STOP_VIDEO);
    }
    return true;
}

void ScreenCaptureServer::PostStopScreenCapture(AVScreenCaptureStateCode stateCode)
{
    MediaTrace trace("ScreenCaptureServer::PostStopScreenCapture");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStopScreenCapture start, stateCode:%{public}d.",
        FAKE_POINTER(this), stateCode);
#ifdef PC_STANDARD
    SetTimeoutScreenoffDisableLock(true);
#endif
    SetSystemScreenRecorderStatus(false);
    UpdateHighlightOutline(false);
    ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureFinished(appInfo_.appPid);
    if (screenCaptureCb_ != nullptr && stateCode != AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID) {
        screenCaptureCb_->OnStateChange(stateCode);
    }
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    if (isPrivacyAuthorityEnabled_ &&
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) != 0 && !isScreenCaptureAuthority_) {
        // Remove real time notification
        int32_t ret = NotificationHelper::CancelNotification(notificationId_);
        MEDIA_LOGI("StopScreenCaptureInner CancelNotification id:%{public}d, ret:%{public}d ", notificationId_, ret);
        micCount_.store(0);
    }
#endif
    isPrivacyAuthorityEnabled_ = false;
    isRegionCapture_ = false;
    if (!LastPidUpdatePrivacyUsingPermissionState(appInfo_.appPid)) {
        MEDIA_LOGE("UpdatePrivacyUsingPermissionState STOP failed, dataType:%{public}d", captureConfig_.dataType);
    }
    std::unordered_map<std::string, std::string> payload;
    int64_t value = ResourceSchedule::ResType::ScreenCaptureStatus::STOP_SCREEN_CAPTURE;
    ResSchedReportData(value, payload);
    RemoveStartedSessionIdList(this->sessionId_);
    MEDIA_LOGI("PostStopScreenCapture sessionId: %{public}d is removed from list, list_size is %{public}d.",
        this->sessionId_, static_cast<uint32_t>(ScreenCaptureServer::startedSessionIDList_.size()));
    captureState_ = AVScreenCaptureState::STOPPED;
}

int32_t ScreenCaptureServer::StopScreenCapture()
{
    MediaTrace trace("ScreenCaptureServer::StopScreenCapture");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCapture S", FAKE_POINTER(this));

    if (captureState_ == AVScreenCaptureState::STOPPED) {
        MEDIA_LOGI("StopScreenCapture repeat, capture is STOPPED.");
        return MSERR_OK;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
    if (statisticalEventInfo_.startLatency == -1) {
        statisticalEventInfo_.captureDuration = -1; // latency -1 means invalid
    } else {
        int64_t endTime = GetCurrentMillisecond();
        statisticalEventInfo_.captureDuration = static_cast<int32_t>(endTime - startTime_ -
            statisticalEventInfo_.startLatency);
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCapture E", FAKE_POINTER(this));
    isScreenCaptureAuthority_ = false;
    isPresentPicker_ = false;
    isPresentPickerPopWindow_ = false;
    return ret;
}

void ScreenCaptureServer::Release()
{
    ReleaseInner();
}

void ScreenCaptureServer::ReleaseInner()
{
    MediaTrace trace("ScreenCaptureServer::ReleaseInner");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner S", FAKE_POINTER(this));
    if (captureState_ != AVScreenCaptureState::STOPPED) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (captureState_ != AVScreenCaptureState::STOPPED) {
            StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner Stop done, sessionId:%{public}d",
                FAKE_POINTER(this), sessionId_);
        }
    }
    MEDIA_LOGI("ScreenCaptureServer::ReleaseInner before RemoveScreenCaptureServerMap");

    RemoveSaAppInfoMap(saUid_);
    RemoveScreenCaptureServerMap(sessionId_);
    sessionId_ = SESSION_ID_INVALID;
    MEDIA_LOGD("ReleaseInner removeMap success, mapSize: %{public}d",
        static_cast<int32_t>(ScreenCaptureServer::serverMap_.size()));
    skipPrivacyWindowIDsVec_.clear();
    SetMetaDataReport();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner E", FAKE_POINTER(this));
}

int32_t ScreenCaptureServer::SetCaptureAreaHighlight(AVScreenCaptureHighlightConfig config)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("SetCaptureAreaHighlight lineColor: 0x%{public}x, lineThickness: %{public}dvp, mode: %{public}d",
        config.lineColor, config.lineThickness, static_cast<int32_t>(config.mode));
    captureConfig_.highlightConfig = config;
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetScreenCaptureStrategy(ScreenCaptureStrategy strategy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ < AVScreenCaptureState::POPUP_WINDOW, MSERR_INVALID_STATE,
        "strategy can not be modified after screen capture started");
    MEDIA_LOGI("SetScreenCaptureStrategy enableDeviceLevelCapture: %{public}d, keepCaptureDuringCall: %{public}d,"
               "strategyForPrivacyMaskMode: %{public}d, canvasFollowRotation: %{public}d, enableBFrame: %{public}d,"
               "pickerPopUp: %{public}d, fillMode: %{public}d",
        strategy.enableDeviceLevelCapture, strategy.keepCaptureDuringCall, strategy.strategyForPrivacyMaskMode,
        strategy.canvasFollowRotation, strategy.enableBFrame, static_cast<int32_t>(strategy.pickerPopUp),
        static_cast<int32_t>(strategy.fillMode));
    captureConfig_.strategy = strategy;
    return MSERR_OK;
}

std::shared_ptr<OHOS::AbilityRuntime::WantAgent::WantAgent> ScreenCaptureServer::GetWantAgent(
    const std::string& callingLabel,
    int32_t sessionId)
{
    MEDIA_LOGI("GetWantAgent, setWantAgent");
    auto want = std::make_shared<AAFwk::Want>();
    AppExecFwk::ElementName element("",
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"],
        "PrivacyControlAbility");
    want->SetElement(element);
    want->SetParam("appLabel", callingLabel);
    want->SetParam("sessionId", sessionId);
    std::vector<std::shared_ptr<AAFwk::Want>> wants;
    wants.push_back(want);
    MEDIA_LOGI("GetWantAgent, setWantAgent set all params");
    std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
    flags.push_back(AbilityRuntime::WantAgent::WantAgentConstant::Flags::UPDATE_PRESENT_FLAG);
    AbilityRuntime::WantAgent::WantAgentInfo wantAgentInfo(0,
        AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY,
        flags, wants, nullptr);
    MEDIA_LOGI("GetWantAgent, setWantAgent create wantAgentInfo");
    MEDIA_LOGI("GetWantAgent, setWantAgent get wantAgent");
    return OHOS::AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(wantAgentInfo);
}

void ScreenCaptureServer::SetupPublishRequest(NotificationRequest &request)
{
    std::shared_ptr<NotificationContent> notificationContent =
        std::make_shared<NotificationContent>(localLiveViewContent_);
    request.SetBadgeIconStyle(NotificationRequest::BadgeStyle::LITTLE);
    request.SetContent(notificationContent);
    request.SetCreatorUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetInProgress(true);
    request.SetNotificationId(notificationId_);
    request.SetOwnerUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetRemoveAllowed(false);
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request.SetUnremovable(true);
    request.SetLittleIcon(GetPixelMap(ICON_PATH_NOTIFICATION));
    if (GetSCServerDataType() == DataType::ORIGINAL_STREAM) {
        request.SetWantAgent(GetWantAgent(callingLabel_, sessionId_));
        MEDIA_LOGI("SetupPublishRequest, setWantAgent success");
    }
}

void ScreenCaptureServer::SystemPrivacyProtected(ScreenId& virtualScreenId, bool systemPrivacyProtectionSwitch)
{
    std::vector<ScreenId> screenIds;
    screenIds.push_back(virtualScreenId);
    auto ret = ScreenManager::GetInstance().SetScreenSkipProtectedWindow(screenIds, systemPrivacyProtectionSwitch);
    if (ret == DMError::DM_OK || ret == DMError::DM_ERROR_DEVICE_NOT_SUPPORT) {
        MEDIA_LOGI("SystemPrivacyProtected SetScreenSkipProtectedWindow success");
    } else {
        MEDIA_LOGI("SystemPrivacyProtected SetScreenSkipProtectedWindow failed, ret: %{public}d", ret);
    }
}

void ScreenCaptureServer::AppPrivacyProtected(ScreenId& virtualScreenId, bool appPrivacyProtectionSwitch)
{
    std::vector<std::string> privacyWindowTags;
    privacyWindowTags.push_back("TAG_SCREEN_PROTECTION_SENSITIVE_APP");
    auto ret = ScreenManager::GetInstance().SetScreenPrivacyWindowTagSwitch(virtualScreenId,
        privacyWindowTags, appPrivacyProtectionSwitch);
    if (ret == DMError::DM_OK || ret == DMError::DM_ERROR_DEVICE_NOT_SUPPORT) {
        MEDIA_LOGI("AppPrivacyProtected SetScreenSkipProtectedWindow success");
    } else {
        MEDIA_LOGI("AppPrivacyProtected SetScreenSkipProtectedWindow failed, ret: %{public}d", ret);
    }
}

bool ScreenCaptureServer::IsSkipPrivacyWindow()
{
#ifdef PC_STANDARD
    return GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] == appName_ ||
           (CheckCustScrRecPermission() && !IsPickerPopUp());
#else
    return GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] == appName_;
#endif
}

ScreenCaptureObserverCallBack::ScreenCaptureObserverCallBack(
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer): taskQueObserverCb_("NotifyStopSc")
{
    screenCaptureServer_ = screenCaptureServer;
    taskQueObserverCb_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " ScreenCaptureObserverCallBack Instances create", FAKE_POINTER(this));
}

bool ScreenCaptureObserverCallBack::StopAndRelease(AVScreenCaptureStateCode state)
{
    MEDIA_LOGI("ScreenCaptureObserverCallBack::StopAndRelease");
    auto scrServer = screenCaptureServer_.lock();
    if (scrServer && !scrServer->IsTelInCallSkipList()) {
        if (scrServer->GetSCServerCaptureState() == AVScreenCaptureState::STOPPED) {
            MEDIA_LOGI("StopAndRelease repeat, capture is STOPPED.");
            return true;
        }
        scrServer->StopScreenCaptureByEvent(state);
        scrServer->Release();
    }
    return true;
}

bool ScreenCaptureObserverCallBack::NotifyStopAndRelease(AVScreenCaptureStateCode state)
{
    MEDIA_LOGI("ScreenCaptureObserverCallBack::NotifyStopAndRelease START.");
    auto task = std::make_shared<TaskHandler<void>>([&, this, state] {
        StopAndRelease(state);
    });
    int32_t res = taskQueObserverCb_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, false, "NotifyStopAndRelease EnqueueTask failed.");
    return true;
}

#ifdef SUPPORT_CALL
bool ScreenCaptureObserverCallBack::TelCallStateUpdated(bool isInCall)
{
    MEDIA_LOGI("ScreenCaptureObserverCallBack::TelCallStateUpdated InCall:%{public}d", isInCall);
    auto scrServer = screenCaptureServer_.lock();
    if (scrServer && !scrServer->IsTelInCallSkipList()) {
        if (scrServer->GetSCServerCaptureState() == AVScreenCaptureState::STOPPED) {
            MEDIA_LOGI("TelCallStateUpdated: capture is STOPPED.");
            return true;
        }
        scrServer->TelCallStateUpdated(isInCall);
    }
    return true;
}

bool ScreenCaptureObserverCallBack::NotifyTelCallStateUpdated(bool isInCall)
{
    MEDIA_LOGD("ScreenCaptureObserverCallBack::NotifyTelCallStateUpdated START InCall:%{public}d", isInCall);
    auto task = std::make_shared<TaskHandler<void>>([&, this, isInCall] {
        TelCallStateUpdated(isInCall);
    });
    int32_t res = taskQueObserverCb_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, false, "NotifyTelCallStateUpdated EnqueueTask failed.");
    return true;
}
#endif

void ScreenCaptureObserverCallBack::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);
    taskQueObserverCb_.Stop();
}

ScreenCaptureObserverCallBack::~ScreenCaptureObserverCallBack()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void ScreenCapBufferConsumerListener::OnBufferAvailable()
{
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailable", HITRACE_LEVEL_DEBUG);
    MEDIA_LOGD("ScreenCapConsumer: 0x%{public}06" PRIXPTR " OnBufferAvailable start.", FAKE_POINTER(this));
    {
        std::lock_guard<std::mutex> lock(bufferAvailableWorkerMtx_);
        messageQueueSCB_.push({SCBufferMessageType::GET_BUFFER, "Get buffer!"});
        MEDIA_LOGD("ScreenCapConsumer: 0x%{public}06" PRIXPTR " queue size: %{public}" PRId64, FAKE_POINTER(this),
            static_cast<uint64_t>(messageQueueSCB_.size()));
        bufferAvailableWorkerCv_.notify_one();
    }
}

void ScreenCapBufferConsumerListener::OnBufferAvailableAction()
{
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailableAction", HITRACE_LEVEL_DEBUG);
    MEDIA_LOGD("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " start.", FAKE_POINTER(this));
    CHECK_AND_RETURN(consumer_ != nullptr);
    int64_t timestamp = 0;
    OHOS::Rect damage;
    OHOS::sptr<OHOS::SurfaceBuffer> buffer = nullptr;
    sptr<SyncFence> acquireFence = SyncFence::INVALID_FENCE;
    int32_t acquireBufferRet = consumer_->AcquireBuffer(buffer, acquireFence, timestamp, damage);
    if (acquireBufferRet != GSERROR_OK) {
        MEDIA_LOGE("OnBufferAvailableAction AcquireBuffer Fail Code %{public}d", acquireBufferRet);
    }
    MEDIA_LOGD("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " after AcquireBuffer.", FAKE_POINTER(this));
    int32_t flushFence = -1;
    if (acquireFence != nullptr && acquireFence != SyncFence::INVALID_FENCE) {
        acquireFence->Wait(1000); // 1000 ms
        flushFence = acquireFence->Get();
    }
    CHECK_AND_RETURN_LOG(buffer != nullptr, "Acquire SurfaceBuffer failed");
    if ((buffer->GetUsage() & BUFFER_USAGE_MEM_MMZ_CACHE) != 0) {
        MEDIA_LOGD("OnBufferAvailableAction cache enable");
        buffer->InvalidateCache();
    }
    void *addr = buffer->GetVirAddr();
    if (addr == nullptr) {
        MEDIA_LOGE("Acquire SurfaceBuffer address invalid");
        int32_t releaseBufferRet = consumer_->ReleaseBuffer(buffer, -1); // -1 not wait
        if (releaseBufferRet != GSERROR_OK) {
            MEDIA_LOGE("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " ReleaseBuffer Fail Code %{public}d",
                FAKE_POINTER(this), releaseBufferRet);
        }
        return;
    }
    MEDIA_LOGD("OnBufferAvailableAction SurfaceBuffer size: %{public}u", buffer->GetSize());
    {
        std::unique_lock<std::mutex> lock(bufferMutex_);
        if (availBuffers_.size() > MAX_BUFFER_SIZE) {
            MEDIA_LOGE("OnBufferAvailableAction consume slow, drop video frame");
            int32_t releaseBufferRet = consumer_->ReleaseBuffer(buffer, -1); // -1 not wait
            if (releaseBufferRet != GSERROR_OK) {
                MEDIA_LOGE("OnBufferAvailableAction: 0x%{public}06" PRIXPTR " consume slow ReleaseBuffer "
                    "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
            }
            return;
        }
        availBuffers_.push(std::make_unique<SurfaceBufferEntry>(buffer, flushFence, timestamp, damage));
    }
    bufferCond_.notify_all();
    ProcessVideoBufferCallBack();
}

void ScreenCapBufferConsumerListener::SurfaceBufferThreadRun()
{
    SCBufferMessage message;
    std::string threadName = std::string("OS_SCBufferAvailableWorker");
    MEDIA_LOGD("0x%{public}06" PRIXPTR " BufferAvailableWorker name: %{public}s",
        FAKE_POINTER(this), threadName.c_str());
    pthread_setname_np(pthread_self(), threadName.c_str());
    while (true) {
        {
            std::unique_lock<std::mutex> lock(bufferAvailableWorkerMtx_);
            bufferAvailableWorkerCv_.wait(lock, [&]() { return !messageQueueSCB_.empty(); });
            message = messageQueueSCB_.front();
            if (static_cast<uint64_t>(messageQueueSCB_.size()) > MAX_MESSAGE_QUEUE_SIZE &&
                message.type == SCBufferMessageType::GET_BUFFER) {
                messageQueueSCB_.pop();
                MEDIA_LOGE("0x%{public}06" PRIXPTR " BufferAvailableWorker skip get buffer", FAKE_POINTER(this));
                continue;
            }
            messageQueueSCB_.pop();
        }
        if (message.type == SCBufferMessageType::EXIT) {
            break;
        }
        if (message.type == SCBufferMessageType::GET_BUFFER) {
            OnBufferAvailableAction();
        }
    }
    MEDIA_LOGD("ScreenCapBufferConsumerListener::SurfaceBufferThreadRun End.");
}

int32_t ScreenCapBufferConsumerListener::StartBufferThread()
{
    if (isSurfaceCbInThreadStopped_.load()) {
        surfaceCbInThread_ = new (std::nothrow) std::thread([this]() {
            isSurfaceCbInThreadStopped_.store(false);
            this->SurfaceBufferThreadRun();
            isSurfaceCbInThreadStopped_.store(true);
        });
        CHECK_AND_RETURN_RET_LOG(surfaceCbInThread_ != nullptr, MSERR_UNKNOWN, "new surface thread failed");
    }
    MEDIA_LOGI("ScreenCapBufferConsumerListener::StartBufferThread End.");
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::ProcessVideoBufferCallBack()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_LOG(screenCaptureCb_ != nullptr, "no consumer, will drop video frame");
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " OnBufferAvailable end.", FAKE_POINTER(this));
    screenCaptureCb_->OnVideoBufferAvailable(true);
}

int32_t ScreenCapBufferConsumerListener::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
    int64_t &timestamp, OHOS::Rect &damage)
{
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer", HITRACE_LEVEL_DEBUG);
    using namespace std::chrono_literals;
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer start, fence:%{public}d, "
        "timestamp:%{public}" PRId64, FAKE_POINTER(this), fence, timestamp);
    if (!bufferCond_.wait_for(
        lock, std::chrono::milliseconds(OPERATION_TIMEOUT_IN_MS), [this] { return !availBuffers_.empty(); })) {
        return MSERR_UNKNOWN;
    }
    surfaceBuffer = availBuffers_.front()->buffer;
    fence = availBuffers_.front()->flushFence;
    timestamp = availBuffers_.front()->timeStamp;
    damage = availBuffers_.front()->damageRect;
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer end.", FAKE_POINTER(this));
    return MSERR_OK;
}

void ScreenCapBufferConsumerListener::StopBufferThread()
{
    std::lock_guard<std::mutex> lock(bufferAvailableWorkerMtx_);
    messageQueueSCB_.push({SCBufferMessageType::EXIT, ""});
    MEDIA_LOGI("StopBufferThread: 0x%{public}06" PRIXPTR " EXIT.", FAKE_POINTER(this));
    bufferAvailableWorkerCv_.notify_one();
}

ScreenCapBufferConsumerListener::~ScreenCapBufferConsumerListener()
{
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " Destroy.", FAKE_POINTER(this));
    StopBufferThread();
    if (surfaceCbInThread_ && surfaceCbInThread_->joinable()) {
        surfaceCbInThread_->join();
        delete surfaceCbInThread_;
        surfaceCbInThread_ = nullptr;
    }
    std::unique_lock<std::mutex> lock(bufferMutex_);
    ReleaseBuffer();
}

int32_t ScreenCapBufferConsumerListener::ReleaseBuffer()
{
    while (!availBuffers_.empty()) {
        if (consumer_ != nullptr) {
            int32_t releaseBufferRet = consumer_->ReleaseBuffer(availBuffers_.front()->buffer, -1);  // -1 not wait
            if (releaseBufferRet != GSERROR_OK) {
                MEDIA_LOGE("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseBuffer "
                    "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
            }
        }
        availBuffers_.pop();
    }
    return MSERR_OK;
}

int32_t ScreenCapBufferConsumerListener::ReleaseVideoBuffer()
{
    MediaTrace trace("ScreenCaptureServer::ReleaseVideoBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer start.",
        FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(!availBuffers_.empty(), MSERR_OK, "buffer queue is empty, no video frame to release");

    if (consumer_ != nullptr) {
        int32_t releaseBufferRet = consumer_->ReleaseBuffer(availBuffers_.front()->buffer, -1); // -1 not wait
        if (releaseBufferRet != GSERROR_OK) {
            MEDIA_LOGE("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer "
                "Fail Code %{public}d", FAKE_POINTER(this), releaseBufferRet);
        }
    }
    availBuffers_.pop();
    MEDIA_LOGD("ScreenCapBufferConsumerListener: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCapBufferConsumerListener::Release()
{
    std::unique_lock<std::mutex> lock(bufferMutex_);
    MEDIA_LOGI("ScreenCapBufferConsumerListener Release");
    return ReleaseBuffer();
}

void ScreenRendererAudioStateChangeCallback::SetAudioSource(std::shared_ptr<AudioDataSource> audioSource)
{
    audioSource_ = audioSource;
}

void ScreenRendererAudioStateChangeCallback::SetAppName(std::string appName)
{
    appName_ = appName;
}

void ScreenRendererAudioStateChangeCallback::OnRendererStateChange(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    MEDIA_LOGD("ScreenRendererAudioStateChangeCallback IN");
    CHECK_AND_RETURN(audioSource_ != nullptr);
    auto screenCaptureServer = audioSource_->GetScreenCaptureServer();
    CHECK_AND_RETURN(screenCaptureServer != nullptr);
    CHECK_AND_RETURN(screenCaptureServer->GetSCServerCaptureState() != AVScreenCaptureState::STOPPED);
    audioSource_->SpeakerStateUpdate(audioRendererChangeInfos);
#ifdef SUPPORT_CALL
    audioSource_->TelCallAudioStateUpdate(audioRendererChangeInfos);
#endif
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) == 0 && region == "CN") {
        audioSource_->VoIPStateUpdate(audioRendererChangeInfos);
    }
}

void AudioDataSource::SpeakerStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    uint32_t changeInfoSize = allAudioRendererChangeInfos.size();
    if (changeInfoSize == 0) {
        return;
    }
    bool speakerAlive = HasSpeakerStream(allAudioRendererChangeInfos);
    if (speakerAlive != speakerAliveStatus_) {
        speakerAliveStatus_ = speakerAlive;
        CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
        screenCaptureServer_->OnSpeakerAliveStatusChanged(speakerAlive);
        if (speakerAlive) {
            MEDIA_LOGI("HEADSET Change to Speaker.");
        } else {
            MEDIA_LOGI("Speaker Change to HEADSET.");
        }
    }
}

#ifdef SUPPORT_CALL
void AudioDataSource::TelCallAudioStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: allAudioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("Client pid : %{public}d, State : %{public}d, usage : %{public}d",
            changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->rendererInfo.streamUsage));
        if (changeInfo->rendererInfo.streamUsage ==
            AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION &&
            (changeInfo->rendererState == RendererState::RENDERER_RUNNING ||
            changeInfo->rendererState == RendererState::RENDERER_PREPARED)) {
            screenCaptureServer_->TelCallAudioStateUpdated(true);
            return;
        }
    }
    screenCaptureServer_->TelCallAudioStateUpdated(false);
}
#endif

bool AudioDataSource::HasSpeakerStream(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    uint32_t changeInfoIndex = 0;
    uint32_t headSetCount = 0;
    bool hasSpeakerStream = true;
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: audioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("ChangeInfo Id: %{public}d, Client pid : %{public}d, State : %{public}d, DeviceType : %{public}d",
            changeInfoIndex, changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->outputDeviceInfo.deviceType_));
        if (changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADPHONES ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_ARM_HEADSET) {
            headSetCount++;
        }
        changeInfoIndex++;
    }
    if (headSetCount == changeInfoIndex) { // only if all streams in headset
        hasSpeakerStream = false;
    }
    return hasSpeakerStream;
}

void AudioDataSource::VoIPStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    std::lock_guard<std::mutex> lock(voipStatusChangeMutex_);
    (void)audioRendererChangeInfos;
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> allAudioRendererChangeInfos;
    AudioStreamManager::GetInstance()->GetCurrentRendererChangeInfos(allAudioRendererChangeInfos);
    bool isInVoIPCall = HasVoIPStream(allAudioRendererChangeInfos);
    if (isInVoIPCall_.load() == isInVoIPCall) {
        return;
    }
    isInVoIPCall_.store(isInVoIPCall);
    CHECK_AND_RETURN(screenCaptureServer_ != nullptr);
    screenCaptureServer_->OnVoIPStatusChanged(isInVoIPCall);
}

bool AudioDataSource::HasVoIPStream(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo: audioRendererChangeInfos) {
        if (!changeInfo) {
            continue;
        }
        MEDIA_LOGD("Client pid : %{public}d, State : %{public}d, usage : %{public}d",
            changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->rendererInfo.streamUsage));
        if (changeInfo->rendererState == RendererState::RENDERER_RUNNING &&
		    (changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION ||
		    changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION)) {
            return true;
        }
    }
    return false;
}

void AudioDataSource::SetAppPid(int32_t appid)
{
    appPid_ = appid;
}

int32_t AudioDataSource::GetAppPid()
{
    return appPid_ ;
}

bool AudioDataSource::GetIsInVoIPCall()
{
    return isInVoIPCall_.load();
}

bool AudioDataSource::IsInWaitMicSyncState()
{
    return isInWaitMicSyncState_;
}

bool AudioDataSource::GetSpeakerAliveStatus()
{
    return speakerAliveStatus_;
}

void AudioDataSource::SetAppName(std::string appName)
{
    appName_ = appName;
}

int32_t AudioDataSource::RegisterAudioRendererEventListener(const int32_t clientPid,
    const std::shared_ptr<AudioRendererStateChangeCallback> &callback)
{
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL, "audio callback is null");
    int32_t ret = AudioStreamManager::GetInstance()->RegisterAudioRendererEventListener(clientPid, callback);
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> audioRendererChangeInfos;
    SpeakerStateUpdate(audioRendererChangeInfos);
    std::string region = Global::I18n::LocaleConfig::GetSystemRegion();
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) == 0 && region == "CN") {
        VoIPStateUpdate(audioRendererChangeInfos);
    }
    return ret;
}

int32_t AudioDataSource::UnregisterAudioRendererEventListener(const int32_t clientPid)
{
    MEDIA_LOGI("client id: %{public}d", clientPid);
    return AudioStreamManager::GetInstance()->UnregisterAudioRendererEventListener(clientPid);
}

void AudioDataSource::SetVideoFirstFramePts(int64_t firstFramePts)
{
    firstVideoFramePts_.store(firstFramePts);
    struct timespec timestamp = {0, 0};
    clock_gettime(CLOCK_MONOTONIC, &timestamp);
    int64_t curTime = timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
    MEDIA_LOGI("SetVideoFirstFramePts video to ScreenCapture timeWindow: %{public}" PRId64
        " firstVideoFramePts: %{public}" PRId64, curTime - firstFramePts, firstFramePts);
}

void AudioDataSource::SetAudioFirstFramePts(int64_t firstFramePts)
{
    if (firstAudioFramePts_.load() == -1) {
        firstAudioFramePts_.store(firstFramePts);
        MEDIA_LOGI("firstAudioFramePts_: %{public}" PRId64, firstFramePts);
    }
}

ScreenCaptureServer* AudioDataSource::GetScreenCaptureServer()
{
    return screenCaptureServer_;
}

AudioDataSourceReadAtActionState AudioDataSource::WriteInnerAudio(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(innerAudioBuffer->timestamp); // update firstAudioFramePts in case re-sync
    return MixModeBufferWrite(innerAudioBuffer, tmp, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMicAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || micAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    std::shared_ptr<AudioBuffer> tmp = nullptr;
    SetAudioFirstFramePts(micAudioBuffer->timestamp);
    return MixModeBufferWrite(tmp, micAudioBuffer, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::WriteMixAudio(std::shared_ptr<AVBuffer> &buffer, uint32_t length,
    std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr || micAudioBuffer == nullptr) {
        MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    SetAudioFirstFramePts(std::min(micAudioBuffer->timestamp, innerAudioBuffer->timestamp));
    return MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
}

AudioDataSourceReadAtActionState AudioDataSource::HandleMicBeforeInnerSync(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    int64_t timeDiff = innerAudioBuffer->timestamp - micAudioBuffer->timestamp;
    if (timeDiff > MAX_MIC_BEFORE_INNER_TIME_IN_NS) {
        // Drop mic data Before 40ms
        if (micAudioBuffer && screenCaptureServer_->GetMicAudioCapture()) {
            screenCaptureServer_->GetMicAudioCapture()->DropBufferUntil(innerAudioBuffer->timestamp);
            MEDIA_LOGI("mic before inner timeDiff: %{public}" PRId64 " DropBufferUntil inner time: %{public}" PRId64
                " lastAudioPts: %{public}" PRId64, timeDiff,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        }
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    return WriteMicAudio(buffer, length, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::InnerMicAudioSync(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    int64_t timeWindow = micAudioBuffer->timestamp - innerAudioBuffer->timestamp;
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // mic before inner
        return HandleMicBeforeInnerSync(buffer, length, innerAudioBuffer, micAudioBuffer);
    }
    if (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS) { // Write mix
        return WriteMixAudio(buffer, length, innerAudioBuffer, micAudioBuffer);
    } else { // Write Inner data Before mic timeWindow >= AUDIO_INTERVAL_IN_NS
        return WriteInnerAudio(buffer, length, innerAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncMixMode(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (micAudioBuffer && screenCaptureServer_->GetMicAudioCapture() && mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("mic AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            screenCaptureServer_->GetMicAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture() && !mixModeAddAudioMicFrame_) {
            MEDIA_LOGI("inner AddBufferFrom timeWindow: %{public}" PRId64, timeWindow);
            screenCaptureServer_->GetInnerAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (micAudioBuffer && screenCaptureServer_->GetMicAudioCapture()) {
            screenCaptureServer_->GetMicAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        return ReadWriteAudioBufferMixCore(buffer, length, innerAudioBuffer, micAudioBuffer);
    }
}

int64_t AudioDataSource::GetFirstAudioTime(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer && micAudioBuffer) {
        if (innerAudioBuffer->timestamp > micAudioBuffer->timestamp) {
            mixModeAddAudioMicFrame_ = true;
            return micAudioBuffer->timestamp;
        }
        mixModeAddAudioMicFrame_ = false;
        return innerAudioBuffer->timestamp;
    }
    if (innerAudioBuffer && !micAudioBuffer) {
        mixModeAddAudioMicFrame_ = false;
        return innerAudioBuffer->timestamp;
    }
    if (!innerAudioBuffer && micAudioBuffer) {
        mixModeAddAudioMicFrame_ = true;
        return micAudioBuffer->timestamp;
    }
    return -1;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMixCore(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (innerAudioBuffer == nullptr && micAudioBuffer) {
        return WriteMicAudio(buffer, length, micAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer == nullptr) {
        if (screenCaptureServer_->IsStopAcquireAudioBufferFlag() && isInWaitMicSyncState_) {
            return WriteInnerAudio(buffer, length, innerAudioBuffer);
        }
        if (screenCaptureServer_->IsMicrophoneSwitchTurnOn()) {
            int64_t currentAudioTime = 0;
            screenCaptureServer_->GetInnerAudioCapture()->GetCurrentAudioTime(currentAudioTime);
            if (currentAudioTime - innerAudioBuffer->timestamp < MAX_INNER_AUDIO_TIMEOUT_IN_NS) { // 2s
                isInWaitMicSyncState_ = true;
                return AudioDataSourceReadAtActionState::RETRY_IN_INTERVAL;
            } else {
                MEDIA_LOGD("isInWaitMicSyncState close");
                isInWaitMicSyncState_ = false;
            }
        }
        return WriteInnerAudio(buffer, length, innerAudioBuffer);
    }
    if (innerAudioBuffer && micAudioBuffer) {
        return InnerMicAudioSync(buffer, length, innerAudioBuffer, micAudioBuffer);
    }
    if (innerAudioBuffer == nullptr && micAudioBuffer == nullptr) {
        MEDIA_LOGD("acquire none inner mic buffer");
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    return AudioDataSourceReadAtActionState::OK;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadWriteAudioBufferMix(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, std::shared_ptr<AudioBuffer> &innerAudioBuffer, std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (screenCaptureServer_->IsMicrophoneCaptureRunning()) {
        if (screenCaptureServer_->GetMicAudioCapture()->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
        }
    }
    if (screenCaptureServer_->IsInnerCaptureRunning()) {
        if (screenCaptureServer_->GetInnerAudioCapture()->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
        }
    }
    CHECK_AND_RETURN_RET_NOLOG(innerAudioBuffer || micAudioBuffer, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1) { // video audio sync
        int64_t audioTime = GetFirstAudioTime(innerAudioBuffer, micAudioBuffer);
        CHECK_AND_RETURN_RET_NOLOG(audioTime != -1, AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG);
        struct timespec timestamp = {0, 0};
        clock_gettime(CLOCK_MONOTONIC, &timestamp);
        int64_t curTime = timestamp.tv_sec * SEC_TO_NS + timestamp.tv_nsec;
        MEDIA_LOGI("ReadWriteAudioBufferMix audio to ScreenCapture timeWindow: %{public}" PRId64
            " firstAudioFramePts: %{public}" PRId64, curTime - audioTime, audioTime);
        int64_t timeWindow = firstVideoFramePts_.load() - audioTime;
        MEDIA_LOGI("ReadWriteAudioBufferMix video to audio timeWindow: %{public}" PRId64, timeWindow);
        return VideoAudioSyncMixMode(buffer, length, timeWindow, innerAudioBuffer, micAudioBuffer);
    }
    return ReadWriteAudioBufferMixCore(buffer, length, innerAudioBuffer, micAudioBuffer);
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMixMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
    std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
    AudioDataSourceReadAtActionState ret = ReadWriteAudioBufferMix(buffer, length, innerAudioBuffer, micAudioBuffer);
    MEDIA_LOGD("AudioDataSource ReadAtMixMode ret: %{public}d", static_cast<int32_t>(ret));
    return ret;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtMicMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    if (screenCaptureServer_->GetMicAudioCapture() == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (screenCaptureServer_->IsMicrophoneCaptureRunning()) {
        std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
        if (screenCaptureServer_->GetMicAudioCapture()->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("micAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer mic success");
        if (buffer->memory_ == nullptr || micAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or micAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write mic cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
        audioBufferQ_.emplace_back(micAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(screenCaptureServer_->ReleaseMicAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "micAudioCapture ReleaseAudioBuffer failed");
        micAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::VideoAudioSyncInnerMode(std::shared_ptr<AVBuffer> &buffer,
    uint32_t length, int64_t timeWindow, std::shared_ptr<AudioBuffer> &innerAudioBuffer)
{
    if (timeWindow <= NEG_AUDIO_INTERVAL_IN_NS) { // video before audio add 0
        if (innerAudioBuffer && screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->AddBufferFrom(-1 * timeWindow,
                length, firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (timeWindow >= AUDIO_INTERVAL_IN_NS) { // video after audio drop audio
        if (screenCaptureServer_->GetInnerAudioCapture()) {
            screenCaptureServer_->GetInnerAudioCapture()->DropBufferUntil(firstVideoFramePts_.load());
        }
        SetAudioFirstFramePts(firstVideoFramePts_.load());
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    } else { // (timeWindow > NEG_AUDIO_INTERVAL_IN_NS && timeWindow < AUDIO_INTERVAL_IN_NS)
        if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        audioBufferQ_.emplace_back(innerAudioBuffer);
        SetAudioFirstFramePts(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        screenCaptureServer_->ReleaseInnerAudioBuffer();
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAtInnerMode(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    if (screenCaptureServer_->GetInnerAudioCapture() == nullptr) {
        return AudioDataSourceReadAtActionState::INVALID;
    }
    if (screenCaptureServer_->IsInnerCaptureRunning()) {
        std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
        if (screenCaptureServer_->GetInnerAudioCapture()->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGD("innerAudioCapture AcquireAudioBuffer failed");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("AcquireAudioBuffer inner success");
        if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstAudioFramePts_ == -1 && innerAudioBuffer) {
            int64_t timeWindow = firstVideoFramePts_.load() - innerAudioBuffer->timestamp;
            return VideoAudioSyncInnerMode(buffer, length, timeWindow, innerAudioBuffer);
        }
        if (buffer->memory_ == nullptr || innerAudioBuffer == nullptr) {
            MEDIA_LOGE("buffer->memory_ or innerAudioBuffer nullptr");
            return AudioDataSourceReadAtActionState::RETRY_SKIP;
        }
        MEDIA_LOGD("ABuffer write inner cur:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        audioBufferQ_.emplace_back(innerAudioBuffer);
        CHECK_AND_RETURN_RET_LOG(screenCaptureServer_->ReleaseInnerAudioBuffer() == MSERR_OK,
            AudioDataSourceReadAtActionState::RETRY_SKIP, "innerAudioCapture ReleaseAudioBuffer failed");
        innerAudioBuffer = nullptr;
        return AudioDataSourceReadAtActionState::OK;
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAudioBuffer(
    std::shared_ptr<AVBuffer> &buffer, const uint32_t &length)
{
    MEDIA_LOGD("AudioDataSource ReadAt start");
    CHECK_AND_RETURN_RET_LOG(screenCaptureServer_ != nullptr, AudioDataSourceReadAtActionState::RETRY_SKIP,
        "ReadAt screenCaptureServer null");
    if (screenCaptureServer_->GetSCServerCaptureState() != AVScreenCaptureState::STARTED) {
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (screenCaptureServer_->IsSCRecorderFileWithVideo() && firstVideoFramePts_.load() == -1) { // video frame not come
        return AudioDataSourceReadAtActionState::SKIP_WITHOUT_LOG;
    }
    if (type_ == AVScreenCaptureMixMode::MIX_MODE) {
        return ReadAtMixMode(buffer, length);
    }
    if (type_ == AVScreenCaptureMixMode::INNER_MODE) {
        return ReadAtInnerMode(buffer, length);
    }
    if (type_ == AVScreenCaptureMixMode::MIC_MODE) {
        return ReadAtMicMode(buffer, length);
    }
    return AudioDataSourceReadAtActionState::RETRY_SKIP;
}

void AudioDataSource::HandlePastMicBuffer(std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer->timestamp < lastWriteAudioFramePts_.load() &&
        micAudioBuffer->timestamp < lastMicAudioFramePts_.load() + AUDIO_MIC_TOO_CLOSE_LIMIT_IN_NS &&
        lastWriteType_ == AVScreenCaptureMixBufferType::INNER) { // drop past mic data when switch,keep when mic stable
        screenCaptureServer_->ReleaseMicAudioBuffer();
        MEDIA_LOGD("ABuffer drop mix mic error cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        micAudioBuffer = nullptr;
    }
}

void AudioDataSource::HandleSwitchToSpeakerOptimise(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (speakerAliveStatus_ && screenCaptureServer_ && screenCaptureServer_->IsMicrophoneSwitchTurnOn() &&
        !isInVoIPCall_ && micAudioBuffer->buffer &&
        lastWriteType_ == AVScreenCaptureMixBufferType::MIX && screenCaptureServer_->GetInnerAudioCapture()) {
        if (stableStopInnerSwitchCount_ > INNER_SWITCH_MIC_REQUIRE_COUNT) { // optimise inner while use speaker
            MEDIA_LOGI("ABuffer stop mix inner optimise cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
            screenCaptureServer_->StopInnerAudioCapture();
            stableStopInnerSwitchCount_ = 0;
        } else {
            stableStopInnerSwitchCount_++;
        }
    }
}

void AudioDataSource::HandleBufferTimeStamp(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer)
{
    if (micAudioBuffer) {
        HandlePastMicBuffer(micAudioBuffer);
    }
    if (innerAudioBuffer) {
        if (innerAudioBuffer->timestamp < lastWriteAudioFramePts_.load()
            && !GetIsInVoIPCall() && speakerAliveStatus_) {
            screenCaptureServer_->ReleaseInnerAudioBuffer(); // drop past inner data while use speaker
            MEDIA_LOGD("ABuffer drop mix inner error cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
            innerAudioBuffer = nullptr;
        }
    }
    if (innerAudioBuffer && micAudioBuffer) {
        HandleSwitchToSpeakerOptimise(innerAudioBuffer, micAudioBuffer);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem)
{
    HandleBufferTimeStamp(innerAudioBuffer, micAudioBuffer);
    if (innerAudioBuffer && innerAudioBuffer->buffer && micAudioBuffer && micAudioBuffer->buffer) {
        char* mixData = new char[innerAudioBuffer->length];
        char* srcData[2] = {nullptr};
        srcData[0] = reinterpret_cast<char*>(innerAudioBuffer->buffer);
        srcData[1] = reinterpret_cast<char*>(micAudioBuffer->buffer);
        int channels = 2;
        MixAudio(srcData, mixData, channels, innerAudioBuffer->length);
        MEDIA_LOGD("ABuffer write mix mix cur:%{public}" PRId64 " mic:%{public}" PRId64 " last: %{public}" PRId64,
            innerAudioBuffer->timestamp, micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIX;
        audioBufferQ_.emplace_back(reinterpret_cast<uint8_t*>(mixData), innerAudioBuffer->timestamp);
    } else if (innerAudioBuffer && innerAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix inner cur:%{public}" PRId64 " last: %{public}" PRId64,
                innerAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(innerAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::INNER;
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(innerAudioBuffer);
    } else if (micAudioBuffer && micAudioBuffer->buffer) {
        MEDIA_LOGD("ABuffer write mix mic cur:%{public}" PRId64 " last: %{public}" PRId64,
            micAudioBuffer->timestamp, lastWriteAudioFramePts_.load());
        lastWriteAudioFramePts_.store(micAudioBuffer->timestamp);
        lastMicAudioFramePts_.store(micAudioBuffer->timestamp);
        lastWriteType_ = AVScreenCaptureMixBufferType::MIC;
        stableStopInnerSwitchCount_ = 0;
        audioBufferQ_.emplace_back(micAudioBuffer);
    } else {
        MEDIA_LOGE("without buffer write");
        return AudioDataSourceReadAtActionState::RETRY_SKIP;
    }
    if (innerAudioBuffer) {
        screenCaptureServer_->ReleaseInnerAudioBuffer();
        innerAudioBuffer = nullptr;
    }
    if (micAudioBuffer) {
        screenCaptureServer_->ReleaseMicAudioBuffer();
        micAudioBuffer = nullptr;
    }
    return AudioDataSourceReadAtActionState::OK;
}

int32_t AudioDataSource::GetSize(int64_t &size)
{
    size_t bufferLen = 0;
    int32_t ret = MSERR_UNKNOWN;
    if (screenCaptureServer_->GetInnerAudioCapture()) {
        ret = screenCaptureServer_->GetInnerAudioCaptureBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    if (screenCaptureServer_->GetMicAudioCapture()) {
        ret = screenCaptureServer_->GetMicAudioCaptureBufferSize(bufferLen);
        MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
        if (ret == MSERR_OK) {
            size = static_cast<int64_t>(bufferLen);
            return ret;
        }
    }
    return ret;
}

void AudioDataSource::MixAudio(char** srcData, char* mixData, int channels, int bufferSize)
{
    MEDIA_LOGD("AudioDataSource MixAudio");
    int const max = 32767;
    int const min = -32768;
    double const splitNum = 32;
    int const doubleChannels = 2;
    double coefficient = 1;
    int totalNum = 0;
    if (channels == 0) {
        return;
    }
    for (totalNum = 0; totalNum < bufferSize / channels; totalNum++) {
        int temp = 0;
        for (int channelNum = 0; channelNum < channels; channelNum++) {
            temp += *reinterpret_cast<short*>(srcData[channelNum] + totalNum * channels);
        }
        int32_t output = static_cast<int32_t>(temp * coefficient);
        if (output > max) {
            coefficient = static_cast<double>(max) / static_cast<double>(output);
            output = max;
        }
        if (output < min) {
            coefficient = static_cast<double>(min) / static_cast<double>(output);
            output = min;
        }
        if (coefficient < 1) {
            coefficient += (static_cast<double>(1) - coefficient) / splitNum;
        }
        *reinterpret_cast<short*>(mixData + totalNum * doubleChannels) = static_cast<short>(output);
    }
}

int32_t AudioDataSource::LostFrameNum(const int64_t &timestamp)
{
    return static_cast<int32_t>(
        (timestamp - (writedFrameTime_ + firstAudioFramePts_)) / FILL_AUDIO_FRAME_DURATION_IN_NS);
}

void AudioDataSource::FillLostBuffer(const int64_t &lostNum, const int64_t &timestamp, const uint32_t &bufferSize)
{
    CHECK_AND_RETURN_LOG(bufferSize > 0, "AudioDataSource::FillLostBuffer: bufferSize is invalid");
    MEDIA_LOGI("AudioDataSource::FillLostBuffer: lostNum=%{public}" PRId64 ", timestamp=%{public}" PRId64
               ", bufferSize=%{public}" PRId32,
        lostNum, timestamp, bufferSize);
    auto pts = timestamp;
    for (int64_t i = 0; i < lostNum; i++) {
        auto *buffer = new (std::nothrow) uint8_t[bufferSize]{0};
        CHECK_AND_CONTINUE_LOG(buffer != nullptr, "AudioDataSource::FillLostBuffer: buffer is null");
        pts -= FILL_AUDIO_FRAME_DURATION_IN_NS;
        audioBufferQ_.emplace_front(buffer, pts);
    }
}

AudioDataSourceReadAtActionState AudioDataSource::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    if (!audioBufferQ_.empty()) {
        auto &audioBuffer = audioBufferQ_.front();
        auto lostNum = LostFrameNum(audioBuffer.timestamp);
        if (lostNum >= FILL_LOST_FRAME_COUNT_THRESHOLD) {
            FillLostBuffer(lostNum, audioBuffer.timestamp, length);
        }
        audioBufferQ_.front().WriteTo(buffer->memory_, length);
        audioBufferQ_.pop_front();
        writedFrameTime_ += FILL_AUDIO_FRAME_DURATION_IN_NS;
        return AudioDataSourceReadAtActionState::OK;
    }
    const auto &ret = ReadAudioBuffer(buffer, length);
    CHECK_AND_RETURN_RET_NOLOG(ret == AudioDataSourceReadAtActionState::OK, ret);
    if (!audioBufferQ_.empty()) {
        return ReadAt(buffer, length);
    }
    return ret;
}

AudioDataSource::CacheBuffer::CacheBuffer(const std::shared_ptr<AudioBuffer> &buf)
    : refBuf_(buf), timestamp(buf->timestamp)
{
}

AudioDataSource::CacheBuffer::CacheBuffer(uint8_t *buf, const int64_t &timestamp)
    : buf_(std::unique_ptr<uint8_t>(buf)), timestamp(timestamp)
{
}

void AudioDataSource::CacheBuffer::WriteTo(const std::shared_ptr<AVMemory> &avMem, const uint32_t &len)
{
    if (buf_) {
        avMem->Write(buf_.get(), len, 0);
    } else if (refBuf_) {
        avMem->Write(refBuf_->buffer, len, 0);
    } else {
        MEDIA_LOGE("AudioDataSource::CacheBuffer::WriteTo: buffer is null");
    }
}
} // namespace Media
} // namespace OHOS
