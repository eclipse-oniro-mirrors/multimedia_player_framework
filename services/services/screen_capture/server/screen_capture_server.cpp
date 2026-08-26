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

#include "screen_capture_server.h"
#include "account_observer.h"
#include "audio_capturer_wrapper.h"
#include "screen_capture_server_manager.h"
#include <ability_connection.h>
#include <ability_manager_client.h>
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif
#include "audio_data_source.h"
#include "extension_manager_client.h"
#include "i_screen_capture_monitor_service.h"
#include "media_dfx.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "os_account_manager.h"
#include "scope_guard.h"
#include "screen_cap_buffer_consumer_listener.h"
#include "uri_helper.h"
#include <accesstoken_kit.h>
#include <algorithm>
#include <audio_stream_manager.h>
#include <common/rs_common_def.h>
#include <cstddef>
#include <display_manager.h>
#include <hitrace/tracechain.h>
#include <i_input_device_listener.h>
#include <i_recorder_service.h>
#include <image_source.h>
#include <image_type.h>
#include <input_manager.h>
#include <ipc_skeleton.h>
#include <iservice_registry.h>
#include <list>
#include <locale_config.h>
#include <meta/meta.h>
#include <nativetoken_kit.h>
#include <notification_constant.h>
#include <notification_content.h>
#include <notification_helper.h>
#include <notification_request.h>
#include <notification_slot.h>
#include <param_wrapper.h>
#include <parameter.h>
#include <pixel_map.h>
#include <privacy_kit.h>
#include <res_sched_client.h>
#include <res_type.h>
#include <screen_manager.h>
#include <session_manager_lite.h>
#include <set>
#include <surface.h>
#include <sys/stat.h>
#include <system_ability_definition.h>
#include <system_ability_status_change_stub.h>
#include <token_setproc.h>
#include <tokenid_kit.h>
#include <ui_extension_ability_connection.h>
#include <unistd.h>
#include <unordered_map>
#include <v1_0/buffer_handle_meta_key_type.h>
#include <want_agent_helper.h>
#include <want_agent_info.h>
#include <window_manager.h>
#include <window_manager_lite.h>
#ifdef PC_STANDARD
#include <parameters.h>
#include <power_mgr_client.h>
#endif

using namespace OHOS::Rosen;
using namespace OHOS::AudioStandard;
using namespace OHOS::Notification;
using namespace OHOS::Security::AccessToken;
using SessionLifecycleEvent = OHOS::Rosen::ISessionLifecycleListener::SessionLifecycleEvent;

namespace {
const std::string DUMP_PATH = "/data/media/screen_capture.bin";
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServer"};

std::mutex g_serverMapMutex;
std::map<OHOS::Media::IScreenCaptureService*, std::shared_ptr<OHOS::Media::IScreenCaptureService>> g_serverMap;
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
static const std::string BUTTON_NAME_PAUSE = "pause";
static const std::string BUTTON_NAME_RESUME = "resume";
static const std::string ICON_PATH_CAPSULE_STOP = "/etc/screencapture/capsule_stop.svg";
static const std::string ICON_PATH_CAPSULE_STOP_2_0 = "/etc/screencapture/capsule_stop_live2.svg";
static const std::string ICON_PATH_NOTIFICATION = "/etc/screencapture/notification.png";
static const std::string ICON_PATH_STOP = "/etc/screencapture/light.svg";
static const std::string ICON_PATH_PAUSE = "/etc/screencapture/pause.svg";
static const std::string ICON_PATH_RESUME = "/etc/screencapture/play.svg";
static const std::string BACK_GROUND_COLOR = "#E84026";
static const std::string SYS_SCR_RECR_KEY = "const.multimedia.screencapture.screenrecorderbundlename";
static const std::string PERM_CUST_SCR_REC = "ohos.permission.CUSTOM_SCREEN_RECORDING";
static const std::string SHOW_TOUCH_HINT_KEY = "settings.app.show_touch_hint";
#ifdef PC_STANDARD
static const std::string SELECT_ABILITY_NAME = "SelectWindowAbility";
static const std::string TIMEOUT_SCREENOFF_DISABLE_LOCK = "ohos.permission.TIMEOUT_SCREENOFF_DISABLE_LOCK";
#endif
static const int32_t SVG_HEIGHT = 80;
static const int32_t SVG_WIDTH = 80;
static const uint32_t MIN_LINE_WIDTH = 1;
static const uint32_t MAX_LINE_WIDTH = 8;
static const uint32_t MAX_LINE_COLOR_RGB = 0xffffff;
static const uint32_t MIN_LINE_COLOR_ARGB = 0xff000000;
static const size_t MAX_DISPLAY_LEN = 1000;
static const uint32_t APPMISSIONID_WAIT_TIME = 3;
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    static const int32_t NOTIFICATION_MAX_TRY_NUM = 3;
#endif

static const auto NOTIFICATION_SUBSCRIBER = NotificationSubscriber();
static constexpr int32_t AUDIO_CHANGE_TIME = 80000; // 80 ms
static const int32_t UNSUPPORT_ERROR_CODE_API_VERSION_ISOLATION = 20;
static constexpr std::array<uint32_t, 7> STATE_CAPS_ = {
    CAP_INIT | CAP_CONFIG | CAP_ALIVE,
    CAP_ALIVE | CAP_POPUP,
    CAP_ALIVE,
    CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE,
    CAP_ALIVE | CAP_PAUSED | CAP_ACTIVE,
    CAP_ALIVE | CAP_RUNNING | CAP_ACTIVE,
    CAP_INIT,
};

template <typename T> static std::string JoinVector(const std::vector<T> &vec, const std::string_view &separator = ",")
{
    std::ostringstream oss;
    for (size_t i = 0; i < vec.size(); ++i) {
        oss << vec[i];
        if (i < vec.size() - 1) {
            oss << separator;
        }
    }
    return oss.str();
}

static std::string JsonToString(const Json::Value &root)
{
    Json::StreamWriterBuilder builder;
    std::string comStr = Json::writeString(builder, root);
    return comStr;
}

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
    std::string buttonName = buttonOption->GetButtonName();
    MEDIA_LOGI("OnResponse notificationId:%{public}d ButtonName:%{public}s", notificationId, buttonName.c_str());

    auto server = ScreenCaptureServerManager::GetInstance().GetScreenCaptureServerById(notificationId).lock();
    if (server != nullptr) {
        server->HandleNotificationButtonResponse(buttonName);
    }
}

void NotificationSubscriber::OnDied()
{
    MEDIA_LOGI("NotificationSubscriber OnDied");
}

void ScreenCaptureServer::HandleNotificationButtonResponse(const std::string &buttonName)
{
    if (buttonName == BUTTON_NAME_STOP) {
        StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
    } else if (buttonName == BUTTON_NAME_PAUSE) {
        PauseScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_PAUSED_BY_USER);
    } else if (buttonName == BUTTON_NAME_RESUME) {
        ResumeScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_RESUMED_BY_USER);
    } else if (buttonName == BUTTON_NAME_MIC) {
        UpdateMicrophoneEnabled();
    } else {
        MEDIA_LOGW("HandleNotificationButtonResponse unknown button:%{public}s", buttonName.c_str());
    }
}

bool ScreenCaptureServer::IsCaptureScreen(uint64_t displayId)
{
    return std::find(sourceDisplayIds_.begin(), sourceDisplayIds_.end(), displayId) != sourceDisplayIds_.end();
}

void ScreenCaptureServer::NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent event,
    ScreenCaptureRect* area)
{
    if (IsState(CAP_ALIVE)) {
        MEDIA_LOGI("NotifyCaptureContentChanged event: %{public}d", event);
        curWindowEvent_ = event;
        cbProxy_->OnCaptureContentChanged(event, area);
    }
}

void ScreenCaptureServer::OnCaptureContentChanged(bool isMirrorChanged)
{
    MEDIA_LOGI("OnCaptureContentChanged, displayId: %{public}" PRIu64 " event: %{public}d, lifecycle: %{public}d",
        curWindowInDisplayId_.load(), static_cast<int32_t>(curWindowEvent_), static_cast<int32_t>(curWindowLifecycle_));
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    if (!IsCaptureScreen(curWindowInDisplayId_.load())) {
        MEDIA_LOGI("OnCaptureContentChanged is in capture screen %{public}d", isMirrorChanged);
        if (isMirrorChanged || curWindowEvent_ == AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE) {
            return;
        }
        NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_HIDE, nullptr);
        return;
    }
    CHECK_AND_RETURN_LOG(curWindowLifecycle_ == SessionLifecycleEvent::FOREGROUND,
        "OnCaptureContentChanged dms event and not foreground");
    WindowInfoOption windowInfoOption;
    std::vector<sptr<WindowInfo>> infos;
    if (interestWindowId_ == -1) {
        return;
    }
    windowInfoOption.windowId = interestWindowId_;
    auto ret = Rosen::WindowManager::GetInstance().ListWindowInfo(windowInfoOption, infos);
    CHECK_AND_RETURN_LOG(ret == Rosen::WMError::WM_OK && !infos.empty() && infos.front() != nullptr,
        "ListWindowInfo failed.");
    CHECK_AND_RETURN(curWindowEvent_ != AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE);
    NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE,
        reinterpret_cast<ScreenCaptureRect *>(&(infos.front()->windowLayoutInfo.rect)));
}

std::shared_ptr<IScreenCaptureService> ScreenCaptureServer::Create(
    std::unique_ptr<IScreenCaptureServiceProviders> providers)
{
    MEDIA_LOGI("ScreenCaptureServer Create start.");
    auto& mgr = ScreenCaptureServerManager::GetInstance();
    int32_t id = mgr.GetNewSessionId();
    CHECK_AND_RETURN_RET_LOG(id != -1, nullptr, "GetNewSessionId failed.");
    auto server = std::make_shared<ScreenCaptureServer>(std::move(providers));
    CHECK_AND_RETURN_RET_LOG(server != nullptr, nullptr, "Failed to create ScreenCaptureServer.");
    server->sessionId_ = id;
    server->GetAndSetAppVersion();
    server->listenerManager_ = std::make_shared<ScreenCaptureListenerManager>(server, server->providers_.get());
    mgr.RegisterServer(id, server, server->appInfo_.appUid);
    return std::static_pointer_cast<IScreenCaptureService>(server);
}

int32_t ScreenCaptureServer::SetAndCheckSaLimit(OHOS::AudioStandard::AppInfo &appInfo)
{
    MEDIA_LOGI("SetAndCheckSaLimit START.");
    const int32_t saUid = IPCSkeleton::GetCallingUid();
    std::lock_guard<std::mutex> lock(mutex_);
    if (!ScreenCaptureServerManager::GetInstance().IsSAUidValid(saUid, appInfo.appUid)) {
        MEDIA_LOGE("SetAndCheckSaLimit failed, saUid-appUid exists.");
        saUid_ = -1;
        return MSERR_INVALID_OPERATION;
    }
    appInfo_.appUid = appInfo.appUid;
    appInfo_.appPid = appInfo.appPid;
    appInfo_.appTokenId = appInfo.appTokenId;
    appInfo_.appFullTokenId = appInfo.appFullTokenId;
    appName_ = GetClientBundleName(appInfo_.appUid);
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(appInfo_.appUid, userId);
    appUserId_.store(userId);
    isSystemRecorder_.store(GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] == appName_);
    ScreenCaptureServerManager::GetInstance().UpdateServerAppUid(sessionId_, appInfo_.appUid);
    ScreenCaptureServerManager::GetInstance().AddSaAppInfoMap(saUid, appInfo_.appUid);
    if (!ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(appInfo.appUid)) {
        MEDIA_LOGE("SetAndCheckSaLimit failed, cannot create ScreenCapture Instance.");
        saUid_ = -1;
        return MSERR_INVALID_OPERATION;
    }
    saUid_ = saUid;
    MEDIA_LOGI("SetAndCheckSaLimit SUCCESS! appUid: %{public}d, saUid: %{public}d", appInfo.appUid, saUid_);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetAndCheckLimit()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetAndCheckLimit START.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(
        ScreenCaptureServerManager::GetInstance().CanScreenCaptureInstanceBeCreate(IPCSkeleton::GetCallingUid()),
        MSERR_INVALID_OPERATION, "SetAndCheckLimit failed, cannot create ScreenCapture Instance.");
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
    MEDIA_LOGI("GetValueFromJson key=%{public}s value=%{public}d", key.c_str(), value);
}

void ScreenCaptureServer::SetCaptureConfig(CaptureMode captureMode, int32_t missionId)
{
    captureConfig_.captureMode = captureMode;
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    missionInfos_.clear();
    if (missionId != -1) { // -1 无效值
        missionInfos_.push_back({static_cast<uint64_t>(missionId), true});
    }
}

void ScreenCaptureServer::PrepareSelectWindow(Json::Value &root)
{
    if (root.type() != Json::objectValue) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        missionInfos_.clear();
    }
    UpdateHighlightOutline(false);
    ParseDisplayId(root["displayId"]);
    const Json::Value missionIdJson = root["missionId"];
    if (!missionIdJson.isNull() && missionIdJson.isInt() && missionIdJson.asInt() >= 0) {
        int32_t missionId = missionIdJson.asInt();
        MEDIA_LOGI("Report Select MissionId: %{public}d", missionId);
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_WINDOW, missionId);
    }
    if (ParseAppMissionIds(root["appInformation"]) == MSERR_OK) {
        FinishPrepareSelectWindow();
    }
}

void ScreenCaptureServer::FinishPrepareSelectWindow()
{
    UpdateHighlightOutline(true);
    ScreenCaptureUserSelectionInfo selectionInfo;
    bool isApp;
    {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        isApp = !missionInfos_.empty();
    }
    if (isApp || captureConfig_.captureMode == CaptureMode::CAPTURE_SPECIFIED_WINDOW) {
        selectionInfo.selectType = isApp ? SELECT_TYPE_APP : SELECT_TYPE_WINDOW;
        selectionInfo.displayIds = {GetDisplayIdOfWindows()};
    } else {
        selectionInfo.selectType = SELECT_TYPE_SCREEN;
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        selectionInfo.displayIds = displayIds_;
    }
    cbProxy_->OnUserSelected(selectionInfo);
    OnReceiveUserPrivacyAuthority(true);
}

int32_t ScreenCaptureServer::ReportAVScreenCaptureUserChoice(const std::string &content)
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice captureState_ is %{public}d", captureState_.load());

    Json::Value root;
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    if (IsPickerPopUp() && isPresentPickerPopWindow_ && IsState(CAP_RUNNING)) {
        return HandlePresentPickerWindowCase(root, content);
    }
#endif
    if (IsState(CAP_POPUP)) {
        return HandlePopupWindowCase(root, content);
    }
    CHECK_AND_RETURN_RET(captureConfig_.dataType != DataType::ORIGINAL_STREAM || !IsState(CAP_RUNNING),
        HandleStreamDataCase(root, content));
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
    NotifyprivacyProtect();
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice checkBoxSelected: %{public}d", checkBoxSelected_);

    if (showShareSystemAudioBox_) {
        GetValueFromJson(root, content, std::string("isInnerAudioBoxSelected"), isInnerAudioBoxSelected_);
    }
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice showShareSystemAudioBox: %{public}d,"
        "isInnerAudioBoxSelected: %{public}d", showShareSystemAudioBox_,
        isInnerAudioBoxSelected_);

    if (USER_CHOICE_ALLOW.compare(choice) == 0) {
        PrepareSelectWindow(root);
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
    bool appPrivacyProtectionSwitch = false;
    bool systemPrivacyProtectionSwitch = false;
    GetValueFromJson(root, content, std::string("stopRecording"), stopRecord);
    if (stopRecord) {
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER);
        MEDIA_LOGI("ReportAVScreenCaptureUserChoice user stop record");
        return MSERR_OK;
    }

    GetValueFromJson(root, content, std::string("appPrivacyProtectionSwitch"),
        appPrivacyProtectionSwitch);
    GetValueFromJson(root, content, std::string("systemPrivacyProtectionSwitch"),
        systemPrivacyProtectionSwitch);
    if (appPrivacyProtectionSwitch != appPrivacyProtectionSwitch_ ||
        systemPrivacyProtectionSwitch != systemPrivacyProtectionSwitch_) {
        appPrivacyProtectionSwitch_ = appPrivacyProtectionSwitch;
        systemPrivacyProtectionSwitch_ = systemPrivacyProtectionSwitch;
        NotifyprivacyProtect();
    }

    PrivacyProtected(virtualScreenId_, systemPrivacyProtectionSwitch_, appPrivacyProtectionSwitch_);

    NotificationRequest request;
    UpdateLiveViewPrivacy();
    SetupPublishRequest(request);
    return NotificationHelper::PublishNotification(request);
}

int32_t ScreenCaptureServer::HandlePresentPickerWindowCase(Json::Value& root, const std::string &content)
{
    std::string choice = "false";
    GetChoiceFromJson(root, content, std::string("choice"), choice);
    MEDIA_LOGI("HandlePresentPickerWindowCase dataType: %{public}d, choice: %{public}s, mode: %{public}d",
        captureConfig_.dataType, choice.c_str(), captureConfig_.captureMode);
    isPresentPickerPopWindow_ = false;
    if (choice != USER_CHOICE_ALLOW) {
        MEDIA_LOGI("HandlePresentPickerWindowCase user choice is not allow");
        return MSERR_OK;
    }
    PrepareSelectWindow(root);
    DestroyVirtualScreen();
    listenerManager_->UnregisterListeners(LF_WIN_LIFECYCLE | LF_WIN_INFO | LF_SCREEN_CONN | LF_APP_LIFECYCLE);
    int32_t ret = MSERR_OK;
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        auto consumerSurface = isSurfaceMode_ ? surface_ : producerSurface_;
        ret = CreateVirtualScreen(consumerSurface);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen surface failed, ret: %{public}d", ret);
    } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        ret = CreateVirtualScreen(consumer_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen file failed, ret: %{public}d", ret);
    } else {
        MEDIA_LOGE("HandlePresentPickerWindowCase dataType is invalid");
        return MSERR_UNKNOWN;
    }
    uint32_t listenerFlags = LF_SCREEN_CONN;
    ListenerRegisterParams params;
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        if (missionInfos_.size() == 1) {
            interestWindowId_ = static_cast<int32_t>(missionInfos_.front().missionId);
            curWindowLifecycle_ = SessionLifecycleEvent::FOREGROUND;
            curWindowEvent_ = AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE;
            listenerFlags |= LF_WIN_LIFECYCLE | LF_WIN_INFO;
            params.windowIdList = {interestWindowId_};
        }
    }
    ret = listenerManager_->RegisterListeners(listenerFlags, params);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "HandlePresentPickerWindowCase RegisterListeners failed");
    return ret;
}

int32_t ScreenCaptureServer::ParseAppMissionIds(const Json::Value &appInformation)
{
    MediaTrace trace("ScreenCaptureServer::ParseAppMissionIds");
    MEDIA_LOGI("ParseAppMissionIds start.");
    CHECK_AND_RETURN_RET_LOG(!appInformation.isNull(), MSERR_OK, "appInformation isNull");
    const Json::Value bundleNameJson = appInformation["bundleName"];
    const Json::Value appIndexJson = appInformation["appIndex"];
    CHECK_AND_RETURN_RET_LOG(bundleNameJson.isString() && appIndexJson.isInt(), MSERR_OK,
        "bundleNameJson or appIndexJson isNull");

    int32_t ret = listenerManager_->RegisterListeners(LF_APP_LIFECYCLE,
        {.appBundleName = bundleNameJson.asString(), .appIndex = appIndexJson.asInt()});
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_OK, "RegisterListeners LF_APP_LIFECYCLE failed");
    SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_APP, -1);
    isGetAppMissionId_ = false;
    auto timeoutTask = std::make_shared<TaskHandler<void>>([this] {
        if (isGetAppMissionId_) { return; }
        MEDIA_LOGE("ParseAppMissionIds timeout");
        PostStartScreenCaptureFail();
    });
    taskQue_.EnqueueTask(timeoutTask, false, APPMISSIONID_WAIT_TIME * 1000000ULL);
    return MSERR_INVALID_OPERATION;
}

void ScreenCaptureServer::ParseDisplayId(const Json::Value &displayIdJson)
{
    if (displayIdJson.isUInt64()) {
        auto displayId = static_cast<uint64_t>(displayIdJson.asUInt64());
        MEDIA_LOGI("Report Select DisplayId: %{public}" PRIu64, displayId);
        SetDisplayId(displayId);
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_SCREEN, -1);
        return;
    }
    if (displayIdJson.isArray()) {
        std::vector<uint64_t> displayIds;
        for (const auto &idJson : displayIdJson) {
            if (!idJson.isUInt64()) {
                continue;
            }
            displayIds.emplace_back(static_cast<uint64_t>(idJson.asUInt64()));
        }
        SetDisplayId(std::move(displayIds));
        SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_SCREEN, -1);
        return;
    }
}


int32_t ScreenCaptureServer::PresentPicker()
{
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
#ifdef PC_STANDARD
    if (!IsPickerPopUp()) {
        MEDIA_LOGE("PresentPicker not support picker.");
        return MSERR_INVALID_OPERATION_PRESENT;
    }
#endif
    if (!IsState(CAP_RUNNING)) {
        MEDIA_LOGE("PresentPicker captureState_ is not STARTED, not allowed.");
        return MSERR_INVALID_OPERATION_STARTED;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PresentPicker start.", FAKE_POINTER(this));
    MediaTrace trace("ScreenCaptureServer::PresentPicker");
    std::lock_guard<std::mutex> lock(mutex_);
    isPresentPickerPopWindow_ = true;
    showShareSystemAudioBox_ = false;
    showSensitiveCheckBox_ = false;
    int32_t ret = StartPicker();
    return ret;
#endif
    return MSERR_INVALID_OPERATION_UNSUPPORT;
}

int32_t ScreenCaptureServer::GetAVScreenCaptureConfigurableParameters(std::string &resultStr)
{
    MEDIA_LOGI("GetAVScreenCaptureConfigurableParameters");
    Json::Value root;
    root["appPrivacyProtectionSwitch"] = appPrivacyProtectionSwitch_.load();
    root["systemPrivacyProtectionSwitch"] = systemPrivacyProtectionSwitch_.load();
    Json::FastWriter fastWriter;
    resultStr = fastWriter.write(root);
    MEDIA_LOGI("GetAVScreenCaptureConfigurableParameters res: %{public}s", resultStr.c_str());
    return MSERR_OK;
}

bool ScreenCaptureServer::IsMicrophoneSwitchTurnOn()
{
    return isMicrophoneSwitchTurnOn_;
}

bool ScreenCaptureServer::IsSCRecorderFileWithVideo()
{
    return recorderFileWithVideo_.load();
}

bool ScreenCaptureServer::IsStopAcquireAudioBufferFlag()
{
    return stopAcquireAudioBufferFromAudio_.load();
}

void ScreenCaptureServer::SetDisplayId(uint64_t displayId)
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    displayIds_.clear();
    displayIds_.emplace_back(displayId);
}

void ScreenCaptureServer::SetDisplayId(std::vector<uint64_t> &&displayIds)
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    displayIds_ = std::move(displayIds);
}

DMError ScreenCaptureServer::CreateMirror(const std::vector<uint64_t> &displayIds, std::vector<ScreenId> &mirrorIds)
{
    ScreenId mirrorGroup = 0;
#ifdef PC_STANDARD
    if (IsHopper() && captureConfig_.strategy.enableDeviceLevelCapture == false) {
        return Rosen::ScreenManager::GetInstance().MakeMirrorForRecord(displayIds, mirrorIds, mirrorGroup);
    }
#endif
    CHECK_AND_RETURN_RET(displayIds.size() == 1, DMError::DM_ERROR_INVALID_PARAM);
    if (!IsState(CAP_ACTIVE)) {
        sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDisplayById(displayIds.front());
        if (display != nullptr) {
            targetRotation_ = display->GetRotation();
        }
    } else if (IsState(CAP_PAUSED) && !canvasRotation_) {
        return Rosen::ScreenManager::GetInstance().MakeMirror(displayIds.front(), mirrorIds, mirrorGroup,
            targetRotation_);
    }
    return Rosen::ScreenManager::GetInstance().MakeMirror(displayIds.front(), mirrorIds, mirrorGroup);
}

void ScreenCaptureServer::ChangeMirrorScreen()
{
    CHECK_AND_RETURN_LOG(virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID,
        "ChangeMirrorScreen failed, invalid screenId");
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    CHECK_AND_RETURN_LOG(!displayIds_.empty(), "displayIds_ is empty");
    uint64_t displayId = displayIds_.front();
    CHECK_AND_RETURN_LOG(!IsCaptureScreen(displayId), "ChangeMirrorScreen have missionId in capture screen");
    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(virtualScreenId_);
    Rosen::ScreenManager::GetInstance().StopMirror(mirrorIds);
    DMError ret = CreateMirror(displayIds_, mirrorIds);
    CHECK_AND_RETURN_LOG(ret == DMError::DM_OK, "ChangeMirrorScreen failed, ret:%{public}d", ret);
    MEDIA_LOGI("ChangeMirrorScreen success, screenId:%{public}" PRIu64, displayId);
    sourceDisplayIds_ = displayIds_;
}

void ScreenCaptureServer::NotifyWindowVisible(uint64_t missionId)
{
    CHECK_AND_RETURN_LOG(missionId <= static_cast<uint64_t>(std::numeric_limits<int32_t>::max()), "");
    WindowInfoOption opt;
    opt.windowId = static_cast<int32_t>(missionId);
    std::vector<sptr<WindowInfo>> infos;
    auto ret = Rosen::WindowManager::GetInstance().ListWindowInfo(opt, infos);
    CHECK_AND_RETURN_LOG(ret == Rosen::WMError::WM_OK && !infos.empty() && infos.front() != nullptr, "");
    NotifyCaptureContentChanged(AVScreenCaptureContentChangedEvent::SCREEN_CAPTURE_CONTENT_VISIBLE,
        reinterpret_cast<ScreenCaptureRect *>(&(infos.front()->windowLayoutInfo.rect)));
}

uint8_t ScreenCaptureServer::UpdateMissionData(uint64_t missionId, Rosen::SessionState state,
    std::vector<uint64_t> &allIds)
{
    uint8_t flags = 0;
    {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        auto it = std::find_if(missionInfos_.begin(), missionInfos_.end(),
            [missionId](const MissionInfo &m) { return m.missionId == missionId; });
        switch (state) {
            case Rosen::SessionState::STATE_FOREGROUND:
            case Rosen::SessionState::STATE_ACTIVE:
                if (it == missionInfos_.end()) {
                    missionInfos_.push_back({missionId, true});
                    flags |= ADD_WHITE_LIST | NOTIFY_VISIBLE;
                } else {
                    it->isForeground = true;
                }
                break;
            case Rosen::SessionState::STATE_BACKGROUND:
                if (it != missionInfos_.end() && it->isForeground) {
                    it->isForeground = false;
                    flags |= UPDATE_MIRROR;
                }
                break;
            case Rosen::SessionState::STATE_DISCONNECT:
                if (it != missionInfos_.end()) {
                    if (it->isForeground) { flags |= UPDATE_MIRROR; }
                    missionInfos_.erase(it);
                    if (missionInfos_.empty()) { flags |= NOTIFY_UNAVAILABLE; }
                }
                flags |= REMOVE_WHITE_LIST;
                break;
            default:
                break;
        }
        for (const auto &m : missionInfos_) { allIds.push_back(m.missionId); }
    }
    return flags;
}

bool ScreenCaptureServer::IsState(uint32_t cap) const
{
    return (STATE_CAPS_[captureState_.load()] & cap) != 0;
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

void ScreenCaptureServer::SetMediaKitReport(const std::string &apiCall)
{
    nlohmann::json metaInfoJson;
    metaInfoJson["captureMode"] =  captureConfig_.captureMode;
    metaInfoJson["dataType"] =  std::to_string(captureConfig_.dataType);
    metaInfoJson["videoCapDisplayId"] =  captureConfig_.videoInfo.videoCapInfo.displayId;
    metaInfoJson["videoFrameWidth"] =  captureConfig_.videoInfo.videoCapInfo.videoFrameWidth;
    metaInfoJson["videoFrameHeight"] =  captureConfig_.videoInfo.videoCapInfo.videoFrameHeight;
    metaInfoJson["videoSourceType"] =  captureConfig_.videoInfo.videoCapInfo.videoSource;
    metaInfoJson["videoCapState"] =  captureConfig_.videoInfo.videoCapInfo.state;
    metaInfoJson["videoCodec"] =  captureConfig_.videoInfo.videoEncInfo.videoCodec;
    metaInfoJson["videoBitrate"] =  captureConfig_.videoInfo.videoEncInfo.videoBitrate;
    metaInfoJson["videoFrameRate"] =  captureConfig_.videoInfo.videoEncInfo.videoFrameRate;
    metaInfoJson["videoEncState"] =  captureConfig_.videoInfo.videoEncInfo.state;
    metaInfoJson["micAudioSampleRate"] =  captureConfig_.audioInfo.micCapInfo.audioSampleRate;
    metaInfoJson["micChannels"] =  captureConfig_.audioInfo.micCapInfo.audioChannels;
    metaInfoJson["micAudioSource"] =  captureConfig_.audioInfo.micCapInfo.audioSource;
    metaInfoJson["micState"] =  captureConfig_.audioInfo.micCapInfo.state;
    metaInfoJson["innerAudioSampleRate"] =  captureConfig_.audioInfo.innerCapInfo.audioSampleRate;
    metaInfoJson["innerChannels"] =  captureConfig_.audioInfo.innerCapInfo.audioChannels;
    metaInfoJson["innerAudioSource"] =  captureConfig_.audioInfo.innerCapInfo.audioSource;
    metaInfoJson["innerState"] =  captureConfig_.audioInfo.innerCapInfo.state;
    metaInfoJson["audioBitrate"] =  captureConfig_.audioInfo.audioEncInfo.audioBitrate;
    metaInfoJson["audioCodecformat"] =  captureConfig_.audioInfo.audioEncInfo.audioCodecformat;
    metaInfoJson["audioEncState"] =  captureConfig_.audioInfo.audioEncInfo.state;
    metaInfoJson["recorderFileFormat"] =  captureConfig_.recorderInfo.fileFormat;
    metaInfoJson["enableDeviceLevelCapture"] =  captureConfig_.strategy.enableDeviceLevelCapture;
    metaInfoJson["keepCaptureDuringCall"] =  captureConfig_.strategy.keepCaptureDuringCall;
    metaInfoJson["strategyForPrivacyMaskMode"] =  captureConfig_.strategy.strategyForPrivacyMaskMode;
    metaInfoJson["canvasFollowRotation"] =  captureConfig_.strategy.canvasFollowRotation;
    metaInfoJson["enableBFrame"] =  captureConfig_.strategy.enableBFrame;
    metaInfoJson["setByUser"] =  captureConfig_.strategy.setByUser;
    metaInfoJson["pickerPopUp"] =  captureConfig_.strategy.pickerPopUp;
    metaInfoJson["fillMode"] =  captureConfig_.strategy.fillMode;
    metaInfoJson["highlightLineThickness"] =  captureConfig_.highlightConfig.lineThickness;
    metaInfoJson["highlightLineColor"] =  captureConfig_.highlightConfig.lineColor;
    metaInfoJson["highlightMode"] =  captureConfig_.highlightConfig.mode;
    std::string instanceIdStr =  std::to_string(instanceId_);
    OHOS::Media::MediaEvent event;
    std::string events = metaInfoJson.dump();
    event.MediaKitStatistics("AVScreenCapture", appName_, instanceIdStr, apiCall, events);
}

ScreenCaptureServer::ScreenCaptureServer(std::unique_ptr<IScreenCaptureServiceProviders> providers)
    : providers_(std::move(providers))
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ScreenCaptureServer Instances create", FAKE_POINTER(this));
    cbProxy_ = std::make_shared<ScreenCaptureCallbackProxy>();
    InitAppInfo();
    instanceId_ = OHOS::HiviewDFX::HiTraceChain::GetId().GetChainId();
    CreateMediaInfo(SCREEN_CAPTRUER, IPCSkeleton::GetCallingUid(), instanceId_);
    taskQue_.Start();
}

ScreenCaptureServer::~ScreenCaptureServer()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " ScreenCaptureServer Instances destroy", FAKE_POINTER(this));
    ReleaseInner();
    CloseFd();
    taskQue_.Stop();
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
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION,
        "SetCaptureMode failed, cannot config in current state:%{public}d", captureState_.load());
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
    int32_t appUid;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
            "SetDataType failed, cannot config in current state:%{public}d", captureState_.load());
        MEDIA_LOGI("ScreenCaptureServer::SetDataType start, dataType:%{public}d", dataType);
        int32_t ret = CheckDataType(dataType);
        CHECK_AND_RETURN_RET(ret == MSERR_OK, ret);
        std::unique_lock<std::shared_mutex> configLock(captureConfigMutex_);
        captureConfig_.dataType = dataType;
        appUid = appInfo_.appUid;
    }
    ScreenCaptureServerManager::GetInstance().UpdateServerDataType(sessionId_, dataType);
    CHECK_AND_RETURN_RET_LOG(
        ScreenCaptureServerManager::GetInstance().CheckSCServerSpecifiedDataTypeNum(appUid, dataType),
        MSERR_INVALID_OPERATION_OVERSIZE, "ScreenCaptureServer: 0x%{public}06" PRIXPTR "SetDataType failed.",
        FAKE_POINTER(this));
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetDataType OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetRecorderInfo(RecorderInfo recorderInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "SetRecorderInfo failed, capture is not CREATED, state:%{public}d", captureState_.load());
    MEDIA_LOGI("ScreenCaptureServer::SetRecorderInfo start");
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
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "SetOutputFile failed, capture is not CREATED, state:%{public}d", captureState_.load());
    MEDIA_LOGI("ScreenCaptureServer::SetOutputFile start");
    if (outputFd < 0) {
        MEDIA_LOGI("invalid outputFd");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_,
            SCREEN_CAPTURE_ERR_INVALID_VAL, "invalid outputFd");
        return MSERR_INVALID_FD;
    }

    int flags = fcntl(outputFd, F_GETFL);
    if (flags == -1) {
        MEDIA_LOGE("Fail to get File Status Flags");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "Fail to get File Status Flags");
        return MSERR_INVALID_FD;
    }
    if ((static_cast<unsigned int>(flags) & (O_RDWR | O_WRONLY)) == 0) {
        MEDIA_LOGE("File descriptor is not in read-write mode or write-only mode");
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_INVALID_VAL,
            "File descriptor is not in read-write mode or write-only mode");
        return MSERR_INVALID_WRITE;
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
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION,
        "SetScreenCaptureCallback failed, capture is not CREATED, state:%{public}d", captureState_.load());
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, MSERR_INVALID_VAL,
        "SetScreenCaptureCallback failed, callback is nullptr, state:%{public}d", captureState_.load());
    MEDIA_LOGI("ScreenCaptureServer::SetScreenCaptureCallback start");
    cbProxy_->SetCallback(callback);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenCaptureCallback OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitAudioEncInfo(AudioEncInfo audioEncInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "InitAudioEncInfo failed, capture is not CREATED, state:%{public}d", captureState_.load());
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
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "InitVideoEncInfo failed, capture is not CREATED, state:%{public}d", captureState_.load());
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
    CHECK_AND_RETURN_RET_LOG(result == Security::AccessToken::PERMISSION_GRANTED, false,
        "user do not have the right to access capture screen!");
    return true;
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
    if ((captureMode > CAPTURE_VIRTUAL_EXTENDED_SCREEN) || (captureMode < CAPTURE_HOME_SCREEN)) {
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
    auto supportedSamplingRates = AudioStandard::AudioCapturer::GetSupportedSamplingRates();
    bool foundSupportSample = std::any_of(supportedSamplingRates.begin(), supportedSamplingRates.end(),
        [&audioCapInfo](
            const AudioSamplingRate &rate) { return audioCapInfo.audioSampleRate == static_cast<int32_t>(rate); });
    if (!foundSupportSample) {
        MEDIA_LOGE("invalid audioSampleRate:%{public}d", audioCapInfo.audioSampleRate);
        return MSERR_UNSUPPORT_AUD_SAMPLE_RATE;
    }

    auto supportedChannelList = AudioStandard::AudioCapturer::GetSupportedChannels();
    bool foundSupportChannel = std::any_of(supportedChannelList.begin(), supportedChannelList.end(),
        [&audioCapInfo](
            const AudioChannel &channel) { return audioCapInfo.audioChannels == static_cast<int32_t>(channel); });
    if (!foundSupportChannel) {
        MEDIA_LOGE("invalid audioChannels:%{public}d", audioCapInfo.audioChannels);
        return MSERR_UNSUPPORT_AUD_CHANNEL_NUM;
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
        return MSERR_INVALID_VID_FRAME_WIDTH;
    }
    if ((videoCapInfo.videoFrameHeight <= 0) || (videoCapInfo.videoFrameHeight > VIDEO_FRAME_HEIGHT_MAX)) {
        MEDIA_LOGE("videoCapInfo Height is invalid, videoFrameWidth:%{public}d, videoFrameHeight:%{public}d",
            videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight);
        return MSERR_INVALID_VID_FRAME_HEIGHT;
    }

    if (videoCapInfo.videoSource != VIDEO_SOURCE_SURFACE_RGBA) {
        MEDIA_LOGE("invalid videoSource:%{public}d, must be VIDEO_SOURCE_SURFACE_RGBA", videoCapInfo.videoSource);
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
        return MSERR_INVALID_AUD_BITRATE;
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
        return MSERR_INVALID_VID_CODEC_FORMAT;
    }
    if (videoEncInfo.videoBitrate < VIDEO_BITRATE_MIN || videoEncInfo.videoBitrate > VIDEO_BITRATE_MAX) {
        MEDIA_LOGE("invalid videoBitrate:%{public}d", videoEncInfo.videoBitrate);
        return MSERR_INVALID_VID_BITRATE;
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
        isSurfaceMode_.load() ? "true" : "false", captureConfig_.videoInfo.videoCapInfo.state,
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
    int32_t userId = -1;
    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(appInfo_.appUid, userId);
    appUserId_.store(userId <= 0 ? -1 : userId);
    isSystemRecorder_.store(GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] == appName_);
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
        return StartAuthWindow();
    }

    MEDIA_LOGI("privacy notification window not support, go on to check CAPTURE_SCREEN permission");
    return CheckScreenCapturePermission() ? MSERR_OK : MSERR_INVALID_OPERATION;
}

int32_t ScreenCaptureServer::OnReceiveUserPrivacyAuthority(bool isAllowed)
{
    // Should callback be running in seperate thread?
    MEDIA_LOGI("OnReceiveUserPrivacyAuthority start, isAllowed:%{public}d, state:%{public}d",
        isAllowed, captureState_.load());
    if (!IsState(CAP_POPUP)) {
        MEDIA_LOGE("OnReceiveUserPrivacyAuthority failed, capture is not POPUP_WINDOW");
        cbProxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
            AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
        SetMediaKitReport("startRecording fail");
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
        return MSERR_UNKNOWN;
    }
    if (!isAllowed) {
        captureState_ = AVScreenCaptureState::CREATED;
        cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_CANCELED);
        return MSERR_UNKNOWN;
    }
    int32_t ret = OnStartScreenCapture();
    PostStartScreenCapture(ret == MSERR_OK);
    return ret;
}

std::string ScreenCaptureServer::GenerateThreadNameByPrefix(std::string threadName)
{
    return threadName + std::to_string(sessionId_);
}

int32_t ScreenCaptureServer::StartInnerAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartInnerAudioCapture start, dataType:%{public}d, "
        "innerCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.innerCapInfo.state);
    CHECK_AND_RETURN_RET(!(innerAudioCapture_ && innerAudioCapture_->IsRecording()), MSERR_OK);
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        if (innerAudioCapture_ == nullptr) {
            std::string threadName = captureConfig_.dataType == DataType::ORIGINAL_STREAM
                ? GenerateThreadNameByPrefix("OS_SInnAd")
                : GenerateThreadNameByPrefix("OS_FInnAd");
            innerAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
                captureConfig_.audioInfo.innerCapInfo, cbProxy_, std::move(threadName), contentFilter_);
            CHECK_AND_RETURN_RET_LOG(innerAudioCapture_ != nullptr, MSERR_UNKNOWN, "CreateInnerAudioCapture failed");
        }
        MediaTrace trace("ScreenCaptureServer::StartInnerAudioCapture");
        int32_t ret = innerAudioCapture_->Start(appInfo_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartInnerAudioCapture failed");
        if (showShareSystemAudioBox_ && !isInnerAudioBoxSelected_) {
            innerAudioCapture_->SetIsMute(true);
        }
        if (audioSource_) {
            audioSource_->SetInnerCapture(innerAudioCapture_);
        }
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartInnerAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartScreenCaptureStream()
{
    MediaTrace trace("ScreenCaptureServer::StartScreenCaptureStream");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartScreenCaptureStream start, dataType:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType);
    CHECK_AND_RETURN_RET(captureConfig_.dataType == DataType::ORIGINAL_STREAM, MSERR_INVALID_OPERATION);
    ON_SCOPE_EXIT(0) { StopAudioCapture(); };
    int32_t ret = SyncAudioCaptures(true);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SyncAudioCaptures failed, ret:%{public}d", ret);
    ret = StartStreamVideoCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartStreamVideoCapture failed, ret:%{public}d", ret);
    CANCEL_SCOPE_EXIT_GUARD(0);
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

    ON_SCOPE_EXIT(1) { StopAudioCapture(); };
    ret = SyncAudioCaptures(true);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SyncAudioCaptures failed, ret:%{public}d", ret);
    MEDIA_LOGI("StartScreenCaptureFile RecorderServer S");
    ret = recorder_->Start();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "recorder start failed, ret:%{public}d", ret);
    ret = CreateVirtualScreen(consumer_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "CreateVirtualScreen failed, ret:%{public}d, dataType:%{public}d",
        ret, captureConfig_.dataType);
    CANCEL_SCOPE_EXIT_GUARD(1);
    CANCEL_SCOPE_EXIT_GUARD(0);

    MEDIA_LOGI("StartScreenCaptureFile E");
    return ret;
}

int32_t ScreenCaptureServer::OnStartScreenCapture(bool isSkipPrivacyWindow)
{
    MediaTrace trace("ScreenCaptureServer::OnStartScreenCapture");
    MEDIA_LOGI("OnStartScreenCapture start, dataType:%{public}d", captureConfig_.dataType);
    captureState_ = AVScreenCaptureState::STARTING;
    int32_t ret = MSERR_UNSUPPORT;
    if (isSkipPrivacyWindow && captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        int32_t missionId = -1;
        {
            std::lock_guard<std::mutex> lock(captureIdsMutex_);
            if (missionInfos_.size() == 1) {
                missionId = static_cast<int32_t>(missionInfos_.front().missionId);
            }
        }
        if (missionId != -1) {
            auto amsClient = AAFwk::AbilityManagerClient::GetInstance();
            if (amsClient) {
                auto aaRet = amsClient->MoveMissionToFront(missionId);
                MEDIA_LOGI("MoveMissionToFront missionId: %{public}d, ret: %{public}d", missionId, aaRet);
            } else {
                MEDIA_LOGE("Ability manager client is null");
            }
        }
    }
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
    MEDIA_LOGI("UpdateHighlightOutline enter. isStarted:%{public}d", static_cast<int32_t>(isStarted));
    if (IsSetHighlightConfig()) {
        Rosen::OutlineParams outlineParams;
        outlineParams.type_ = OutlineType::OUTLINE_FOR_WINDOW;
        SetHighlightConfigForWindowManager(isStarted, outlineParams);
        auto mediaService = GetMediaService();
        if (mediaService == nullptr) {
            MEDIA_LOGE("Get media service failed");
            return;
        }
        Rosen::WMError res = Rosen::WindowManager::GetInstance().UpdateOutline(mediaService, outlineParams);
        if (res == Rosen::WMError::WM_OK) {
            MEDIA_LOGI("UpdateHighlightOutline sussess");
        } else {
            MEDIA_LOGE("UpdateHighlightOutline failed:%{public}d", res);
        }
    }
}

bool ScreenCaptureServer::IsSetHighlightConfig()
{
    if (captureConfig_.highlightConfig.lineThickness < MIN_LINE_WIDTH ||
        captureConfig_.highlightConfig.lineThickness > MAX_LINE_WIDTH) {
        return false;
    }
    if (captureConfig_.highlightConfig.lineColor > MAX_LINE_COLOR_RGB &&
        captureConfig_.highlightConfig.lineColor < MIN_LINE_COLOR_ARGB) {
        return false;
    }
    if (captureConfig_.highlightConfig.mode != ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CLOSED &&
        captureConfig_.highlightConfig.mode != ScreenCaptureHighlightMode::HIGHLIGHT_MODE_CORNER_WRAP) {
        return false;
    }
    if (captureConfig_.captureMode != CaptureMode::CAPTURE_SPECIFIED_WINDOW) {
        return false;
    }
    return true;
}

void ScreenCaptureServer::SetHighlightConfigForWindowManager(bool isStarted,
    Rosen::OutlineParams &outlineParams)
{
    MEDIA_LOGI("SetHighlightConfigForWindowManager enter");
    outlineParams.persistentIds_.clear();
    if (isStarted) {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        uint64_t maxInt32 = static_cast<uint64_t>(std::numeric_limits<int32_t>::max());
        for (const auto &m : missionInfos_) {
            if (m.missionId > maxInt32) {
                MEDIA_LOGE("windowId is an incorrect value: %{public}" PRIu64, m.missionId);
                continue;
            }
            outlineParams.persistentIds_.push_back(static_cast<int32_t>(m.missionId));
        }
        outlineParams.outlineStyleParams_.outlineColor_ = captureConfig_.highlightConfig.lineColor;
        outlineParams.outlineStyleParams_.outlineWidth_ = captureConfig_.highlightConfig.lineThickness;
        outlineParams.outlineStyleParams_.outlineShape_ = ConvertToOutlineShape(captureConfig_.highlightConfig.mode);
    } else {
        outlineParams.outlineStyleParams_.outlineColor_ = OUTLINE_COLOR_DEFAULT;
        outlineParams.outlineStyleParams_.outlineWidth_ = OUTLINE_WIDTH_DEFAULT;
        outlineParams.outlineStyleParams_.outlineShape_ = OutlineShape::OUTLINE_SHAPE_FOUR_CORNERS;
    }
    MEDIA_LOGI("SetHighlightConfigForWindowManager, lineColor:0x%{public}x, lineThickness:%{public}dvp, "
        "mode:%{public}d", outlineParams.outlineStyleParams_.outlineColor_,
        outlineParams.outlineStyleParams_.outlineWidth_, outlineParams.outlineStyleParams_.outlineShape_);
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

void ScreenCaptureServer::PostStartScreenCaptureSuccessAction()
{
    std::unordered_map<std::string, std::string> payload;
    int64_t value = ResourceSchedule::ResType::ScreenCaptureStatus::START_SCREEN_CAPTURE;
    ResSchedReportData(value, payload);
    captureState_ = AVScreenCaptureState::STARTED;
    if (isSystemRecorder_.load()) {
        providers_->GetScreenCaptureMonitor().SetSystemScreenRecorderPid(appInfo_.appPid);
    }
    providers_->GetScreenCaptureMonitor().CallOnScreenCaptureStarted(appInfo_.appPid);
    cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
    uint64_t selectedDisplayId = SCREEN_ID_INVALID;
    {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        if (!sourceDisplayIds_.empty() && sourceDisplayIds_.front() != SCREEN_ID_INVALID) {
            selectedDisplayId = sourceDisplayIds_.front();
        }
    }
    if (selectedDisplayId != SCREEN_ID_INVALID) {
        cbProxy_->OnDisplaySelected(selectedDisplayId);
    }
}

bool ScreenCaptureServer::IsFirstStartPidInstance(int32_t pid)
{
    std::list<int32_t> pidList = providers_->GetScreenCaptureMonitor().IsScreenCaptureWorking();
    bool isFirst = find(pidList.begin(), pidList.end(), pid) == pidList.end();
    MEDIA_LOGD("IsFirstStartPidInstance pid: %{public}d, isFirst: %{public}d", pid, isFirst);
    return isFirst;
}

bool ScreenCaptureServer::FirstPidUpdatePrivacyUsingPermissionState(int32_t pid)
{
    if (IsFirstStartPidInstance(pid)) {
        return UpdatePrivacyUsingPermissionState(START_VIDEO);
    }
    return true;
}


void ScreenCaptureServer::NotifyprivacyProtect()
{
    MEDIA_LOGI("NotifyprivacyProtect displayId appPrivacyProtect: %{public}d, systemPrivacyProtect: %{public}d",
        appPrivacyProtectionSwitch_.load(), systemPrivacyProtectionSwitch_.load());
    AVScreenCapturePrivacyProtect privacyProtect = {
        .appPrivacyProtection = appPrivacyProtectionSwitch_.load(),
        .systemPrivacyProtection = systemPrivacyProtectionSwitch_.load()
    };
    cbProxy_->OnPrivacyProtect(privacyProtect);
}

void ScreenCaptureServer::PostStartScreenCapture(bool isSuccess)
{
    MediaTrace trace("ScreenCaptureServer::PostStartScreenCapture.");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture start, isSuccess:%{public}s, "
        "dataType:%{public}d.", FAKE_POINTER(this), isSuccess ? "true" : "false", captureConfig_.dataType);
    if (isSuccess) {
        MEDIA_LOGI("PostStartScreenCapture handle success");
#ifdef PC_STANDARD
        SetTimeoutScreenoffDisableLock(false);
#endif
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
        if (isPrivacyAuthorityEnabled_ && !isSystemRecorder_.load() && !isScreenCaptureAuthority_ &&
            TryNotificationOnPostStartScreenCapture() == MSERR_UNKNOWN) {
            return;
        }
#endif
        if (!FirstPidUpdatePrivacyUsingPermissionState(appInfo_.appPid)) {
            MEDIA_LOGE("UpdatePrivacyUsingPermissionState START failed, dataType:%{public}d", captureConfig_.dataType);
            captureState_ = AVScreenCaptureState::STARTED;
            cbProxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
                AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
            SetMediaKitReport("startRecording fail");
            StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
            return;
        }
        MEDIA_LOGI("PostStartScreenCaptureSuccessAction START.");
        UpdateHighlightOutline(true);
        PostStartScreenCaptureSuccessAction();
        SetMediaKitReport("startRecording");
    } else {
        PostStartScreenCaptureFail();
        return;
    }
    uint32_t listenerFlags = LF_PRIVATE_WIN | LF_SCREEN_CONN | (isSystemRecorder_ ? 0 : LF_LANG_SWITCH);
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        if (missionInfos_.size() == 1) {
            interestWindowId_ = static_cast<int32_t>(missionInfos_.front().missionId);
            listenerFlags |= LF_WIN_LIFECYCLE | LF_WIN_INFO | LF_RECORD_DISP;
        }
    }
    auto ret = listenerManager_->RegisterListeners(listenerFlags, {.windowIdList = {interestWindowId_}});
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "PostStartScreenCapture RegisterListeners failed");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture end.", FAKE_POINTER(this));
}

void ScreenCaptureServer::PostStartScreenCaptureFail()
{
    MEDIA_LOGE("PostStartScreenCapture handle failure");
    if (isPrivacyAuthorityEnabled_) {
        cbProxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
            AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
        SetMediaKitReport("startRecording fail");
    }
    StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
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
    CHECK_AND_RETURN_RET_NOLOG(tryTimes > NOTIFICATION_MAX_TRY_NUM, MSERR_OK);
    captureState_ = AVScreenCaptureState::STARTED;
    cbProxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
    SetMediaKitReport("startRecording fail");
    StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
    return MSERR_UNKNOWN;
}
#endif

int32_t ScreenCaptureServer::InitAudioCap(AudioCaptureInfo audioInfo)
{
    MediaTrace trace("ScreenCaptureServer::InitAudioCap");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitAudioCap start, audioChannels:%{public}d, "
        "audioSampleRate:%{public}d, audioSource:%{public}d, state:%{public}d.", FAKE_POINTER(this),
        audioInfo.audioChannels, audioInfo.audioSampleRate, audioInfo.audioSource, audioInfo.state);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "InitAudioCap failed, capture is not CREATED, state:%{public}d", captureState_.load());

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
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
        showShareSystemAudioBox_ = true;
        MEDIA_LOGI("InitAudioCap set showShareSystemAudioBox true.");
#endif
    }
    MEDIA_LOGI("InitAudioCap success sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d,"
        "showShareSystemAudioBox:%{public}d", audioInfo.audioSampleRate, audioInfo.audioChannels,
        audioInfo.audioSource, audioInfo.state, showShareSystemAudioBox_);
    return MSERR_OK;
}

void ScreenCaptureServer::ConvertTaskIdsToMissionIds()
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    missionInfos_.clear();
    for (int32_t taskId : captureConfig_.videoInfo.videoCapInfo.taskIDs) {
        if (taskId >= 0) {
            missionInfos_.push_back({static_cast<uint64_t>(taskId), true});
        }
    }
}

int32_t ScreenCaptureServer::InitVideoCap(VideoCaptureInfo videoInfo)
{
    MediaTrace trace("ScreenCaptureServer::InitVideoCap");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION_CREATE,
        "InitVideoCap failed, capture is not CREATED, state:%{public}d", captureState_.load());

    int ret = CheckVideoCapInfo(videoInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "InitVideoCap CheckVideoCapInfo failed");
    captureConfig_.videoInfo.videoCapInfo = videoInfo;
    ConvertTaskIdsToMissionIds();
    SetDisplayId(videoInfo.displayId);

#ifdef PC_STANDARD
    isPickerModePopUp_ = false;
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        std::lock_guard<std::mutex> idLock(captureIdsMutex_);
        if (missionInfos_.size() == 1) {
            Rosen::WindowInfoOption windowInfoOption;
            windowInfoOption.windowId = static_cast<int32_t>(missionInfos_.front().missionId);
            std::vector<sptr<Rosen::WindowInfo>> infos;
            auto wmRet = Rosen::WindowManager::GetInstance().ListWindowInfo(windowInfoOption, infos);
            isPickerModePopUp_ = (wmRet != Rosen::WMError::WM_OK || infos.empty() || infos.front() == nullptr ||
                infos.front()->windowMetaInfo.pid != appInfo_.appPid);
            MEDIA_LOGI("list window info ret:%{public}d, isPickerModePopUp:%{public}d", wmRet,
                isPickerModePopUp_.load());
        } else {
            isPickerModePopUp_ = true;
        }
    }
#endif

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
        ret = recorder->SetVideoSource(captureConfig_.videoInfo.videoCapInfo.videoSource, videoSourceId_);
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
        // continue, do not return error
        TRUE_LOG(ret != MSERR_OK, MEDIA_LOGE, "recorder SetVideoEnableBFrame failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::InitRecorderMix()
{
    int32_t ret = MSERR_OK;
    MEDIA_LOGI("InitRecorder prepare to SetAudioDataSource");
    audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, this);
    audioSource_->SetAppPid(appInfo_.appPid);
    ret = listenerManager_->RegisterListeners(LF_AUDIO_RENDERER, {.appPid = appInfo_.appPid});
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterListeners LF_AUDIO_RENDERER failed");
    std::vector<std::shared_ptr<AudioRendererChangeInfo>> infos;
    OnAudioRendererStateChanged(infos);
    ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
    return ret;
}

int32_t ScreenCaptureServer::InitRecorderInner()
{
    int32_t ret = MSERR_OK;
    isMicrophoneSwitchTurnOn_ = false;
    MEDIA_LOGI("InitRecorder prepare to SetAudioSource inner");
    {
        std::lock_guard<std::mutex> lock(audioMutex_);
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, this);
    }
    ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
    return ret;
}

int32_t ScreenCaptureServer::InitRecorderMic()
{
    MEDIA_LOGI("InitRecorder prepare to SetAudioSource mic");
    {
        std::lock_guard<std::mutex> lock(audioMutex_);
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, this);
    }
    int32_t ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
    return ret;
}

int32_t ScreenCaptureServer::InitRecorder()
{
    CHECK_AND_RETURN_RET_LOG(outputFd_ > 0, MSERR_INVALID_FD, "the outputFd is invalid");
    MEDIA_LOGI("InitRecorder start");
    MediaTrace trace("ScreenCaptureServer::InitRecorder");
    if (!recorder_) {
        recorder_ = providers_->CreateRecorder();
        CHECK_AND_RETURN_RET_LOG(recorder_ != nullptr, MSERR_UNKNOWN, "init Recoder failed");
    }
    ON_SCOPE_EXIT(0) {
        recorder_->Release();
        recorder_ = nullptr;
    };
    int32_t ret;
    AudioCaptureInfo audioInfo;
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID &&
        captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        ret = InitRecorderMix();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_SETAUDIO, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        ret = InitRecorderInner();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_SETAUDIO, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.micCapInfo;
        ret = InitRecorderMic();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_SETAUDIO, "SetAudioDataSource failed");
    } else {
        MEDIA_LOGE("InitRecorder not VALIDATION_VALID");
        return MSERR_UNKNOWN;
    }
    MEDIA_LOGI("InitRecorder recorder SetAudioDataSource ret:%{public}d", ret);
    ret = InitRecorderInfo(recorder_, audioInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_INIT, "InitRecorderInfo failed");
    ret = recorder_->SetOutputFile(outputFd_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_SETFILE, "SetOutputFile failed");
    ret = recorder_->SetStabilizationMode(false);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetStabilizationMode failed");
    ret = recorder_->Prepare();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_PREPARE, "recorder Prepare failed");
    if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        recorderFileWithVideo_.store(true);
        consumer_ = recorder_->GetSurface(videoSourceId_);
        CHECK_AND_RETURN_RET_LOG(consumer_ != nullptr, MSERR_UNKNOWN_RECORDER_GETSURFACE, "recorder GetSurface failed");
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
        CHECK_AND_RETURN_RET_LOG(res == 0, false, "start using perm error: %{public}d", res);
        res = PrivacyKit::AddPermissionUsedRecord(appInfo_.appTokenId, "ohos.permission.CAPTURE_SCREEN", 1, 0);
        CHECK_AND_RETURN_RET_LOG(res == 0, false, "add screen capture record error: %{public}d", res);
    } else if (state == STOP_VIDEO) {
        res = PrivacyKit::StopUsingPermission(appInfo_.appTokenId, "ohos.permission.CAPTURE_SCREEN", appInfo_.appPid);
        if (res != 0) {
            MEDIA_LOGE("stop using perm error");
            return false;
        }
    }
    return true;
}

int32_t ScreenCaptureServer::PrepareStartCapture()
{
    uint32_t listenerFlags = LF_ACCOUNT;
#ifdef SUPPORT_CALL
    if (!captureConfig_.strategy.keepCaptureDuringCall && providers_->GetInCallObserver().IsInCall(true)) {
        MEDIA_LOGI("ScreenCaptureServer Start InCall Abort");
        cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNSUPPORT,
            "ScreenCaptureServer Start InCall Abort");
        return MSERR_UNSUPPORT_INCALL;
    }
    listenerFlags |= LF_CALL;
#endif
    int32_t ret = listenerManager_->RegisterListeners(listenerFlags, {});
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterListeners failed");

    ret = CheckAllParams();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ret);

    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(display != nullptr, MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN, "GetDefaultDisplaySync failed");
    density_ = display->GetVirtualPixelRatio();

    std::string systemUI2;
    ret = OHOS::system::GetStringParameter("persist.systemui.live2", systemUI2, "false");
    isSystemUI2_ = (ret == 0 && systemUI2 == "true");
    appName_ = GetClientBundleName(appInfo_.appUid);
    isSystemRecorder_.store(GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] == appName_);
    callingLabel_ = GetBundleResourceLabel(appName_);
    MEDIA_LOGD("PrepareStartCapture ret: %{public}d, isSystemUI2: %{public}d, appName: %{public}s, label: %{public}s",
        ret, isSystemUI2_, appName_.c_str(), callingLabel_.c_str());
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartScreenCaptureInner(bool isPrivacyAuthorityEnabled)
{
    MEDIA_LOGI("StartScreenCaptureInner S, appUid:%{public}d, appPid:%{public}d, isPrivacyAuthorityEnabled:%{public}d"
        ", isSurfaceMode:%{public}d, dataType:%{public}d", appInfo_.appUid, appInfo_.appPid, isPrivacyAuthorityEnabled,
        isSurfaceMode_.load(), captureConfig_.dataType);
    MediaTrace trace("ScreenCaptureServer::StartScreenCaptureInner");

    int32_t ret = PrepareStartCapture();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "PrepareStartCapture failed");

    isPrivacyAuthorityEnabled_ = isPrivacyAuthorityEnabled;
    captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    isScreenCaptureAuthority_ = CheckPrivacyWindowSkipPermission();

    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        showSensitiveCheckBox_ = true;
        checkBoxSelected_ = true;
    }

    bool isSkipPrivacyWindow = false;
    if (!isScreenCaptureAuthority_ && IsUserPrivacyAuthorityNeeded()) {
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

    ret = OnStartScreenCapture(isSkipPrivacyWindow);
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

void ScreenCaptureServer::BuildCommonParams(Json::Value &root)
{
    root["ability.want.params.uiExtensionType"] = "sys/commonUI";
    root["sessionId"] = std::to_string(sessionId_);
    root["callerUid"] = std::to_string(appInfo_.appUid);
    root["appLabel"] = callingLabel_;
    root["showSensitiveCheckBox"] = std::to_string(static_cast<int>(showSensitiveCheckBox_));
    root["checkBoxSelected"] = std::to_string(static_cast<int>(checkBoxSelected_));
}

#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
bool ScreenCaptureServer::IsPickerPopUp()
{
    if (captureConfig_.captureMode == CAPTURE_VIRTUAL_EXTENDED_SCREEN) {
        return false;
    }
    if (captureConfig_.strategy.pickerPopUp == AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_ENABLE) {
        return true;
    }
#ifdef PC_STANDARD
    if (captureConfig_.strategy.pickerPopUp == AVScreenCapturePickerPopUp::SCREEN_CAPTURE_PICKER_POPUP_DISABLE) {
        return false;
    }
    return !isRegionCapture_ && isPickerModePopUp_;
#else
    return false;
#endif
}

int32_t ScreenCaptureServer::StartPicker()
{
    MEDIA_LOGI("StartPicker");
    isRegionCapture_ = false;
#ifdef PC_STANDARD
    AAFwk::Want want;
    AppExecFwk::ElementName element("", GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY], SELECT_ABILITY_NAME);
    want.SetElement(element);
    want.SetParam("appLabel", callingLabel_);
    want.SetParam("sessionId", sessionId_);
    want.SetParam("showSensitiveCheckBox", showSensitiveCheckBox_);
    want.SetParam("checkBoxSelected", checkBoxSelected_);
    want.SetParam("showShareSystemAudioBox", showShareSystemAudioBox_);
    want.SetParam("excludedWindowIDs", JoinVector(excludedWindowIDsVec_));
    want.SetParam("pickerMode", static_cast<int>(pickerMode_));
    SendConfigToUIParams(want);
    auto ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want,
        AAFwk::DEFAULT_INVAL_VALUE, appUserId_.load());
    MEDIA_LOGI("StartPicker ret=%{public}d", ret);
    return ret == ERR_OK ? MSERR_OK : MSERR_UNKNOWN;
#elif defined(SUPPORT_PICKER_PHONE_PAD)
    Json::Value root;
    BuildCommonParams(root);
    BuildPickerParams(root);
    return StartPrivacyWindow(JsonToString(root));
#else
    return MSERR_INVALID_OPERATION_UNSUPPORT;
#endif
}

#ifdef PC_STANDARD
void ScreenCaptureServer::SendConfigToUIParams(AAFwk::Want &want)
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    if (displayIds_.size() > 1) {
        const auto &displayStr = JoinVector(displayIds_);
        MEDIA_LOGI("SendConfigToUIParams displayId: %{public}s", displayStr.c_str());
        want.SetParam("displayId", displayStr);
    } else if (!displayIds_.empty() && displayIds_.front() <= static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        MEDIA_LOGI("SendConfigToUIParams displayId: %{public}" PRIu64, displayIds_.front());
        want.SetParam("displayId", static_cast<int>(displayIds_.front()));
    } else {
        MEDIA_LOGI("SendConfigToUIParams displayId undefined");
    }
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_SCREEN) {
        missionInfos_.clear();
        want.SetParam("missionId", -1); // -1 无效值
    } else if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        if (missionInfos_.size() == 1) {
            int32_t missionId = static_cast<int32_t>(missionInfos_.front().missionId);
            MEDIA_LOGI("CAPTURE_SPECIFIED_WINDOW, missionId: %{public}d", missionId);
            want.SetParam("missionId", missionId);
        } else {
            want.SetParam("missionId", -1); // -1 无效值
        }
    }
}

#elif defined(SUPPORT_PICKER_PHONE_PAD)
void ScreenCaptureServer::BuildPickerParams(Json::Value &root)
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    root["showShareSystemAudioBox"] = showShareSystemAudioBox_;
    if (!excludedWindowIDsVec_.empty()) {
        Json::Value excludedWindowIDs(Json::arrayValue);
        for (const auto &windowId : excludedWindowIDsVec_) {
            excludedWindowIDs.append(windowId);
        }
        root["excludedWindowIDs"] = excludedWindowIDs;
    }
    if (!displayIds_.empty()) {
        Json::Value displayIds(Json::arrayValue);
        for (const auto &displayId : displayIds_) {
            displayIds.append(displayId);
        }
        root["displayIds"] = displayIds;
    }
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW && missionInfos_.size() == 1) {
        Json::Value missionIds(Json::arrayValue);
        missionIds.append(static_cast<int32_t>(missionInfos_.front().missionId));
        root["missionIds"] = missionIds;
    }
    root["pickerMode"] = static_cast<int>(pickerMode_);
}
#endif
#endif

int32_t ScreenCaptureServer::StartPrivacyWindow(const std::string &cmdStr)
{
    AAFwk::Want want;
    want.SetElementName(GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"],
                        GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionabilityname"]);
    connection_ = sptr<UIExtensionAbilityConnection>::MakeSptr(cmdStr);
    auto ret = OHOS::AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_,
        nullptr, appUserId_.load());
    MEDIA_LOGI("StartPrivacyWindow ret=%{public}d", ret);
    return ret == ERR_OK ? MSERR_OK : MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::StartAuthWindow()
{
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    if (IsPickerPopUp()) {
        return StartPicker();
    }
    showShareSystemAudioBox_ = false;
    Json::Value root;
    BuildCommonParams(root);
    return StartPrivacyWindow(JsonToString(root));
#else
    Json::Value root;
    BuildCommonParams(root);
    return StartPrivacyWindow(JsonToString(root));
#endif
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
    resourceManager_->GetStringByName(name, resourceContext);
    MEDIA_LOGD("get resource string: %{public}s", resourceContext.c_str());
    return resourceContext;
}

void ScreenCaptureServer::InitResourceManager()
{
    std::string language = Global::I18n::LocaleConfig::GetSystemLanguage();
    UErrorCode status = U_ZERO_ERROR;
    icu::Locale locale = icu::Locale::forLanguageTag(language, status);
    TRUE_LOG(status != U_ZERO_ERROR, MEDIA_LOGE, "forLanguageTag failed, errCode:%{public}d", status);
    if (resourceManager_ == nullptr) {
        resourceManager_ = Global::Resource::GetSystemResourceManagerNoSandBox();
    }
    if (resConfig_ == nullptr) {
        resConfig_ = Global::Resource::CreateResConfig();
    }
    if (resConfig_) {
        resConfig_->SetLocaleInfo(locale.getLanguage(), locale.getScript(), locale.getCountry());
        if (resourceManager_) {
            resourceManager_->UpdateResConfig(*resConfig_);
        }
    }
}

void ScreenCaptureServer::InitLiveViewContent()
{
    localLiveViewContent_ =
        std::make_shared<NotificationLocalLiveViewContent>();
    localLiveViewContent_->SetType(1);
    UpdateLiveViewContent();
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
}

void ScreenCaptureServer::UpdateLiveViewButton()
{
    NotificationLocalLiveViewButton basicButton;

    if (captureConfig_.strategy.enablePause) {
        if (isTimePaused_) {
            basicButton.addSingleButtonName(BUTTON_NAME_RESUME);
            std::shared_ptr<PixelMap> pixelMapResumeSpr = GetPixelMapSvg(ICON_PATH_RESUME, SVG_HEIGHT, SVG_WIDTH);
            basicButton.addSingleButtonIcon(pixelMapResumeSpr);
        } else {
            basicButton.addSingleButtonName(BUTTON_NAME_PAUSE);
            std::shared_ptr<PixelMap> pixelMapPauseSpr = GetPixelMapSvg(ICON_PATH_PAUSE, SVG_HEIGHT, SVG_WIDTH);
            basicButton.addSingleButtonIcon(pixelMapPauseSpr);
        }
    }

    basicButton.addSingleButtonName(BUTTON_NAME_STOP);
    std::shared_ptr<PixelMap> pixelMapStopSpr = GetPixelMapSvg(ICON_PATH_STOP, SVG_HEIGHT, SVG_WIDTH);
    basicButton.addSingleButtonIcon(pixelMapStopSpr);

    localLiveViewContent_->SetButton(basicButton);
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
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        localLiveViewContent_->SetTitle(liveViewText_);
        UpdateLiveViewPrivacy();
        MEDIA_LOGI("UpdateLiveViewContent additionalText: %{public}s", liveViewSubText_.c_str());
        capsule.SetTitle(callingLabel_);
    } else {
        localLiveViewContent_->SetText(liveViewText_);
        NotificationTime countTime;
        countTime.SetIsCountDown(false);
        countTime.SetIsPaused(isTimePaused_);
        countTime.SetIsInTitle(true);
        countTime.SetInitialTime(1);
        localLiveViewContent_->SetTime(countTime);
        localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);
    }
    localLiveViewContent_->SetCapsule(capsule);
    UpdateLiveViewButton();
}

void ScreenCaptureServer::UpdateLiveViewPrivacy()
{
    CHECK_AND_RETURN_LOG(localLiveViewContent_ != nullptr, "localLiveViewContent_ is null");
    if (!systemPrivacyProtectionSwitch_ && !appPrivacyProtectionSwitch_) {
        liveViewSubText_ = GetStringByResourceName("notification_screen_recording_privacy_off");
    } else {
        liveViewSubText_ = GetStringByResourceName("notification_screen_recording_privacy_on");
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
    return std::shared_ptr<PixelMap>(imageSource->CreatePixelMap(decodeOpts, errorCode));
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
    return std::shared_ptr<PixelMap>(imageSource->CreatePixelMap(decodeOpts, errorCode));
}

void ScreenCaptureServer::UpdateMicrophoneEnabled()
{
    std::lock_guard<std::mutex> lock(mutex_);
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
    if (appUserId_ != -1) {
        request.SetOwnerUserId(appUserId_.load());
    }

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
        FAKE_POINTER(this), isPrivacyAuthorityEnabled ? "true" : "false", captureState_.load());
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_INIT), MSERR_INVALID_OPERATION,
        "StartScreenCapture failed, not in CREATED or STOPPED, state:%{public}d", captureState_.load());
    MEDIA_LOGI("StartScreenCapture isPrivacyAuthorityEnabled:%{public}d", isPrivacyAuthorityEnabled);
    isSurfaceMode_ = false;
    return StartScreenCaptureInner(isPrivacyAuthorityEnabled);
}

int32_t ScreenCaptureServer::StartScreenCaptureWithSurface(sptr<Surface> surface, bool isPrivacyAuthorityEnabled)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_INIT), MSERR_INVALID_OPERATION,
        "StartScreenCaptureWithSurface failed, not in CREATED or STOPPED, state:%{public}d",
        captureState_.load());
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
        captureConfig_.videoInfo.videoCapInfo.state, captureConfig_.dataType, isSurfaceMode_.load() ? "true" : "false");
    if (captureConfig_.videoInfo.videoCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_IGNORE) {
        MEDIA_LOGI("StartStreamVideoCapture is ignored");
        return MSERR_OK;
    } else if (captureConfig_.videoInfo.videoCapInfo.state != AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        return MSERR_INVALID_VAL;
    }
    int32_t ret = StartStreamHomeVideoCapture();
    CHECK_AND_RETURN_RET(ret == MSERR_OK, ret);
    MEDIA_LOGI("StartStreamVideoCapture end.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartStreamHomeVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StartStreamHomeVideoCapture");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamHomeVideoCapture start, "
        "isSurfaceMode: %{public}s.", FAKE_POINTER(this), isSurfaceMode_.load() ? "true" : "false");
    if (isSurfaceMode_) {
        int32_t ret = CreateVirtualScreen(surface_);
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
    surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(consumer_, cbProxy_);
    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_UNKNOWN, "MakeSptr surfaceCb_ failed");
    consumer_->RegisterConsumerListener(surfaceCb_);
    MEDIA_LOGD("StartStreamHomeVideoCapture producerSurface_: %{public}" PRIu64, producerSurface_->GetUniqueId());
    int32_t ret = MSERR_OK;
    if (!isSurfaceMode_) {
        ret = (static_cast<ScreenCapBufferConsumerListener*>(surfaceCb_.GetRefPtr()))->StartBufferThread();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "start buffer thread failed");
    }
    ret = CreateVirtualScreen(producerSurface_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "create virtual screen without input surface failed");
    CANCEL_SCOPE_EXIT_GUARD(0);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartStreamHomeVideoCapture OK.", FAKE_POINTER(this));
    MEDIA_LOGI("ScreenCaptureServer:StartStreamHomeVideoCapture surfaceCb_: 0x%{public}06" PRIXPTR,
        FAKE_POINTER(surfaceCb_.GetRefPtr()));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetVirtualScreenAutoRotation()
{
    CHECK_AND_RETURN_RET(captureConfig_.dataType == DataType::ORIGINAL_STREAM, MSERR_INVALID_OPERATION);
    MEDIA_LOGI("config strategy canvasFollowRotation %{public}d", captureConfig_.strategy.canvasFollowRotation);
    auto setAutoRotationRet = Rosen::ScreenManager::GetInstance().SetVirtualScreenAutoRotation(virtualScreenId_,
        captureConfig_.strategy.canvasFollowRotation);
    MEDIA_LOGI("SetVirtualScreenAutoRotation setAutoRotationRet %{public}d", setAutoRotationRet);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::CreateVirtualScreen(sptr<OHOS::Surface> consumer)
{
    MediaTrace trace("ScreenCaptureServer::CreateVirtualScreen");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " CreateVirtualScreen Start", FAKE_POINTER(this));
    isConsumerStart_ = false;
    VirtualScreenOption virScrOption = InitVirtualScreenOption(consumer);
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (display != nullptr) {
        MEDIA_LOGI("get displayInfo width:%{public}d,height:%{public}d, density:%{public}f", display->GetWidth(),
                   display->GetHeight(), display->GetVirtualPixelRatio());
        virScrOption.density_ = display->GetVirtualPixelRatio();
    }
    {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        if (!missionInfos_.empty()) {
            for (const auto &m : missionInfos_) {
                virScrOption.missionIds_.push_back(m.missionId);
            }
        }
    }
    virtualScreenId_ = Rosen::ScreenManager::GetInstance().CreateVirtualScreen(virScrOption);
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ >= 0, MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN,
        "CreateVirtualScreen failed, invalid screenId");
    SetVirtualScreenAutoRotation();
    CHECK_AND_RETURN_RET_LOG(HandleOriginalStreamPrivacy() == MSERR_OK,
        MSERR_UNKNOWN, "SetScreenSkipProtectedWindow failed");
    if (!showCursor_) {
        ShowCursorInner();
    }
    MEDIA_LOGI("CreateVirtualScreen success, screenId: %{public}" PRIu64, virtualScreenId_);
    return PrepareVirtualScreenMirror();
}

int32_t ScreenCaptureServer::HandleOriginalStreamPrivacy()
{
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        if (checkBoxSelected_) {
            MEDIA_LOGI("CreateVirtualScreen checkBoxSelected: %{public}d", checkBoxSelected_);
            PrivacyProtected(virtualScreenId_, true, true);
        } else {
            PrivacyProtected(virtualScreenId_, false, false);
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
    auto screen = Rosen::ScreenManager::GetInstance().GetScreenById(virtualScreenId_);
    if (screen == nullptr) {
        MEDIA_LOGE("GetScreenById failed");
        DestroyVirtualScreen();
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
            "GetScreenById failed");
        return MSERR_UNKNOWN_CREATE_VIRTUAL_SCREEN;
    }
    if (canvasRotation_) {
        SetCanvasRotationInner();
    }
    SkipPrivacyModeInner();
    int32_t ret;
    if (captureConfig_.captureMode == CAPTURE_VIRTUAL_EXTENDED_SCREEN) {
        ret = MakeVirtualScreenExtended();
    } else {
        ret = MakeVirtualScreenMirror();
    }
    if (ret != MSERR_OK) {
        MEDIA_LOGE("MakeVirtualScreen failed, captureMode:%{public}d", captureConfig_.captureMode);
        DestroyVirtualScreen();
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
            "MakeVirtualScreen failed");
        return MSERR_UNKNOWN_MAKE_MIRROR;
    }
    uint32_t actualRefreshRate = 0;
    auto res = Rosen::ScreenManager::GetInstance().SetVirtualScreenMaxRefreshRate(virtualScreenId_,
        VIDEO_FRAME_RATE_MAX, actualRefreshRate);
    MEDIA_LOGI("SetVirtualScreenMaxRefreshRate res: %{public}d, actualRefreshRate %{public}u", res, actualRefreshRate);
    isConsumerStart_ = true;
    return MSERR_OK;
}

uint64_t ScreenCaptureServer::GetDisplayIdOfWindows()
{
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    std::vector<uint64_t> missionIds;
    for (const auto &m : missionInfos_) {
        missionIds.push_back(m.missionId);
    }
    sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(defaultDisplay != nullptr, Rosen::SCREEN_ID_INVALID, "GetDefaultDisplaySync failed");
    uint64_t displayId = defaultDisplay->GetScreenId();
    if (missionIds.empty()) {
        return displayId;
    }
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_APP && displayIds_.empty()) {
        Rosen::FocusChangeInfo focusedWindowInfo;
        Rosen::WindowManager::GetInstance().GetFocusWindowInfo(focusedWindowInfo);
        uint64_t focusId = static_cast<uint64_t>(focusedWindowInfo.windowId_);
        if (std::find(missionIds.begin(), missionIds.end(), focusId) != missionIds.end()) {
            displayIds_.clear();
            displayIds_.emplace_back(focusedWindowInfo.displayId_);
            return focusedWindowInfo.displayId_;
        }
    }
    std::unordered_map<uint64_t, uint64_t> windowDisplayIdMap;
    Rosen::WindowManager::GetInstance().GetDisplayIdByWindowId(missionIds, windowDisplayIdMap);
    for (auto rit = missionIds.rbegin(); rit != missionIds.rend(); ++rit) {
        auto it = windowDisplayIdMap.find(*rit);
        if (it == windowDisplayIdMap.end()) {
            continue;
        }
        if (std::find(displayIds_.begin(), displayIds_.end(), it->second) != displayIds_.end()) {
            return it->second;
        }
        displayId = it->second;
    }
    displayIds_.clear();
    displayIds_.emplace_back(displayId);
    return displayId;
}

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

#ifdef PC_STANDARD
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

void ScreenCaptureServer::SetTimeoutScreenoffDisableLock(bool lockScreen)
{
    MEDIA_LOGI("SetTimeoutScreenoffDisableLock Start lockScreen %{public}d", lockScreen);
    int result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(appInfo_.appTokenId,
        TIMEOUT_SCREENOFF_DISABLE_LOCK);
    CHECK_AND_RETURN_LOG(result == Security::AccessToken::PERMISSION_GRANTED,
        "user have not the TIMEOUT_SCREENOFF_DISABLE_LOCK!");
    auto powerErrors = OHOS::PowerMgr::PowerMgrClient::GetInstance()
                                .LockScreenAfterTimingOutWithAppid(sessionId_, lockScreen);
    CHECK_AND_RETURN_LOG(powerErrors == OHOS::PowerMgr::PowerErrors::ERR_OK,
        "SetTimeoutScreenoffDisableLock error %{public}d", powerErrors);
    MEDIA_LOGI("SetTimeoutScreenoffDisableLock success");
    CHECK_AND_RETURN_NOLOG(!lockScreen);
    Rosen::DisplayManager::GetInstance().DisablePowerOffRenderControl(virtualScreenId_);
}
#endif

int32_t ScreenCaptureServer::SetupVirtualScreenMirror(std::vector<ScreenId> &mirrorIds)
{
    sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(defaultDisplay != nullptr, MSERR_UNKNOWN,
        "SetupVirtualScreenMirror GetDefaultDisplaySync failed");
    std::vector<uint64_t> displayIds;
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW || captureConfig_.captureMode == CAPTURE_SPECIFIED_APP) {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        displayIds = {displayIds_.empty() ? defaultDisplay->GetScreenId() : displayIds_.front()};
    } else if (captureConfig_.captureMode == CAPTURE_HOME_SCREEN) {
        displayIds = {defaultDisplay->GetScreenId()};
    } else if (captureConfig_.captureMode == CAPTURE_SPECIFIED_SCREEN) {
        std::vector<Rosen::DisplayId> allDisplayIds = Rosen::DisplayManager::GetInstance().GetAllDisplayIds();
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        CHECK_AND_RETURN_RET_LOG(!allDisplayIds.empty() && !displayIds_.empty(), MSERR_UNKNOWN,
            "MakeMirror failed to GetAllDisplayIds, allDisplayIds is empty");
        std::copy_if(displayIds_.begin(), displayIds_.end(), std::back_inserter(displayIds), [&](uint64_t displayId) {
            return std::find(allDisplayIds.begin(), allDisplayIds.end(), displayId) != allDisplayIds.end();
        });
    }
    if (displayIds.empty()) {
        std::lock_guard<std::mutex> lock(captureIdsMutex_);
        MEDIA_LOGE("MakeMirror failed to get displayIds, source size:%{public}zu", displayIds_.size());
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
            "MakeMirror failed to find valid displayId");
        return MSERR_UNKNOWN;
    }
    DMError ret = CreateMirror(displayIds, mirrorIds);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "MakeMirror failed, captureMode:%{public}d, ret:%{public}d", captureConfig_.captureMode, ret);
    MEDIA_LOGI("MakeMirror screen success, screenId:%{public}" PRIu64, displayIds.front());
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    sourceDisplayIds_ = std::move(displayIds);
    curWindowInDisplayId_.store(sourceDisplayIds_.front());
    return MSERR_OK;
}

int32_t ScreenCaptureServer::MakeVirtualScreenMirror()
{
    MediaTrace trace("ScreenCaptureServer::MakeVirtualScreenMirror");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " MakeVirtualScreenMirror start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, invalid screenId");
    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(virtualScreenId_);
    if (isRegionCapture_) {
        return SetCaptureAreaInner(regionDisplayId_, regionArea_);
    }
    return SetupVirtualScreenMirror(mirrorIds);
}

int32_t ScreenCaptureServer::MakeVirtualScreenExtended()
{
    MediaTrace trace("ScreenCaptureServer::MakeVirtualScreenExtended");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " MakeVirtualScreenExtended start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID, MSERR_UNKNOWN,
        "invalid virtualScreenId");
    CHECK_AND_RETURN_RET_LOG(!displayIds_.empty(), MSERR_INVALID_VAL, "displayIds_ empty");
    ScreenId mainScreenId = displayIds_.front();
    auto mainScreen = Rosen::DisplayManager::GetInstance().GetDisplayById(mainScreenId);
    CHECK_AND_RETURN_RET_LOG(mainScreen != nullptr, MSERR_INVALID_VAL, "screen id is invalid");
    auto mainRsId = Rosen::SCREEN_ID_INVALID;
    auto secondRsId = Rosen::SCREEN_ID_INVALID;
    CHECK_AND_RETURN_RET_LOG(Rosen::DisplayManager::GetInstance().ConvertScreenIdToRsScreenId(mainScreenId, mainRsId) &&
            Rosen::DisplayManager::GetInstance().ConvertScreenIdToRsScreenId(virtualScreenId_, secondRsId),
        MSERR_UNKNOWN, "convert rs screen id failed, mainScreenId:%{public}" PRIu64 " virtualScreenId:%{public}" PRIu64,
        mainScreenId, virtualScreenId_);
    auto ret = Rosen::ScreenManager::GetInstance().SetMultiScreenMode(mainScreenId, secondRsId,
        Rosen::MultiScreenMode::SCREEN_EXTEND);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "Set multi screen mode failed, rsId:%{public}" PRIu64 " ret:%{public}d", secondRsId, ret);
    Rosen::MultiScreenPositionOptions mainScreenOpt{.screenId_ = mainRsId};
    Rosen::MultiScreenPositionOptions secondScreenOpt{.screenId_ = secondRsId, .startX_ = mainScreen->GetWidth()};
    ret = Rosen::ScreenManager::GetInstance().SetMultiScreenRelativePosition(mainScreenOpt, secondScreenOpt);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN, "Set relative position failed, %{public}d", ret);
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    sourceDisplayIds_.clear();
    sourceDisplayIds_.push_back(mainScreenId);
    MEDIA_LOGI("MakeVirtualScreenExtended success, mainScreenId:%{public}" PRIu64 ", virtualScreenId:%{public}" PRIu64,
        mainScreenId, virtualScreenId_);
    return MSERR_OK;
}

void ScreenCaptureServer::DestroyVirtualScreen()
{
    MediaTrace trace("ScreenCaptureServer::DestroyVirtualScreen");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " DestroyVirtualScreen start.", FAKE_POINTER(this));
    if (virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID) {
        if (isConsumerStart_) {
            std::vector<ScreenId> screenIds;
            screenIds.push_back(virtualScreenId_);
            Rosen::ScreenManager::GetInstance().StopMirror(screenIds);
        }
        Rosen::ScreenManager::GetInstance().DestroyVirtualScreen(virtualScreenId_);
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

std::string ScreenCaptureServer::GetVirtualScreenName() const
{
    switch (captureConfig_.captureMode) {
        case CAPTURE_VIRTUAL_EXTENDED_SCREEN:
            return "CooperationExtend";
        default:
            return "screen_capture";
    }
}

VirtualScreenOption ScreenCaptureServer::InitVirtualScreenOption(sptr<OHOS::Surface> consumer)
{
    MediaTrace trace("ScreenCaptureServer::InitVirtualScreenOption");
    VirtualScreenOption virScrOption = {
        .name_ = GetVirtualScreenName(),
        .width_ = captureConfig_.videoInfo.videoCapInfo.videoFrameWidth,
        .height_ = captureConfig_.videoInfo.videoCapInfo.videoFrameHeight,
        .density_ = 0,
        .surface_ = consumer,
        .flags_ = captureConfig_.strategy.strategyForPrivacyMaskMode,
        .isForShot_ = true,
        .missionIds_ = {},
        .virtualScreenType_ = VirtualScreenType::SCREEN_RECORDING,
        .bundleName_ = appName_,
    };
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitVirtualScreenOption start, name:%{public}s.",
        FAKE_POINTER(this), virScrOption.name_.c_str());
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitVirtualScreenOption end.", FAKE_POINTER(this));
    return virScrOption;
}

int32_t ScreenCaptureServer::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type)
{
    MediaTrace trace("ScreenCaptureServer::AcquireAudioBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireAudioBuffer start, state:%{public}d, "
        "type:%{public}d.", FAKE_POINTER(this), captureState_.load(), type);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "AcquireAudioBuffer failed, capture is not STARTED or RESUMED, state:%{public}d, type:%{public}d",
        captureState_.load(), type);

    std::lock_guard<std::mutex> audioLock(audioMutex_);
    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        micAudioCapture_ && micAudioCapture_->IsRecording()) {
        return micAudioCapture_->AcquireAudioBuffer(audioBuffer);
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        innerAudioCapture_ && innerAudioCapture_->IsRecording()) {
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
        "type:%{public}d.", FAKE_POINTER(this), captureState_.load(), type);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "ReleaseAudioBuffer failed, capture is not STARTED or RESUMED, state:%{public}d, type:%{public}d",
        captureState_.load(), type);

    std::lock_guard<std::mutex> audioLock(audioMutex_);
    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        micAudioCapture_ && micAudioCapture_->IsRecording()) {
        return micAudioCapture_->ReleaseAudioBuffer();
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        innerAudioCapture_ && innerAudioCapture_->IsRecording()) {
        return innerAudioCapture_->ReleaseAudioBuffer();
    }
    MEDIA_LOGE("ReleaseAudioBuffer failed, source type not support, type:%{public}d", type);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "ReleaseAudioBuffer failed, source type not support");
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::AcquireVideoBuffer(sptr<OHOS::SurfaceBuffer> &surfaceBuffer, int32_t &fence,
                                                int64_t &timestamp, OHOS::Rect &damage, OHOS::Rect &rsRect)
{
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer", HITRACE_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireVideoBuffer start, state:%{public}d, "
        "fence:%{public}d, timestamp:%{public}" PRId64, FAKE_POINTER(this), captureState_.load(), fence, timestamp);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "AcquireVideoBuffer failed, capture is not STARTED or RESUMED, state:%{public}d", captureState_.load());

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
        HDI::Display::Graphic::Common::V1_0::BufferHandleMetaRegion metaRegion;
        std::vector<uint8_t> data;
        auto ret = surfaceBuffer->GetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_CROP_REGION, data);
        if (ret == GSERROR_OK && memcpy_s(&metaRegion,
            sizeof(HDI::Display::Graphic::Common::V1_0::BufferHandleMetaRegion), data.data(), data.size()) == EOK) {
            rsRect.x = static_cast<int32_t>(metaRegion.left);
            rsRect.y = static_cast<int32_t>(metaRegion.top);
            rsRect.w = static_cast<int32_t>(metaRegion.width);
            rsRect.h = static_cast<int32_t>(metaRegion.height);
        } else {
            rsRect = {-1, -1, -1, -1};
        }
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
        FAKE_POINTER(this), captureState_.load());
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "ReleaseVideoBuffer failed, capture is not STARTED, state:%{public}d", captureState_.load());

    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_NO_MEMORY, "ReleaseVideoBuffer failed, callback is nullptr");
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ReleaseVideoBuffer end.", FAKE_POINTER(this));
    return (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->ReleaseVideoBuffer();
}

int32_t ScreenCaptureServer::ExcludeContent(ScreenCaptureContentFilter &contentFilter)
{
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ALIVE), MSERR_INVALID_OPERATION, "ExcludeContent failed, cannot save config");

    MEDIA_LOGI("ScreenCaptureServer::ExcludeContent start");
    contentFilter_ = contentFilter;
    if (IsState(CAP_ACTIVE)) {
        Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(virtualScreenId_,
            contentFilter_.windowIDsVec, surfaceIdList_, surfaceTypeList_);
    }
    int32_t ret = MSERR_OK;
    {
        std::lock_guard<std::mutex> audioLock(audioMutex_);
        if (innerAudioCapture_ != nullptr) {
            ret = innerAudioCapture_->UpdateAudioCapturerConfig(contentFilter_);
        }
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

int32_t ScreenCaptureServer::AddWhiteListWindows(const std::vector<uint64_t> &windowIDsVec)
{
    MediaTrace trace("ScreenCaptureServer::AddWhiteListWindows");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "AddWhiteListWindows failed, virtual screen not create");
    for (const auto& windowID : windowIDsVec) {
        MEDIA_LOGI("AddWhiteListWindows windowIDsVec value :%{public}" PRIu64, windowID);
    }
    MEDIA_LOGI("AddWhiteListWindows start");
    DMError ret = Rosen::ScreenManager::GetInstance().AddVirtualScreenWhiteList(virtualScreenId_,
        windowIDsVec);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "AddVirtualScreenWhiteList failed, ret:%{public}d", ret);
    MEDIA_LOGI("AddWhiteListWindows success");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::RemoveWhiteListWindows(const std::vector<uint64_t> &windowIDsVec)
{
    MediaTrace trace("ScreenCaptureServer::RemoveWhiteListWindows");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_ACTIVE), MSERR_INVALID_OPERATION,
        "RemoveWhiteListWindows failed, virtual screen not create");
    for (const auto& windowID : windowIDsVec) {
        MEDIA_LOGI("RemoveWhiteListWindows windowIDsVec value :%{public}" PRIu64, windowID);
    }
    MEDIA_LOGI("RemoveWhiteListWindows start");
    DMError ret = Rosen::ScreenManager::GetInstance().RemoveVirtualScreenWhiteList(virtualScreenId_,
        windowIDsVec);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "RemoveVirtualScreenWhiteList failed, ret:%{public}d", ret);
    MEDIA_LOGI("RemoveWhiteListWindows success");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ExcludePickerWindows(const std::vector<int32_t> &windowIDsVec)
{
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    std::lock_guard<std::mutex> lock(mutex_);
    excludedWindowIDsVec_ = windowIDsVec;
    return MSERR_OK;
#else
    (void)windowIDsVec;
    return MSERR_UNKNOWN_UNSUPPORT;
#endif
}

int32_t ScreenCaptureServer::SetPickerMode(PickerMode pickerMode)
{
    CHECK_AND_RETURN_RET_LOG(pickerMode >= PickerMode::MIN_VAL && pickerMode <= PickerMode::MAX_VAL,
        MSERR_INVALID_VAL, "pickerMode is invalid, mode:%{public}d", static_cast<int32_t>(pickerMode));
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    MEDIA_LOGD("ScreenCaptureServer::SetPickerMode");
    std::lock_guard<std::mutex> lock(mutex_);
    pickerMode_ = pickerMode;
    return MSERR_OK;
#else
    (void)pickerMode;
    return MSERR_UNKNOWN_UNSUPPORT;
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
    if (!IsState(CAP_RUNNING)) {
        MEDIA_LOGI("ScreenCaptureServer::SetCaptureArea, virtual screen not created, return ok");
        return MSERR_OK;
    }
    return SetCaptureAreaInner(regionDisplayId_, regionArea_);
}

int32_t ScreenCaptureServer::SetCaptureAreaInner(uint64_t displayId, OHOS::Rect area)
{
    MediaTrace trace("ScreenCaptureServer::SetCaptureAreaInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCaptureAreaInner start, state:%{public}d.",
        FAKE_POINTER(this), captureState_.load());
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
    MEDIA_LOGI("SetCaptureAreaInner after, displayId: %{public}" PRIu64
        " x:%{public}d, y:%{public}d, w:%{public}d, h:%{public}d",
        regionScreenId, regionAreaOut.posX_, regionAreaOut.posY_, regionAreaOut.width_, regionAreaOut.height_);

    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(virtualScreenId_);
    ScreenId screenGroupId{0};
    ret = Rosen::ScreenManager::GetInstance().MakeMirror(regionScreenId, mirrorIds, regionAreaOut, screenGroupId);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN, "MakeMirror with region error: %{public}d", ret);
    std::lock_guard<std::mutex> lock(captureIdsMutex_);
    sourceDisplayIds_.clear();
    sourceDisplayIds_.emplace_back(displayId);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCaptureAreaInner end, state:%{public}d.",
        FAKE_POINTER(this), captureState_.load());
    return MSERR_OK;
}

int32_t ScreenCaptureServer::GetMultiDisplayCaptureCapability(const std::vector<uint64_t> &displayIds,
    MultiDisplayCapability &capability)
{
    MediaTrace trace("ScreenCaptureServer::GetMultiDisplayCaptureCapability");
    std::lock_guard<std::mutex> lock(mutex_);
    DMRect region;
    CHECK_AND_RETURN_RET_LOG(displayIds.size() < MAX_DISPLAY_LEN && displayIds.size() > 1,
        MSERR_INVALID_OPERATION, "displayIds size is exceed max range");
    auto ret = Rosen::ScreenManager::GetInstance().QueryMultiScreenCapture(displayIds, region);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK || ret == DMError::DM_ERROR_INVALID_PARAM ||
        ret == DMError::DM_ERROR_DEVICE_NOT_SUPPORT, MSERR_UNKNOWN, "QueryMultiScreenCapture ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_OK, "QueryMultiScreenCapture ret: %{public}d", ret);
    capability.width = region.width_;
    capability.height = region.height_;
    capability.isMultiDisplaySupport = true;
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
    if (area.x < 0 || area.y < 0 || area.w < 0 || area.h < 0) {
        MEDIA_LOGE("CheckDisplayArea input area has negative value, "
            "x:%{public}d, y:%{public}d, w:%{public}d, h:%{public}d", area.x, area.y, area.w, area.h);
        return false;
    }
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
        "%{public}d, new isMicrophone:%{public}d", FAKE_POINTER(this), IsMicrophoneSwitchTurnOn(), isMicrophone);
    if (isMicrophone) {
        statisticalEventInfo_.enableMic = true;
    }
    if (!IsState(CAP_RUNNING)) {
        isMicrophoneSwitchTurnOn_ = isMicrophone;
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET_LOG(captureConfig_.audioInfo.micCapInfo.state ==
        AVScreenCaptureParamValidationState::VALIDATION_VALID, MSERR_OK, "No Microphone Config");
#ifdef SUPPORT_CALL
    if (isMicrophone && providers_->GetInCallObserver().IsInCall(true)) {
        cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
        return MSERR_UNKNOWN_INCALL;
    }
#endif
    bool oldFlag = isMicrophoneSwitchTurnOn_;
    isMicrophoneSwitchTurnOn_ = isMicrophone;
    int32_t ret = SyncAudioCaptures();
    if (ret != MSERR_OK) {
        isMicrophoneSwitchTurnOn_ = oldFlag;
        return ret;
    }
    cbProxy_->OnStateChange(isMicrophone ? AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNMUTED_BY_USER
        : AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_MUTED_BY_USER);
    MEDIA_LOGI("SetMicrophoneEnabled OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::AudioRendererStateUpdate(
    const std::vector<std::shared_ptr<AudioRendererChangeInfo>> &audioRendererChangeInfos)
{
    uint32_t headSetCount = 0;
    uint32_t newState = 0;
    for (const std::shared_ptr<AudioRendererChangeInfo> &changeInfo : audioRendererChangeInfos) {
        CHECK_AND_CONTINUE(changeInfo);
#ifdef SUPPORT_CALL
        if (changeInfo->rendererInfo.streamUsage ==
                AudioStandard::StreamUsage::STREAM_USAGE_VOICE_MODEM_COMMUNICATION &&
            (changeInfo->rendererState == RendererState::RENDERER_RUNNING ||
                changeInfo->rendererState == RendererState::RENDERER_PREPARED)) {
            newState |= AUDIO_STATE_TEL;
        }
#endif
        if (changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION ||
            changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VIDEO_COMMUNICATION) {
            newState |= AUDIO_STATE_VOIP;
        }
        if (changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_WIRED_HEADPHONES ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_SCO ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_BLUETOOTH_A2DP ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_USB_ARM_HEADSET ||
            changeInfo->outputDeviceInfo.deviceType_ == DEVICE_TYPE_NEARLINK) {
            headSetCount++;
        }
    }

    if (headSetCount > 0 && headSetCount == audioRendererChangeInfos.size()) {
        newState |= AUDIO_STATE_HEADSET;
    }

    if ((newState & AUDIO_STATE_VOIP) &&
        (GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY] != appName_ ||
            Global::I18n::LocaleConfig::GetSystemRegion() != "CN")) {
        newState &= ~AUDIO_STATE_VOIP;
    }

    {
        std::lock_guard<std::mutex> lock(audioMutex_);
        CHECK_AND_RETURN_RET_LOG(audioSource_ != nullptr, MSERR_OK, "audioSource_ is null");
        uint32_t oldState = audioSource_->GetAudioRendererState();
        MEDIA_LOGI("AudioRendererStateUpdate: newState=%{public}u oldState=%{public}u", newState, oldState);
        if (oldState == newState) {
            return MSERR_OK;
        }
        audioSource_->SetAudioRendererState(newState);
    }

    return SyncAudioCaptures();
}

bool ScreenCaptureServer::StopMicAudio()
{
    bool isRecording = micAudioCapture_ && micAudioCapture_->IsRecording();
    if (isRecording) {
        usleep(AUDIO_CHANGE_TIME);
    }
    if (micAudioCapture_) {
        MEDIA_LOGI("StopMicAudioCapture");
        micAudioCapture_->Stop();
    }
    return isRecording;
}

int32_t ScreenCaptureServer::SyncAudioCaptures(bool ignoreMicError)
{
    std::lock_guard<std::mutex> lock(audioMutex_);
    uint32_t newState = audioSource_ ? audioSource_->GetAudioRendererState() : 0;
    uint32_t state = newState;
#ifdef SUPPORT_CALL
    if (isInTelCall_.load()) {
        state |= AUDIO_STATE_TEL;
    }
#endif
    bool micStop = !isMicrophoneSwitchTurnOn_ || (state & AUDIO_STATE_TEL) ||
        (micAudioCapture_ && micAudioCapture_->IsInVoIPCall() != ((state & AUDIO_STATE_VOIP) != 0));
    bool micStart = isMicrophoneSwitchTurnOn_ && !(state & AUDIO_STATE_TEL);
    bool innerStart;
    {
        std::shared_lock<std::shared_mutex> configLock(captureConfigMutex_);
        innerStart = captureConfig_.dataType == DataType::ORIGINAL_STREAM;
    }
    innerStart |= audioSource_ && audioSource_->GetType() == AVScreenCaptureMixMode::MIX_MODE &&
        (state != 0 || micStop);

    MEDIA_LOGI("SyncAudioCaptures: 0x%{public}06" PRIXPTR " newState=%{public}u state=%{public}u "
               "isMicrophoneSwitchTurnOn_=%{public}d micStop=%{public}d micStart=%{public}d innerStart=%{public}d "
               "ignoreMicError=%{public}d",
        FAKE_POINTER(this), newState, state, IsMicrophoneSwitchTurnOn(), micStop, micStart, innerStart, ignoreMicError);
    int32_t ret = MSERR_OK;
    if (innerStart) {
        ret = StartInnerAudioCapture();
    }
    if (micStop && StopMicAudio()) {
#ifdef SUPPORT_CALL
    if ((state & AUDIO_STATE_TEL) && isMicrophoneSwitchTurnOn_) {
        MEDIA_LOGI("Mic unavailable due to call");
        cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
    }
#endif
    }
    if (micStart) {
        int32_t micRet = StartMicAudioCapture(state & AUDIO_STATE_VOIP);
        if (micRet != MSERR_OK) {
            if (!ignoreMicError) {
                return micRet;
            }
            innerStart = true;
        }
    }
    return ret;
}

#ifdef SUPPORT_CALL
int32_t ScreenCaptureServer::TelCallStateUpdated(bool isInTelCall)
{
    auto task = std::make_shared<TaskHandler<void>>([this, isInTelCall] {
        bool keepCapture;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            keepCapture = captureConfig_.strategy.keepCaptureDuringCall;
        }
        if (!keepCapture && isInTelCall && !IsState(CAP_PAUSED)) {
            StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
            Release();
            return;
        }
        if (!IsState(CAP_ACTIVE)) {
            return;
        }
        if (isInTelCall_.load() == isInTelCall) {
            return;
        }
        isInTelCall_.store(isInTelCall);
        std::lock_guard<std::mutex> lock(mutex_);
        SyncAudioCaptures();
    });
    int32_t res = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, MSERR_INVALID_OPERATION, "TelCallStateUpdated EnqueueTask failed.");
    return MSERR_OK;
}
#endif

int32_t ScreenCaptureServer::SetCanvasRotation(bool canvasRotation)
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotation");
    std::lock_guard<std::mutex> lock(mutex_);
    canvasRotation_ = canvasRotation;
    MEDIA_LOGI("ScreenCaptureServer::SetCanvasRotation, canvasRotation:%{public}d", canvasRotation);
    CHECK_AND_RETURN_RET(IsState(CAP_ACTIVE), MSERR_OK);  // Before Start
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotation end.", FAKE_POINTER(this));
    return SetCanvasRotationInner();
}

int32_t ScreenCaptureServer::SetCanvasRotationInner()
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotationInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotationInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(virtualScreenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
        "SetCanvasRotation failed virtual screen not init");
    auto ret = Rosen::ScreenManager::GetInstance().SetVirtualMirrorScreenCanvasRotation(virtualScreenId_,
        canvasRotation_);
    CHECK_AND_RETURN_RET_LOG(!CheckAppVersionForUnsupport(ret), MSERR_UNSUPPORT,
        "SetVirtualMirrorScreenCanvasRotation failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_INVALID_OPERATION,
        "SetVirtualMirrorScreenCanvasRotation failed, ret: %{public}d", ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotationInner OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetContentAutoRotation(bool contentAutoRotation)
{
    MediaTrace trace("ScreenCaptureServer::SetContentAutoRotation");
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_CONFIG), MSERR_INVALID_OPERATION,
        "SetContentAutoRotation failed, capture is not CREATED, state:%{public}d", captureState_.load());
    canvasRotation_ = contentAutoRotation;
    MEDIA_LOGI("ScreenCaptureServer::SetContentAutoRotation, contentAutoRotation:%{public}d", canvasRotation_);
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
    if (!IsState(CAP_RUNNING)) {
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
    if (!IsState(CAP_ACTIVE)) {
        MEDIA_LOGE("ResizeCanvas captureState_ invalid, captureState_:%{public}d", captureState_.load());
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

    auto resizeRet = Rosen::ScreenManager::GetInstance().ResizeVirtualScreen(virtualScreenId_, width, height);
    MEDIA_LOGI("ScreenCaptureServer::ResizeCanvas, ResizeVirtualScreen end, ret: %{public}d ", resizeRet);
    CHECK_AND_RETURN_RET_LOG(!CheckAppVersionForUnsupport(resizeRet), MSERR_UNSUPPORT,
        "ResizeCanvas failed, resizeRet: %{public}d", resizeRet);
    CHECK_AND_RETURN_RET_LOG(resizeRet == DMError::DM_OK, MSERR_INVALID_OPERATION, "ResizeVirtualScreen failed");

    return MSERR_OK;
}

int32_t ScreenCaptureServer::UpdateSurface(sptr<Surface> surface)
{
    CHECK_AND_RETURN_RET_NOLOG(isSurfaceMode_, MSERR_INVALID_OPERATION);
    MediaTrace trace("ScreenCaptureServer::UpdateSurface");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::UpdateSurface start");
    if (!IsState(CAP_RUNNING)) {
        MEDIA_LOGE("UpdateSurface captureState_ invalid, captureState_:%{public}d", captureState_.load());
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_OPERATION, "UpdateSurface failed, invalid param");

    auto res = Rosen::ScreenManager::GetInstance().SetVirtualScreenSurface(virtualScreenId_, surface);
    MEDIA_LOGI("UpdateSurface, ret: %{public}d ", res);
    CHECK_AND_RETURN_RET_LOG(res == DMError::DM_OK, MSERR_UNSUPPORT, "UpdateSurface failed");
    surface_ = surface;

    return MSERR_OK;
}

int32_t ScreenCaptureServer::SkipPrivacyMode(const std::vector<uint64_t> &windowIDsVec)
{
    MediaTrace trace("ScreenCaptureServer::SkipPrivacyMode");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SkipPrivacyMode, windowIDsVec size:%{public}d",
        static_cast<int32_t>(windowIDsVec.size()));
    for (size_t i = 0; i < windowIDsVec.size(); i++) {
        MEDIA_LOGD("SkipPrivacyMode windowIDsVec value :%{public}" PRIu64, windowIDsVec[i]);
    }
    skipPrivacyWindowIDsVec_.assign(windowIDsVec.begin(), windowIDsVec.end());
    CHECK_AND_RETURN_RET(IsState(CAP_ACTIVE), MSERR_OK); // Before Start
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
    CHECK_AND_RETURN_RET_LOG(!CheckAppVersionForUnsupport(ret), MSERR_UNKNOWN_UNSUPPORT,
        "SetVirtualScreenSecurityExemption failed, ret: %{public}d", ret);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
        "SkipPrivacyModeInner failed, ret: %{public}d", ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SkipPrivacyModeInner OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMaxVideoFrameRate(int32_t frameRate)
{
    MediaTrace trace("ScreenCaptureServer::SetMaxVideoFrameRate");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SetMaxVideoFrameRate start, frameRate:%{public}d", frameRate);
    if (!IsState(CAP_ACTIVE)) {
        MEDIA_LOGE("SetMaxVideoFrameRate captureState_ invalid, captureState_:%{public}d", captureState_.load());
        return MSERR_INVALID_OPERATION;
    }
    if (frameRate <= 0) {
        MEDIA_LOGE("SetMaxVideoFrameRate frameRate is invalid, frameRate:%{public}d", frameRate);
        return MSERR_INVALID_VAL;
    }

    uint32_t actualRefreshRate = 0;
    auto res = Rosen::ScreenManager::GetInstance().SetVirtualScreenMaxRefreshRate(virtualScreenId_,
        static_cast<uint32_t>(frameRate), actualRefreshRate);
    CHECK_AND_RETURN_RET_LOG(!CheckAppVersionForUnsupport(res), MSERR_UNSUPPORT,
        "SetVirtualScreenMaxRefreshRate failed, res: %{public}d", res);
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
    auto ret = Rosen::ScreenManager::GetInstance().SetVirtualMirrorScreenScaleMode(
        virtualScreenId_, GetScreenScaleMode(captureConfig_.strategy.fillMode));
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, static_cast<int32_t>(ret),
        "SetScreenScaleMode failed, ret: %{public}d", ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenScaleMode OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopAudioCapture start.", FAKE_POINTER(this));
    std::lock_guard<std::mutex> audioLock(audioMutex_);
    if (micAudioCapture_) {
        micAudioCapture_->Stop();
    }
    if (innerAudioCapture_) {
        innerAudioCapture_->Stop();
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopAudioCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StartMicAudioCapture(bool isVoip)
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartMicAudioCapture start, dataType:%{public}d, "
        "micCapInfo.state:%{public}d, isVoip:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.micCapInfo.state, isVoip);
    CHECK_AND_RETURN_RET(!(micAudioCapture_ && micAudioCapture_->IsRecording()), MSERR_OK);
    if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        if (micAudioCapture_ == nullptr) {
            std::string threadName = captureConfig_.dataType == DataType::ORIGINAL_STREAM
                ? GenerateThreadNameByPrefix("OS_SMicAd")
                : GenerateThreadNameByPrefix("OS_FMicAd");
            ScreenCaptureContentFilter contentFilterMic;
            micAudioCapture_ = std::make_shared<AudioCapturerWrapper>(
                captureConfig_.audioInfo.micCapInfo, cbProxy_, std::move(threadName), contentFilterMic);
            CHECK_AND_RETURN_RET_LOG(micAudioCapture_ != nullptr, MSERR_UNKNOWN, "CreateMicAudioCapture failed");
        }
        MediaTrace trace("ScreenCaptureServer::StartMicAudioCapture");
        micAudioCapture_->SetIsInVoIPCall(isVoip);
        int32_t ret = micAudioCapture_->Start(appInfo_);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StartMicAudioCapture failed");
            cbProxy_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            return ret;
        }
        if (audioSource_) {
            audioSource_->SetMicCapture(micAudioCapture_);
        }
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartMicAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StopVideoCapture");
    MEDIA_LOGI("StopVideoCapture");
    if ((virtualScreenId_ < 0) || ((consumer_ == nullptr) && !isSurfaceMode_)) {
        MEDIA_LOGI("StopVideoCapture IGNORED, video capture not start");
        CHECK_AND_RETURN_RET(surfaceCb_ != nullptr, MSERR_OK);
        (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->StopBufferThread();
        (static_cast<ScreenCapBufferConsumerListener *>(surfaceCb_.GetRefPtr()))->Release();
        surfaceCb_ = nullptr;
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
        {
            std::lock_guard<std::mutex> audioLock(audioMutex_);
            if (audioSource_ && audioSource_->GetType() == AVScreenCaptureMixMode::MIX_MODE &&
                audioSource_->IsInWaitMicSyncState() && innerAudioCapture_ && innerAudioCapture_->IsRecording()) {
                int64_t currentAudioTime;
                innerAudioCapture_->GetCurrentAudioTime(currentAudioTime);
                MEDIA_LOGI("0x%{public}06" PRIXPTR " UseUpAllLeftBuffer currentAudioTime: %{public}" PRId64,
                    FAKE_POINTER(this), currentAudioTime);
                innerAudioCapture_->UseUpAllLeftBufferUntil(currentAudioTime);
            }
        }
        ret = recorder_->Stop(false);
        TRUE_LOG(ret != MSERR_OK, MEDIA_LOGE, "StopScreenCaptureRecorder recorder stop failed, ret:%{public}d", ret);
        DestroyVirtualScreen();
        recorder_->Release();
        recorder_ = nullptr;
        StopAudioCapture();
    }
    showCursor_ = true;
    surfaceIdList_ = {};
    surfaceTypeList_ = {};
    isConsumerStart_ = false;
    return ret == MSERR_OK ? MSERR_OK : MSERR_UNKNOWN_RECORDER_STOP;
}

int32_t ScreenCaptureServer::StopAndRelease(AVScreenCaptureStateCode state)
{
    auto task = std::make_shared<TaskHandler<void>>([this, state] {
        if (!IsState(CAP_ALIVE)) {
            return;
        }
        StopScreenCaptureByEvent(state);
        Release();
    });
    int32_t res = taskQue_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, MSERR_INVALID_OPERATION, "StopAndRelease EnqueueTask failed.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopScreenCaptureByEvent(AVScreenCaptureStateCode stateCode)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCaptureByEvent S", FAKE_POINTER(this));
    MediaTrace trace("ScreenCaptureServer::StopScreenCaptureByEvent");
    if (IsState(CAP_ALIVE)) {
        std::lock_guard<std::mutex> lock(mutex_);
        return StopScreenCaptureInner(stateCode);
    }
    MEDIA_LOGI("StopScreenCaptureByEvent repeat, capture is STOPPED.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopScreenCaptureInner(AVScreenCaptureStateCode stateCode)
{
    MediaTrace trace("ScreenCaptureServer::StopScreenCaptureInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopScreenCaptureInner start, stateCode:%{public}d.",
        FAKE_POINTER(this), stateCode);
    ON_SCOPE_EXIT(0) { captureState_ = AVScreenCaptureState::STOPPED; };
    cbProxy_->SetBufferActive(false);
    if (IsState(CAP_ALIVE) && !IsState(CAP_ACTIVE)) {
        StopNotStartedScreenCapture(stateCode);
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET(IsState(CAP_ALIVE), MSERR_OK);
    int32_t ret = MSERR_OK;
    if (isPresentPickerPopWindow_) {
        DestroyPopWindow();
        isPresentPickerPopWindow_ = false;
    }
    DestroyPrivacySheet();
    if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
        ret = StopScreenCaptureRecorder();
    } else if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        ret = StopAudioAndVideoCapture();
    } else {
        MEDIA_LOGW("StopScreenCaptureInner unsupport and ignore");
        return MSERR_OK;
    }
    SetErrorInfo(MSERR_OK, "normal stopped", StopReason::NORMAL_STOPPED, IsUserPrivacyAuthorityNeeded());
    PostStopScreenCapture(stateCode);
    listenerManager_->UnregisterListeners();
    PublishScreenCaptureEvent("stop");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopScreenCaptureInner end.", FAKE_POINTER(this));
    return ret;
}

int32_t ScreenCaptureServer::StopAudioAndVideoCapture()
{
    int32_t retAudio = StopAudioCapture();
    int32_t retVideo = StopVideoCapture();
    int32_t ret = (retAudio == MSERR_OK && retVideo == MSERR_OK) ? MSERR_OK : MSERR_STOP_FAILED;
    return ret;
}

void ScreenCaptureServer::StopNotStartedScreenCapture(AVScreenCaptureStateCode stateCode)
{
    DestroyPopWindow();
    providers_->GetScreenCaptureMonitor().CallOnScreenCaptureFinished(appInfo_.appPid);
    cbProxy_->OnStateChange(stateCode);
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
    CHECK_AND_RETURN_RET_LOG(!bundleName.empty(), false, "Failed to get screenrecorder bundlename.");
    AppExecFwk::ElementName element("", bundleName, "PrivacyControlAbility");

    want.SetElement(element);
    want.SetParam("appLabel", callingLabel_);
    want.SetParam("sessionId", sessionId_);
    want.SetParam("terminateSelf", true);
    ErrCode ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want,
        AAFwk::DEFAULT_INVAL_VALUE, appUserId_.load());
    MEDIA_LOGI("DestroyPrivacySheet StartAbility end %{public}d", ret);
    if (ret != ERR_OK) {
        MEDIA_LOGE("Failed to start ability to destroy privacy sheet, error code : %{public}d", ret);
    }

    return ret == ERR_OK;
}

bool ScreenCaptureServer::DestroyPopWindow()
{
    if (!IsState(CAP_POPUP) && !isPresentPickerPopWindow_) {
        MEDIA_LOGI("window not pop up, no need to destroy.");
        return true;
    }
#if defined(PC_STANDARD) && defined(SUPPORT_SCREEN_CAPTURE_PICKER)
    if (IsPickerPopUp()) {
        MEDIA_LOGI("DestroyPopWindow end, type: picker, deviceType: PC.");
        ErrCode ret = ERR_INVALID_VALUE;
        AAFwk::Want want;
        AppExecFwk::ElementName element("", GetScreenCaptureSystemParam()[SYS_SCR_RECR_KEY], SELECT_ABILITY_NAME);
        want.SetElement(element);
        want.SetParam("appLabel", callingLabel_);
        want.SetParam("sessionId", sessionId_);
        want.SetParam("terminateSelf", true); // inform picker to terminateSelf
        ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want,
        AAFwk::DEFAULT_INVAL_VALUE, appUserId_.load());
        MEDIA_LOGI("Destroy picker end %{public}d, DeviceType: PC", ret);
        return ret == ERR_OK;
    }
#endif
    if (connection_ != nullptr) {
        MEDIA_LOGI("DestroyPopWindow close dialog");
        return connection_->CloseDialog();
    }
    return true;
}

bool ScreenCaptureServer::IsLastStartedPidInstance(int32_t pid)
{
    std::list<int32_t> pidList = providers_->GetScreenCaptureMonitor().IsScreenCaptureWorking();
    bool isLast = find(pidList.begin(), pidList.end(), pid) == pidList.end();
    MEDIA_LOGD("IsLastStartedPidInstance pid: %{public}d, isLast: %{public}d", pid, isLast);
    return isLast;
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
    UpdateHighlightOutline(false);
    providers_->GetScreenCaptureMonitor().CallOnScreenCaptureFinished(appInfo_.appPid);
    cbProxy_->OnStateChange(stateCode);
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    if (isPrivacyAuthorityEnabled_ && !isSystemRecorder_.load() && !isScreenCaptureAuthority_) {
        // Remove real time notification
        int32_t ret = NotificationHelper::CancelNotification(notificationId_);
        MEDIA_LOGI("StopScreenCaptureInner CancelNotification id:%{public}d, ret:%{public}d ", notificationId_, ret);
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
    if (statisticalEventInfo_.startLatency == -1) {
        statisticalEventInfo_.captureDuration = -1; // latency -1 means invalid
    } else {
        int64_t endTime = GetCurrentMillisecond();
        statisticalEventInfo_.captureDuration = static_cast<int32_t>(endTime - startTime_ -
            statisticalEventInfo_.startLatency);
    }
    isScreenCaptureAuthority_ = false;
    isPresentPickerPopWindow_ = false;
    captureState_ = AVScreenCaptureState::STOPPED;
}

int32_t ScreenCaptureServer::StopScreenCapture()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances StopScreenCapture", FAKE_POINTER(this));
    return StopScreenCaptureByEvent(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
}

void ScreenCaptureServer::Release()
{
    ReleaseInner();
}

void ScreenCaptureServer::ReleaseInner()
{
    MediaTrace trace("ScreenCaptureServer::ReleaseInner");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner S", FAKE_POINTER(this));
    auto sessionId = SESSION_ID_INVALID;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        sessionId = sessionId_;
        if (IsState(CAP_ALIVE)) {
            StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
            MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner Stop done, sessionId:%{public}d",
                FAKE_POINTER(this), sessionId_);
            if (isSystemRecorder_.load()) {
                providers_->TryUpdateSettingsValue(SHOW_TOUCH_HINT_KEY, "");
            }
        }
        skipPrivacyWindowIDsVec_.clear();
        ScreenCaptureServerManager::GetInstance().RemoveSaAppInfoMap(saUid_);
        sessionId_ = SESSION_ID_INVALID;
        SetMetaDataReport();
    }
    MEDIA_LOGI("ScreenCaptureServer::ReleaseInner before RemoveScreenCaptureServerMap");
    ScreenCaptureServerManager::GetInstance().RemoveScreenCaptureServerMap(sessionId);
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
    CHECK_AND_RETURN_RET_LOG(captureState_ < AVScreenCaptureState::POPUP_WINDOW, MSERR_INVALID_OPERATION_CREATE,
        "strategy can not be modified after screen capture started");
    MEDIA_LOGI("SetScreenCaptureStrategy enableDeviceLevelCapture: %{public}d, keepCaptureDuringCall: %{public}d,"
               "strategyForPrivacyMaskMode: %{public}d, canvasFollowRotation: %{public}d, enableBFrame: %{public}d,"
               "pickerPopUp: %{public}d, fillMode: %{public}d, enablePause: %{public}d",
        strategy.enableDeviceLevelCapture, strategy.keepCaptureDuringCall, strategy.strategyForPrivacyMaskMode,
        strategy.canvasFollowRotation, strategy.enableBFrame, static_cast<int32_t>(strategy.pickerPopUp),
        static_cast<int32_t>(strategy.fillMode), strategy.enablePause);
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
    if (appUserId_ != -1) {
        request.SetOwnerUserId(appUserId_.load());
    }
    request.SetNotificationId(notificationId_);
    request.SetOwnerUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetRemoveAllowed(false);
    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    request.SetUnremovable(true);
    request.SetLittleIcon(GetPixelMap(ICON_PATH_NOTIFICATION));
    if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
        request.SetWantAgent(GetWantAgent(callingLabel_, sessionId_));
        MEDIA_LOGI("SetupPublishRequest, setWantAgent success");
    }
}

void ScreenCaptureServer::PrivacyProtected(ScreenId &virtualScreenId, bool systemPrivacyProtectionSwitch,
    bool appPrivacyProtectionSwitch)
{
    std::vector<ScreenId> screenIds;
    screenIds.push_back(virtualScreenId);
    auto ret = Rosen::ScreenManager::GetInstance().SetScreenSkipProtectedWindow(screenIds,
        systemPrivacyProtectionSwitch);
    MEDIA_LOGI("SystemPrivacyProtected SetScreenSkipProtectedWindow done, ret: %{public}d", ret);

    std::vector<std::string> privacyWindowTags;
    if (systemPrivacyProtectionSwitch == appPrivacyProtectionSwitch) {
        privacyWindowTags.assign({"SCB_KEYBOARD_DEFAULT", "TAG_SCREEN_PROTECTION_SENSITIVE_APP"});
        ret = Rosen::ScreenManager::GetInstance().SetScreenPrivacyWindowTagSwitch(virtualScreenId,
            std::move(privacyWindowTags), appPrivacyProtectionSwitch);
        MEDIA_LOGI("AppPrivacyProtected SetScreenSkipProtectedWindow done, ret: %{public}d", ret);
    } else {
        privacyWindowTags.assign({"SCB_KEYBOARD_DEFAULT"});
        ret = Rosen::ScreenManager::GetInstance().SetScreenPrivacyWindowTagSwitch(virtualScreenId,
            std::move(privacyWindowTags), systemPrivacyProtectionSwitch);
        MEDIA_LOGI("KeyboardPrivacyProtected SetScreenSkipProtectedWindow done, ret: %{public}d", ret);

        privacyWindowTags.assign({"TAG_SCREEN_PROTECTION_SENSITIVE_APP"});
        ret = Rosen::ScreenManager::GetInstance().SetScreenPrivacyWindowTagSwitch(virtualScreenId,
            std::move(privacyWindowTags), appPrivacyProtectionSwitch);
        MEDIA_LOGI("AppPrivacyProtected SetScreenSkipProtectedWindow done, ret: %{public}d", ret);
    }
}

bool ScreenCaptureServer::IsSkipPrivacyWindow()
{
#ifdef SUPPORT_SCREEN_CAPTURE_PICKER
    return isSystemRecorder_.load() || (CheckCustScrRecPermission() && !IsPickerPopUp());
#else
    return isSystemRecorder_.load() || CheckCustScrRecPermission();
#endif
}

int32_t ScreenCaptureServer::PauseScreenCaptureInner(AVScreenCaptureStateCode stateCode)
{
    MediaTrace trace("ScreenCaptureServer::PauseScreenCaptureInner");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances PauseScreenCaptureInner, state:%{public}d, stateCode:%{public}d",
        FAKE_POINTER(this), captureState_.load(), static_cast<int32_t>(stateCode));
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_RUNNING), MSERR_INVALID_OPERATION_STARTED_RESUMED,
        "PauseScreenCaptureInner failed, not in STARTED or RESUMED, state:%{public}d", captureState_.load());
    CHECK_AND_RETURN_RET_LOG(captureConfig_.strategy.enablePause,
        MSERR_INVALID_OPERATION_ENABLEPAUSE, "PauseScreenCaptureInner failed, enablePause is false");

    int32_t ret = MSERR_OK;
    if (dataMode_ == AVScreenCaptureDataMode::FILE_MODE) {
        CHECK_AND_RETURN_RET_LOG((ret = PauseRecorder()) == MSERR_OK,
            (StopCaptureOnError("pauseRecording fail"), ret),
            "PauseScreenCaptureInner: PauseRecorder failed, ret:%{public}d", ret);
    }

    CHECK_AND_RETURN_RET_LOG((ret = PauseVideoCapture()) == MSERR_OK,
        (StopCaptureOnError("pauseRecording fail"), ret),
        "PauseScreenCaptureInner: PauseVideoCapture failed, ret:%{public}d", ret);

    CHECK_AND_RETURN_RET_LOG((ret = StopAudioCapture()) == MSERR_OK,
        (StopCaptureOnError("pauseRecording fail"), ret),
        "PauseScreenCaptureInner: StopAudioCapture failed, ret:%{public}d", ret);

    {
        std::lock_guard<std::mutex> audioLock(audioMutex_);
        if (audioSource_) {
            audioSource_->Pause();
        }
    }

    isTimePaused_ = true;
    UpdateLiveViewContent();
    NotificationRequest request;
    SetupPublishRequest(request);
    NotificationHelper::PublishNotification(request);

    captureState_ = AVScreenCaptureState::PAUSED;
    cbProxy_->OnStateChange(stateCode);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances PauseScreenCaptureInner success", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::PauseScreenCapture()
{
    return PauseScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_PAUSED_BY_APP);
}

int32_t ScreenCaptureServer::ResumeScreenCapture()
{
    return ResumeScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_RESUMED_BY_APP);
}

int32_t ScreenCaptureServer::ResumeScreenCaptureInner(AVScreenCaptureStateCode stateCode)
{
    MediaTrace trace("ScreenCaptureServer::ResumeScreenCaptureInner");
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ResumeScreenCaptureInner, state:%{public}d, stateCode:%{public}d",
        FAKE_POINTER(this), captureState_.load(), static_cast<int32_t>(stateCode));
    CHECK_AND_RETURN_RET_LOG(IsState(CAP_PAUSED), MSERR_INVALID_OPERATION_PAUSED,
        "ResumeScreenCaptureInner failed, cannot resume in current state, state:%{public}d", captureState_.load());
    CHECK_AND_RETURN_RET_LOG(captureConfig_.strategy.enablePause,
        MSERR_INVALID_OPERATION_ENABLEPAUSE, "ResumeScreenCaptureInner failed, enablePause is false");

#ifdef SUPPORT_CALL
    if (!captureConfig_.strategy.keepCaptureDuringCall && isInTelCall_) {
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
        lock.unlock();
        Release();
        return MSERR_OK;
    }
#endif

    int32_t ret = MSERR_OK;
    CHECK_AND_RETURN_RET_LOG((ret = ResumeVideoCapture()) == MSERR_OK,
        (StopCaptureOnError("resumeRecording fail"), ret),
        "ResumeScreenCaptureInner: ResumeVideoCapture failed, ret:%{public}d", ret);

    ret = SyncAudioCaptures(true);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, (StopCaptureOnError("resumeRecording fail"), ret),
        "ResumeScreenCaptureInner: SyncAudioCaptures failed, ret:%{public}d", ret);

    {
        std::lock_guard<std::mutex> audioLock(audioMutex_);
        if (audioSource_) {
            audioSource_->Resume();
        }
    }

    if (dataMode_ == AVScreenCaptureDataMode::FILE_MODE) {
        CHECK_AND_RETURN_RET_LOG((ret = ResumeRecorder()) == MSERR_OK,
            (StopCaptureOnError("resumeRecording fail"), ret),
            "ResumeScreenCaptureInner: ResumeRecorder failed, ret:%{public}d", ret);
    }

    isTimePaused_ = false;
    UpdateLiveViewContent();
    NotificationRequest request;
    SetupPublishRequest(request);
    NotificationHelper::PublishNotification(request);

    captureState_ = AVScreenCaptureState::RESUMED;
    cbProxy_->OnStateChange(stateCode);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ResumeScreenCaptureInner success", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::PauseVideoCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PauseVideoCapture start.", FAKE_POINTER(this));
    if (captureConfig_.captureMode == CAPTURE_VIRTUAL_EXTENDED_SCREEN) {
        DestroyVirtualScreen();
        MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PauseVideoCapture end.", FAKE_POINTER(this));
        return MSERR_OK;
    }
    if (virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID && isConsumerStart_) {
        std::vector<ScreenId> screenIds;
        screenIds.push_back(virtualScreenId_);
        Rosen::ScreenManager::GetInstance().StopMirror(screenIds);
        isConsumerStart_ = false;
        MEDIA_LOGI("PauseVideoCapture: StopMirror success");
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PauseVideoCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ResumeVideoCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ResumeVideoCapture start.", FAKE_POINTER(this));
    if (captureConfig_.captureMode == CAPTURE_VIRTUAL_EXTENDED_SCREEN) {
        sptr<OHOS::Surface> surface = isSurfaceMode_ ? surface_ : producerSurface_;
        CHECK_AND_RETURN_RET_LOG(surface != nullptr, MSERR_INVALID_OPERATION,
            "ResumeVideoCapture surface is null");
        int32_t ret = CreateVirtualScreen(surface);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "ResumeVideoCapture CreateVirtualScreen failed");
        MEDIA_LOGI("ResumeVideoCapture: recreate virtual screen success");
        return MSERR_OK;
    }
    if (virtualScreenId_ >= 0 && virtualScreenId_ != SCREEN_ID_INVALID) {
        int32_t ret = MakeVirtualScreenMirror();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_MAKE_MIRROR,
            "ResumeVideoCapture: MakeVirtualScreenMirror failed, ret:%{public}d", ret);
        isConsumerStart_ = true;
        MEDIA_LOGI("ResumeVideoCapture: MakeVirtualScreenMirror success");
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ResumeVideoCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::PauseRecorder()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PauseRecorder start.", FAKE_POINTER(this));
    if (recorder_) {
        auto ret = recorder_->Pause();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_PAUSE,
            "ScreenCaptureServer: 0x%{public}06" PRIXPTR "PauseRecorder failed %{public}d", FAKE_POINTER(this), ret);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PauseRecorder end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ResumeRecorder()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ResumeRecorder start.", FAKE_POINTER(this));
    if (recorder_) {
        auto ret = recorder_->Resume();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN_RECORDER_RESUME,
            "ScreenCaptureServer: 0x%{public}06" PRIXPTR "ResumeRecorder failed %{public}d", FAKE_POINTER(this), ret);
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ResumeRecorder end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::AddWatermark(std::shared_ptr<AVBuffer> &watermarkBuffer, int32_t width, int32_t height,
    int32_t &watermarkCount)
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AddWatermark in, width: %{public}d height: %{public}d",
        FAKE_POINTER(this), width, height);
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::CREATED, MSERR_INVALID_OPERATION_CREATE,
        "AddWatermark captureState_ is not CREATED, not allowed. captureState_: %{public}d", captureState_.load());
    CHECK_AND_RETURN_RET_LOG(captureConfig_.dataType == DataType::CAPTURE_FILE, MSERR_UNKNOWN,
        "dataType is not CAPTURE_FILE. dataType: %{public}d", captureConfig_.dataType);
    if (!recorder_) {
        recorder_ = providers_->CreateRecorder();
    }
    CHECK_AND_RETURN_RET_LOG(recorder_ != nullptr, MSERR_UNKNOWN_CREAT_RECORDER, "Create Recoder failed");
    auto ret = recorder_->AddWatermark(watermarkBuffer, width, height, watermarkCount);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "ScreenCaptureServer: 0x%{public}06" PRIXPTR
        "AddWatermark failed %{public}d", FAKE_POINTER(this), ret);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AddWatermark end.", FAKE_POINTER(this));
    return MSERR_OK;
}

void ScreenCaptureServer::StopCaptureOnError(const std::string &reportMsg)
{
    cbProxy_->OnError(ScreenCaptureErrorType::SCREEN_CAPTURE_ERROR_INTERNAL,
        AVScreenCaptureErrorCode::SCREEN_CAPTURE_ERR_UNKNOWN);
    StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVALID);
}

extern "C" {
__attribute__((visibility("default"))) OHOS::Media::IScreenCaptureService *CreateScreenCaptureServer(
    OHOS::Media::IScreenCaptureServiceProviders *providers)
{
    std::unique_ptr<OHOS::Media::IScreenCaptureServiceProviders> providersOwner(providers);
    if (providers == nullptr) {
        return nullptr;
    }
    auto service = ScreenCaptureServer::Create(std::move(providersOwner));
    if (service == nullptr) {
        return nullptr;
    }
    auto *ptr = static_cast<ScreenCaptureServer *>(service.get());
    std::lock_guard<std::mutex> lock(g_serverMapMutex);
    g_serverMap[ptr] = std::move(service);
    return ptr;
}

__attribute__((visibility("default"))) void DestroyScreenCaptureServer(OHOS::Media::IScreenCaptureService *server)
{
    if (server == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_serverMapMutex);
    g_serverMap.erase(server);
}
}
} // namespace Media
} // namespace OHOS
