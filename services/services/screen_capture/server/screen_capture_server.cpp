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
static const std::string BUTTON_NAME_MIC = "mic";
static const std::string BUTTON_NAME_STOP = "stop";
static const std::string ICON_PATH_CAPSULE_STOP = "/etc/screencapture/capsule_stop.svg";
static const std::string ICON_PATH_NOTIFICATION = "/etc/screencapture/notification.png";
static const std::string ICON_PATH_MIC = "/etc/screencapture/mic.svg";
static const std::string ICON_PATH_MIC_OFF = "/etc/screencapture/mic_off.svg";
static const std::string ICON_PATH_STOP = "/etc/screencapture/stop.png";
static const std::string BACK_GROUND_COLOR = "#E84026";
#ifdef PC_STANDARD
static const std::string SELECT_ABILITY_NAME = "SelectWindowAbility";
static const int32_t SELECT_WINDOW_MISSION_ID_NUM_MAX = 2;
#endif
static const int32_t SVG_HEIGHT = 80;
static const int32_t SVG_WIDTH = 80;
static const int32_t MICROPHONE_OFF = 0;
static const int32_t MICROPHONE_STATE_COUNT = 2;
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    static const int32_t NOTIFICATION_MAX_TRY_NUM = 3;
#endif
static const int32_t MOUSE_DEVICE = 5;

static const auto NOTIFICATION_SUBSCRIBER = NotificationSubscriber();
static constexpr int32_t AUDIO_CHANGE_TIME = 200000; // 200 ms

std::map<int32_t, std::weak_ptr<ScreenCaptureServer>> ScreenCaptureServer::serverMap_;
const int32_t ScreenCaptureServer::maxSessionId_ = 8;
const int32_t ScreenCaptureServer::maxAppLimit_ = 4;
UniqueIDGenerator ScreenCaptureServer::gIdGenerator_(ScreenCaptureServer::maxSessionId_);
std::list<int32_t> ScreenCaptureServer::startedSessionIDList_;
const int32_t ScreenCaptureServer::maxSessionPerUid_ = 2;

std::shared_mutex ScreenCaptureServer::mutexServerMapRWGlobal_;
std::shared_mutex ScreenCaptureServer::mutexListRWGlobal_;

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

MouseChangeListener::MouseChangeListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

int32_t MouseChangeListener::GetDeviceInfo(int32_t deviceId, std::shared_ptr<InputDeviceInfo> deviceInfo)
{
    MEDIA_LOGI("Get device info by deviceId %{public}d", deviceId);

    std::function<void(std::shared_ptr<MMI::InputDevice>)> callback = 
        [&deviceInfo](std::shared_ptr<MMI::InputDevice> device) {
            if (device) {
                deviceInfo->SetType(device->GetType());
                deviceInfo->SetName(device->GetName());
            }
        };
    int32_t ret = MMI::InputManager::GetInstance()->GetDevice(
        deviceId, [&callback](std::shared_ptr<MMI::InputDevice> device) {callback(device);});
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
        "Calling method GetDevice failed. Device ID: %{public}d", deviceId);
    return ret;
}

void MouseChangeListener::OnDeviceAdded(int32_t deviceId, const std::string &type)
{
    MEDIA_LOGI("OnDeviceAdded start.");
    std::shared_ptr<InputDeviceInfo> deviceInfo = std::make_shared<InputDeviceInfo>();
    int32_t ret = GetDeviceInfo(deviceId, deviceInfo);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("Get deviceInfo(%{public}d) failed", deviceId);
        return;
    }
    MEDIA_LOGI("Add device type: %{public}d, name:%{public}s", deviceInfo->GetType(), deviceInfo->GetName().c_str());

    if (deviceInfo->GetType() == MOUSE_DEVICE) {
        MEDIA_LOGI("Add device is mouse, type (%{public}d)", deviceInfo->GetType());
        auto scrServer = screenCaptureServer_.lock();
        ret = scrServer->ShowCursorInner();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("OnDeviceAdded ShowCursorInner failed");
        }
    }
    MEDIA_LOGI("OnDeviceAdded end.");
}

void MouseChangeListener::OnDeviceRemoved(int32_t deviceId, const std::string &type)
{
    MEDIA_LOGI("OnDeviceRemoved start, deviceId: %{public}d, type:%{public}s", deviceId, type.c_str());
    std::shared_ptr<InputDeviceInfo> deviceInfo = std::make_shared<InputDeviceInfo>();
    int32_t ret = GetDeviceInfo(deviceId, deviceInfo);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("Get deviceInfo(%{public}d) failed", deviceId);
        return;
    }
    MEDIA_LOGI("Remove device type: %{public}d, name:%{public}s",
        deviceInfo->GetType(), deviceInfo->GetName().c_str());
    
    if (deviceInfo->GetType() != MOUSE_DEVICE) {
        MEDIA_LOGI("Remove device is not mouse");
        return;
    }
    auto scrServer = screenCaptureServer_.lock();
    ret = scrServer->ShowCursorInner();
    if (ret != MSERR_OK) {
        MEDIA_LOGE("OnDeviceRemoved ShowCursorInner failed");
    }
    MEDIA_LOGI("OnDeviceRemoved end.");
}

PrivateWindowListenerInScreenCapture::PrivateWindowListenerInScreenCapture(
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
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
                if ((iter->second).lock() != nullptr) {
                    if (curAppUid == (iter->second).lock()->GetAppUid()) {
                        countForUid++;
                    }
                    CHECK_AND_RETURN_RET_LOG(countForUid < ScreenCaptureServer::maxSessionPerUid_, false,
                        "Create failed, uid(%{public}d) has created too many ScreenCaptureServer instances", curAppUid);
                }
            }
    }
    MEDIA_LOGI("CheckScreenCaptureSessionIdLimit end.");
    return true;
}

void ScreenCaptureServer::CountScreenCaptureAppNum(std::set<int32_t>& appSet)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    for (auto iter = ScreenCaptureServer::serverMap_.begin(); iter != ScreenCaptureServer::serverMap_.end(); iter++) {
        if (iter->second.lock() != nullptr) {
            appSet.insert(iter->second.lock()->GetAppUid());
        }
    }
}

bool ScreenCaptureServer::CheckScreenCaptureAppLimit(int32_t curAppUid)
{
    std::set<int32_t> appSet;
    CountScreenCaptureAppNum(appSet);
    MEDIA_LOGD("appSet.size(): %{public}d", static_cast<int32_t>(appSet.size()));
    if (appSet.find(curAppUid) == appSet.end() &&
        static_cast<int32_t>(appSet.size()) >= ScreenCaptureServer::maxAppLimit_) {
        return false;
    }
    return true;
}

std::shared_ptr<ScreenCaptureServer> ScreenCaptureServer::GetScreenCaptureServerByIdWithLock(int32_t id)
{
    std::unique_lock<std::shared_mutex> lock(ScreenCaptureServer::mutexServerMapRWGlobal_);
    auto iter = ScreenCaptureServer::serverMap_.find(id);
    if (iter == ScreenCaptureServer::serverMap_.end()) {
        return nullptr;
    }
    return (iter->second).lock();
}

std::list<int32_t> ScreenCaptureServer::GetStartedScreenCaptureServerPidList()
{
    std::list<int32_t> startedScreenCapturePidList{};
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        std::shared_ptr<ScreenCaptureServer> currentServer = GetScreenCaptureServerByIdWithLock(sessionId);
        if (currentServer != nullptr) {
            startedScreenCapturePidList.push_back(currentServer->GetAppPid() == 0 ? -1 : currentServer->GetAppPid());
        }
    }
    return startedScreenCapturePidList;
}

int32_t ScreenCaptureServer::CountStartedScreenCaptureServerNumByPid(int32_t pid)
{
    int32_t count = 0;
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        std::shared_ptr<ScreenCaptureServer> currentServer = GetScreenCaptureServerByIdWithLock(sessionId);
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

void ScreenCaptureServer::OnDMPrivateWindowChange(bool hasPrivate)
{
    MEDIA_LOGI("OnDMPrivateWindowChange hasPrivateWindow: %{public}u", hasPrivate);
    if (screenCaptureCb_ != nullptr) {
        screenCaptureCb_->OnStateChange(hasPrivate ?
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_ENTER_PRIVATE_SCENE :
        AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_EXIT_PRIVATE_SCENE);
    }
}

bool ScreenCaptureServer::CanScreenCaptureInstanceBeCreate()
{
    MEDIA_LOGI("CanScreenCaptureInstanceBeCreate start.");
    CHECK_AND_RETURN_RET_LOG(ScreenCaptureServer::serverMap_.size() < ScreenCaptureServer::maxSessionId_, false,
        "ScreenCaptureInstanceCanBeCreate exceed ScreenCaptureServer instances limit.");
    int32_t curAppUid = IPCSkeleton::GetCallingUid();
    MEDIA_LOGD("curAppUid: %{public}d", curAppUid);
    CHECK_AND_RETURN_RET_LOG(CheckScreenCaptureAppLimit(curAppUid), false,
        "CurScreenCaptureAppNum reach limit, cannot create more app.");
    return CheckScreenCaptureSessionIdLimit(curAppUid);
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
    AddScreenCaptureServerMap(id, server);
    return std::static_pointer_cast<IScreenCaptureService>(server);
}

std::shared_ptr<IScreenCaptureService> ScreenCaptureServer::Create()
{
    for (auto sessionId: ScreenCaptureServer::startedSessionIDList_) {
        MEDIA_LOGD("ScreenCaptureServer::Create sessionId: %{public}d", sessionId);
    }
    MEDIA_LOGI("ScreenCaptureServer Create start.");
    CHECK_AND_RETURN_RET_LOG(CanScreenCaptureInstanceBeCreate(), nullptr,
        "Create error, there are too many ScreenCaptureServer instances.");
    return CreateScreenCaptureNewInstance();
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
    if (!keyJson.isNull()) {
        value = keyJson.asString();
    }
}

void ScreenCaptureServer::SetCaptureConfig(CaptureMode captureMode, int32_t missionId)
{
    captureConfig_.captureMode = captureMode;
    if (missionId != -1) { // -1 无效值
        captureConfig_.videoInfo.videoCapInfo.taskIDs.push_back(missionId);
    } else {
        captureConfig_.videoInfo.videoCapInfo.taskIDs = {};
    }
}

void ScreenCaptureServer::PrepareSelectWindow(Json::Value &root, std::shared_ptr<ScreenCaptureServer> &server)
{
    if (root.type() != Json::objectValue) {
        return;
    }
    const Json::Value displayIdJson = root["displayId"];
    if (!displayIdJson.isNull() && displayIdJson.asInt64() >= 0) {
        uint64_t displayId = static_cast<uint64_t>(displayIdJson.asInt64());
        MEDIA_LOGI("Report Select DisplayId: %{public}" PRIu64, displayId);
        server->SetDisplayId(displayId);
        // 手机模式 missionId displayId 均为-1
        server->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_SCREEN, -1);
    }
    const Json::Value missionIdJson = root["missionId"];
    if (!missionIdJson.isNull() && missionIdJson.asInt() >= 0) {
        int32_t missionId = missionIdJson.asInt();
        MEDIA_LOGI("Report Select MissionId: %{public}d", missionId);
        server->SetMissionId(missionId);
        server->SetCaptureConfig(CaptureMode::CAPTURE_SPECIFIED_WINDOW, missionId);
    }
}

int32_t ScreenCaptureServer::ReportAVScreenCaptureUserChoice(int32_t sessionId, const std::string &content)
{
    MEDIA_LOGI("ReportAVScreenCaptureUserChoice sessionId: %{public}d, content: %{public}s",
        sessionId, content.c_str());
    std::shared_ptr<ScreenCaptureServer> server = GetScreenCaptureServerByIdWithLock(sessionId);
    CHECK_AND_RETURN_RET_LOG(server != nullptr, MSERR_UNKNOWN,
        "ReportAVScreenCaptureUserChoice failed to get instance, sessionId: %{public}d", sessionId);
    if (server->captureState_ == AVScreenCaptureState::POPUP_WINDOW) {
        MEDIA_LOGI("ReportAVScreenCaptureUserChoice captureState is %{public}d", AVScreenCaptureState::POPUP_WINDOW);
        Json::Value root;
        std::string choice = "false";
        GetChoiceFromJson(root, content, std::string("choice"), choice);
        if (USER_CHOICE_ALLOW.compare(choice) == 0) {
            PrepareSelectWindow(root, server);
            int32_t ret = server->OnReceiveUserPrivacyAuthority(true);
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret,
                "ReportAVScreenCaptureUserChoice user choice is true but start failed");
            MEDIA_LOGI("ReportAVScreenCaptureUserChoice user choice is true and start success");
            return MSERR_OK;
        } else if (USER_CHOICE_DENY.compare(choice) == 0) {
            return server->OnReceiveUserPrivacyAuthority(false);
        } else {
            MEDIA_LOGW("ReportAVScreenCaptureUserChoice user choice is not support");
        }
    }
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::GetAppPid()
{
    return appInfo_.appPid;
}

int32_t ScreenCaptureServer::GetAppUid()
{
    return appInfo_.appUid;
}

void ScreenCaptureServer::SetDisplayId(uint64_t displayId)
{
    captureConfig_.videoInfo.videoCapInfo.displayId = displayId;
}

void ScreenCaptureServer::SetMissionId(uint64_t missionId)
{
    missionIds_.emplace_back(missionId);
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
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    InitAppInfo();
    instanceId_ = OHOS::HiviewDFX::HiTraceChain::GetId().GetChainId();
    CreateMediaInfo(SCREEN_CAPTRUER, IPCSkeleton::GetCallingUid(), instanceId_);
}

ScreenCaptureServer::~ScreenCaptureServer()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
    ReleaseInner();
    screenCaptureObserverCb_ = nullptr;
    CloseFd();
}

void ScreenCaptureServer::SetSessionId(int32_t sessionId)
{
    sessionId_ = sessionId;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR "sessionId: %{public}d", FAKE_POINTER(this), sessionId_);
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
        "videoSource:%{public}d, state:%{public}d.", videoCapInfo.videoFrameWidth, videoCapInfo.videoFrameHeight,
        videoCapInfo.videoSource, videoCapInfo.state);
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

int32_t ScreenCaptureServer::RequestUserPrivacyAuthority()
{
    MediaTrace trace("ScreenCaptureServer::RequestUserPrivacyAuthority");
    // If Root is treated as whitelisted, how to guarantee RequestUserPrivacyAuthority function by TDD cases.
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " RequestUserPrivacyAuthority start.", FAKE_POINTER(this));
    if (!IsUserPrivacyAuthorityNeeded()) {
        MEDIA_LOGI("Privacy Authority Granted. uid:%{public}d", appInfo_.appUid);
        return MSERR_OK;
    }

    if (isPrivacyAuthorityEnabled_) {
        if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
                .compare(appName_) != 0) {
            return StartPrivacyWindow();
        } else {
            MEDIA_LOGI("ScreenCaptureServer::RequestUserPrivacyAuthority support screenrecorder");
            return MSERR_OK;
        }
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
    captureState_ = AVScreenCaptureState::STARTING;
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
        micAudioCapture_ = nullptr;
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
            if (screenCaptureCb_ != nullptr) {
                screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            }
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
    std::shared_ptr<AudioCapturerWrapper> innerCapture;
    if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        MediaTrace trace("ScreenCaptureServer::StartFileInnerAudioCaptureInner");
        innerCapture = std::make_shared<AudioCapturerWrapper>(captureConfig_.audioInfo.innerCapInfo, screenCaptureCb_,
            std::string(GenerateThreadNameByPrefix("OS_FInnAd")), contentFilter_);
        int32_t ret = innerCapture->Start(appInfo_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileInnerAudioCapture failed");
        if (audioSource_ && audioSource_->GetSpeakerAliveStatus() && !audioSource_->GetIsInVoIPCall() &&
            micAudioCapture_ && micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
            ret = innerCapture->Pause();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartAudioCapture innerCapture Pause failed");
        }
    }
    innerAudioCapture_ = innerCapture;
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileInnerAudioCapture OK.", FAKE_POINTER(this));
    return MSERR_OK;
}
 
int32_t ScreenCaptureServer::StartFileMicAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StartFileMicAudioCapture start, dataType:%{public}d, "
        "micCapInfo.state:%{public}d.",
        FAKE_POINTER(this), captureConfig_.dataType, captureConfig_.audioInfo.micCapInfo.state);
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
            if (screenCaptureCb_ != nullptr) {
                screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            }
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
    int32_t ret = MSERR_UNSUPPORT;
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

void ScreenCaptureServer::SetMouseChangeListener(std::shared_ptr<MouseChangeListener> listener)
{
    mouseChangeListener_ = listener;
}

std::shared_ptr<MouseChangeListener> ScreenCaptureServer::GetMouseChangeListener()
{
    return mouseChangeListener_;
}

bool ScreenCaptureServer::RegisterMMISystemAbilityListener()
{
    MEDIA_LOGI("RegisterMMISystemAbilityListener start.");
    if (mmiListener_ != nullptr) {
        MEDIA_LOGI("RegisterMMISystemAbilityListener already registered");
        return true;
    }
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        MEDIA_LOGE("RegisterMMISystemAbilityListener abilityManager is nullptr");
        return false;
    }
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    sptr<ISystemAbilityStatusChange> listener(new (std::nothrow) MMISystemAbilityListener(screenCaptureServer));
    if (listener == nullptr) {
        MEDIA_LOGE("create listener failed.");
        return false;
    }
    int32_t ret = abilityManager->SubscribeSystemAbility(MULTIMODAL_INPUT_SERVICE_ID, listener);
    if (ret != ERR_OK) {
        MEDIA_LOGE("failed to subscribe systemAbility, ret:%{public}d", ret);
        return false;
    }
    mmiListener_ = listener;
    MEDIA_LOGI("RegisterMMISystemAbilityListener end.");
    return true;
}

bool ScreenCaptureServer::UnRegisterMMISystemAbilityListener()
{
    MEDIA_LOGI("UnRegisterMMISystemAbilityListener start.");
    if (mmiListener_ == nullptr) {
        MEDIA_LOGI("mmiListener already unregistered.");
        return true;
    }
    auto abilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (abilityManager == nullptr) {
        MEDIA_LOGE("UnRegisterMMISystemAbilityListener abilityManager is nullptr");
        return false;
    }
    int32_t ret = abilityManager->UnSubscribeSystemAbility(MULTIMODAL_INPUT_SERVICE_ID, mmiListener_);
    mmiListener_ = nullptr;
    if (ret != ERR_OK) {
        MEDIA_LOGE("failed t subscribe systemAbility, ret:%{public}d", ret);
        return false;
    }
    MEDIA_LOGI("UnRegisterMMISystemAbilityListener end.");
    return true;
}

MMISystemAbilityListener::MMISystemAbilityListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    screenCaptureServer_ = screenCaptureServer;
}

void MMISystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    MEDIA_LOGI("OnAddSystemAbility start.");
    auto scrServer = screenCaptureServer_.lock();
    std::shared_ptr<MouseChangeListener> listener = std::make_shared<MouseChangeListener>(scrServer);
    scrServer->SetMouseChangeListener(listener);
    int32_t ret = MMI::InputManager::GetInstance()->RegisterDevListener("change", listener);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("OnAddSystemAbility RegisterDevListener falied");
    }
    scrServer->ShowCursorInner();
    MEDIA_LOGI("OnAddSystemAbility end.");
}

void MMISystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    auto scrServer = screenCaptureServer_.lock();
    int32_t ret = MMI::InputManager::GetInstance()->UnregisterDevListener("change",
        scrServer->GetMouseChangeListener());
    scrServer->SetMouseChangeListener(nullptr);
    if (ret != MSERR_OK) {
        MEDIA_LOGE("OnRemoveSystemAbility UnregisterDevListener falied");
    }
    MEDIA_LOGI("OnRemoveSystemAbility end.");
}

int32_t ScreenCaptureServer::RegisterMouseChangeListener(std::string type)
{
    MEDIA_LOGI("RegisterMouseChangeListener start.");
    if (mouseChangeListener_ != nullptr) {
        MEDIA_LOGI("RegisterMouseChangeListener mouseChangeListener already registered");
        return MSERR_OK;
    }
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer(shared_from_this());
    mouseChangeListener_ = std::make_shared<MouseChangeListener>(screenCaptureServer);
    int32_t ret = MMI::InputManager::GetInstance()->RegisterDevListener(type, mouseChangeListener_);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "RegisterMouseChangeListener failed");
    MEDIA_LOGI("RegisterMouseChangeListener end.");
    return ret;
}

int32_t ScreenCaptureServer::UnRegisterMouseChangeListener(std::string type)
{
    MEDIA_LOGI("UnRegisterMouseChangeListener start.");
    if (mouseChangeListener_ == nullptr) {
        MEDIA_LOGI("RegisterMouseChangeListener mouseChangeListener already unregistered");
        return MSERR_OK;
    }
    int32_t ret = MMI::InputManager::GetInstance()->UnregisterDevListener(type, mouseChangeListener_);
    mouseChangeListener_ = nullptr;
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "UnRegisterMouseChangeListener failed");
    MEDIA_LOGI("UnRegisterMouseChangeListener end.");
    return ret;
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
    ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureStarted(appInfo_.appPid);
    if (screenCaptureCb_ != nullptr) {
        screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED);
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

void ScreenCaptureServer::PostStartScreenCapture(bool isSuccess)
{
    CHECK_AND_RETURN(screenCaptureCb_ != nullptr);
    MediaTrace trace("ScreenCaptureServer::PostStartScreenCapture.");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture start, isSuccess:%{public}s, "
        "dataType:%{public}d.", FAKE_POINTER(this), isSuccess ? "true" : "false", captureConfig_.dataType);
    if (isSuccess) {
        MEDIA_LOGI("PostStartScreenCapture handle success");
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
        if (isPrivacyAuthorityEnabled_ &&
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
                .compare(appName_) != 0) {
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
        PostStartScreenCaptureSuccessAction();
    } else {
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
        return;
    }
    RegisterPrivateWindowListener();
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " PostStartScreenCapture end.", FAKE_POINTER(this));
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
    }
    MEDIA_LOGI("InitAudioCap success sampleRate:%{public}d, channels:%{public}d, source:%{public}d, state:%{public}d",
        audioInfo.audioSampleRate, audioInfo.audioChannels, audioInfo.audioSource, audioInfo.state);
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
    }
    return MSERR_OK;
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
        MEDIA_LOGI("InitRecorder prepare to SetAudioDataSource");
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIX_MODE, this);
        captureCallback_ = std::make_shared<ScreenRendererAudioStateChangeCallback>();
        audioSource_->SetAppPid(appInfo_.appPid);
        audioSource_->SetAppName(appName_);
        captureCallback_->SetAppName(appName_);
        captureCallback_->SetAudioSource(audioSource_);
        audioSource_->RegisterAudioRendererEventListener(appInfo_.appPid, captureCallback_);
        ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.innerCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.innerCapInfo;
        MEDIA_LOGI("InitRecorder prepare to SetAudioSource inner");
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::INNER_MODE, this);
        ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_UNKNOWN, "SetAudioDataSource failed");
    } else if (captureConfig_.audioInfo.micCapInfo.state == AVScreenCaptureParamValidationState::VALIDATION_VALID) {
        audioInfo = captureConfig_.audioInfo.micCapInfo;
        MEDIA_LOGI("InitRecorder prepare to SetAudioSource mic");
        audioSource_ = std::make_unique<AudioDataSource>(AVScreenCaptureMixMode::MIC_MODE, this);
        ret = recorder_->SetAudioDataSource(audioSource_, audioSourceId_);
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

    appName_ = GetClientBundleName(appInfo_.appUid);

    isPrivacyAuthorityEnabled_ = isPrivacyAuthorityEnabled;
    captureState_ = AVScreenCaptureState::POPUP_WINDOW;
    ret = RequestUserPrivacyAuthority();
    if (ret != MSERR_OK) {
        captureState_ = AVScreenCaptureState::STOPPED;
        SetErrorInfo(ret, "StartScreenCaptureInner RequestUserPrivacyAuthority failed",
            StopReason::REQUEST_USER_PRIVACY_AUTHORITY_FAILED, IsUserPrivacyAuthorityNeeded());
        MEDIA_LOGE("StartScreenCaptureInner RequestUserPrivacyAuthority failed");
        return ret;
    }

    if (IsUserPrivacyAuthorityNeeded()) {
        if (isPrivacyAuthorityEnabled_ &&
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
                .compare(appName_) != 0) {
            MEDIA_LOGI("Wait for user interactions to ALLOW/DENY capture");
            return MSERR_OK;
        }
        MEDIA_LOGI("privacy notification window not support, app has CAPTURE_SCREEN permission and go on");
    } else {
        MEDIA_LOGI("Privacy Authority granted automatically and go on"); // for root
    }

    ret = OnStartScreenCapture();
    PostStartScreenCapture(ret == MSERR_OK);

    MEDIA_LOGI("StartScreenCaptureInner E, appUid:%{public}d, appPid:%{public}d", appInfo_.appUid, appInfo_.appPid);
    return ret;
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
    uint64_t tokenId = IPCSkeleton::GetCallingFullTokenID();
    isCalledBySystemApp_ = OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    MEDIA_LOGI("ScreenCaptureServer::RegisterServerCallbacks isCalledBySystemApp : %{public}d", isCalledBySystemApp_);
    std::weak_ptr<ScreenCaptureServer> wpScreenCaptureServer(shared_from_this());
    screenCaptureObserverCb_ = std::make_shared<ScreenCaptureObserverCallBack>(wpScreenCaptureServer);
    if (InCallObserver::GetInstance().IsInCall() && !IsTelInCallSkipList()) {
        MEDIA_LOGI("ScreenCaptureServer Start InCall Abort");
        if (screenCaptureCb_ != nullptr) {
            screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL);
        }
        FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNSUPPORT,
            "ScreenCaptureServer Start InCall Abort");
        return MSERR_UNSUPPORT;
    } else {
        MEDIA_LOGI("ScreenCaptureServer Start RegisterScreenCaptureCallBack");
        InCallObserver::GetInstance().RegisterInCallObserverCallBack(screenCaptureObserverCb_);
    }
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

int32_t ScreenCaptureServer::StartPrivacyWindow()
{
    auto bundleName = GetClientBundleName(appInfo_.appUid);
    callingLabel_ = GetBundleResourceLabel(bundleName);

    std::string comStr = "{\"ability.want.params.uiExtensionType\":\"sys/commonUI\",\"sessionId\":\"";
    comStr += std::to_string(sessionId_).c_str();
    comStr += "\",\"callerUid\":\"";
    comStr += std::to_string(appInfo_.appUid).c_str();
    comStr += "\",\"appLabel\":\"";
    comStr += callingLabel_.c_str();
    comStr += "\"}";

    AAFwk::Want want;
    ErrCode ret = ERR_INVALID_VALUE;
#ifdef PC_STANDARD
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_SCREEN || CheckCaptureSpecifiedWindowForSelectWindow()) {
        AppExecFwk::ElementName element("",
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"],
            SELECT_ABILITY_NAME); // DeviceID
        want.SetElement(element);
        want.SetParam("params", comStr);
        want.SetParam("appLabel", callingLabel_);
        want.SetParam("sessionId", sessionId_);
        SendConfigToUIParams(want);
        ret = AAFwk::AbilityManagerClient::GetInstance()->StartAbility(want);
        MEDIA_LOGI("StartAbility end %{public}d, DeviceType : PC", ret);
    } else {
        want.SetElementName(GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"],
            GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionabilityname"]);
        auto connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(comStr));
        ret = OHOS::AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_,
            nullptr, -1);
        MEDIA_LOGI("ConnectServiceExtensionAbility end %{public}d, DeviceType : PC", ret);
    }
#else
    want.SetElementName(GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionbundlename"],
                        GetScreenCaptureSystemParam()["const.multimedia.screencapture.dialogconnectionabilityname"]);
    auto connection_ = sptr<UIExtensionAbilityConnection>(new (std::nothrow) UIExtensionAbilityConnection(comStr));
    ret = OHOS::AAFwk::ExtensionManagerClient::GetInstance().ConnectServiceExtensionAbility(want, connection_,
        nullptr, -1);
    MEDIA_LOGI("ConnectServiceExtensionAbility end %{public}d, Device : Phone", ret);
#endif
    return ret;
}

int32_t ScreenCaptureServer::StartNotification()
{
    int32_t result = NotificationHelper::SubscribeLocalLiveViewNotification(NOTIFICATION_SUBSCRIBER);
    MEDIA_LOGD("Screencapture service PublishNotification, result %{public}d", result);
    NotificationRequest request;
    localLiveViewContent_ = GetLocalLiveViewContent();

    std::shared_ptr<NotificationContent> content =
        std::make_shared<NotificationContent>(localLiveViewContent_);

    request.SetSlotType(NotificationConstant::SlotType::LIVE_VIEW);
    notificationId_ = sessionId_;
    request.SetNotificationId(notificationId_);
    request.SetContent(content);
    request.SetCreatorUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetOwnerUid(AV_SCREEN_CAPTURE_SESSION_UID);
    request.SetUnremovable(true);
    request.SetInProgress(true);

    std::shared_ptr<PixelMap> pixelMapTotalSpr = GetPixelMap(ICON_PATH_NOTIFICATION);
    request.SetLittleIcon(pixelMapTotalSpr);
    request.SetBadgeIconStyle(NotificationRequest::BadgeStyle::LITTLE);

    result = NotificationHelper::PublishNotification(request);
    MEDIA_LOGI("Screencapture service UpdateMicrophoneEnabled uid %{public}d, result %{public}d",
        AV_SCREEN_CAPTURE_SESSION_UID, result);
    return result;
}

std::string ScreenCaptureServer::GetStringByResourceName(const char* name)
{
    std::string resourceContext;
    CHECK_AND_RETURN_RET_LOG(resourceManager_ != nullptr, resourceContext, "resourceManager is null");
    if (strcmp(name, NOTIFICATION_SCREEN_RECORDING_TITLE_ID) == 0) {
        resourceManager_->GetStringByName(NOTIFICATION_SCREEN_RECORDING_TITLE_ID, resourceContext);
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
    }
    if (resourceManager_) {
        resourceManager_->UpdateResConfig(*resConfig_);
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

std::shared_ptr<NotificationLocalLiveViewContent> ScreenCaptureServer::GetLocalLiveViewContent()
{
    std::shared_ptr<NotificationLocalLiveViewContent> localLiveViewContent =
        std::make_shared<NotificationLocalLiveViewContent>();
    localLiveViewContent->SetType(1);
    InitResourceManager();
    std::string recordingScreenTitleStr = GetStringByResourceName(NOTIFICATION_SCREEN_RECORDING_TITLE_ID);
    std::string from = "%s";
    std::string to = QUOTATION_MARKS_STRING + callingLabel_ + QUOTATION_MARKS_STRING;
    size_t startPos = recordingScreenTitleStr.find(from);
    if (startPos != std::string::npos) {
        recordingScreenTitleStr.replace(startPos, from.length(), to);
        liveViewText_ = recordingScreenTitleStr;
    }
    MEDIA_LOGD("GetLocalLiveViewContent liveViewText: %{public}s", liveViewText_.c_str());
    localLiveViewContent->SetText(liveViewText_);

    auto capsule = NotificationCapsule();
    capsule.SetBackgroundColor(BACK_GROUND_COLOR);
    capsulePxSize_ = static_cast<int32_t>(capsuleVpSize_ * density_);
    std::shared_ptr<PixelMap> pixelMapCapSpr = GetPixelMapSvg(ICON_PATH_CAPSULE_STOP, capsulePxSize_, capsulePxSize_);
    capsule.SetIcon(pixelMapCapSpr);

    localLiveViewContent->SetCapsule(capsule);
    localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);

    auto countTime = NotificationTime();
    countTime.SetInitialTime(1);
    countTime.SetIsCountDown(false);
    countTime.SetIsPaused(false);
    countTime.SetIsInTitle(true);

    localLiveViewContent->SetTime(countTime);
    localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);

    auto basicButton = NotificationLocalLiveViewButton();
    basicButton.addSingleButtonName(BUTTON_NAME_STOP);
    std::shared_ptr<PixelMap> pixelMapStopSpr = GetPixelMap(ICON_PATH_STOP);
    basicButton.addSingleButtonIcon(pixelMapStopSpr);

    localLiveViewContent->SetButton(basicButton);
    localLiveViewContent->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
    return localLiveViewContent;
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

    std::shared_ptr<PixelMap> pixelMapTotalSpr = GetPixelMap(ICON_PATH_CAPSULE_STOP);
    request.SetLittleIcon(pixelMapTotalSpr);
    request.SetBadgeIconStyle(NotificationRequest::BadgeStyle::LITTLE);

    int32_t result = NotificationHelper::PublishNotification(request);
    MEDIA_LOGI("Screencapture service UpdateMicrophoneEnabled uid %{public}d, result %{public}d",
        AV_SCREEN_CAPTURE_SESSION_UID, result);
    micCount_.store(micCount_.load() + 1);
}

void ScreenCaptureServer::UpdateLiveViewContent()
{
    localLiveViewContent_->SetType(1);
    localLiveViewContent_->SetText(liveViewText_);

    auto capsule = NotificationCapsule();
    capsule.SetBackgroundColor(BACK_GROUND_COLOR);
    std::shared_ptr<PixelMap> pixelMapCapSpr = GetPixelMap(ICON_PATH_CAPSULE_STOP);
    capsule.SetIcon(pixelMapCapSpr);

    localLiveViewContent_->SetCapsule(capsule);
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::CAPSULE);

    auto countTime = NotificationTime();
    countTime.SetIsCountDown(false);
    countTime.SetIsPaused(false);
    countTime.SetIsInTitle(true);

    localLiveViewContent_->SetTime(countTime);
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::TIME);

    auto basicButton = NotificationLocalLiveViewButton();
    basicButton.addSingleButtonName(BUTTON_NAME_MIC);
    if (micCount_.load() % MICROPHONE_STATE_COUNT == MICROPHONE_OFF) {
        std::shared_ptr<PixelMap> pixelMapSpr = GetPixelMapSvg(ICON_PATH_MIC_OFF, SVG_HEIGHT, SVG_WIDTH);
        basicButton.addSingleButtonIcon(pixelMapSpr);
    } else {
        std::shared_ptr<PixelMap> pixelMapSpr = GetPixelMapSvg(ICON_PATH_MIC, SVG_HEIGHT, SVG_WIDTH);
        basicButton.addSingleButtonIcon(pixelMapSpr);
    }

    basicButton.addSingleButtonName(BUTTON_NAME_STOP);
    std::shared_ptr<PixelMap> pixelMapStopSpr = GetPixelMap(ICON_PATH_STOP);
    basicButton.addSingleButtonIcon(pixelMapStopSpr);

    localLiveViewContent_->SetButton(basicButton);
    localLiveViewContent_->addFlag(NotificationLocalLiveViewContent::LiveViewContentInner::BUTTON);
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
    auto producerSurface = OHOS::Surface::CreateSurfaceAsProducer(producer);
    CHECK_AND_RETURN_RET_LOG(producerSurface != nullptr, MSERR_UNKNOWN, "CreateSurfaceAsProducer failed");
    surfaceCb_ = OHOS::sptr<ScreenCapBufferConsumerListener>::MakeSptr(consumer_, screenCaptureCb_);
    CHECK_AND_RETURN_RET_LOG(surfaceCb_ != nullptr, MSERR_UNKNOWN, "MakeSptr surfaceCb_ failed");
    consumer_->RegisterConsumerListener(surfaceCb_);
    MEDIA_LOGD("StartStreamHomeVideoCapture producerSurface: %{public}" PRIu64, producerSurface->GetUniqueId());
    int32_t ret = CreateVirtualScreen(virtualScreenName, producerSurface);
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

int32_t ScreenCaptureServer::CreateVirtualScreen(const std::string &name, sptr<OHOS::Surface> consumer)
{
    MediaTrace trace("ScreenCaptureServer::CreateVirtualScreen");
    MEDIA_LOGI("CreateVirtualScreen Start");
    isConsumerStart_ = false;
    VirtualScreenOption virScrOption = InitVirtualScreenOption(name, consumer);
    sptr<Rosen::Display> display = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    if (display != nullptr) {
        MEDIA_LOGI("get displayInfo width:%{public}d,height:%{public}d, density:%{public}f", display->GetWidth(),
                   display->GetHeight(), display->GetVirtualPixelRatio());
        virScrOption.density_ = display->GetVirtualPixelRatio();
    }
    if (missionIds_.size() > 0 && captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        virScrOption.missionIds_ = missionIds_;
    } else if (captureConfig_.videoInfo.videoCapInfo.taskIDs.size() > 0 &&
        captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        GetMissionIds(missionIds_);
        virScrOption.missionIds_ = missionIds_;
    }
    screenId_ = ScreenManager::GetInstance().CreateVirtualScreen(virScrOption);
    if (!showCursor_) {
        MEDIA_LOGI("CreateVirtualScreen without cursor");
        int32_t ret = ShowCursorInner();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("CreateVirtualScreen SetVirtualScreenBlackList failed");
        }
    }
    CHECK_AND_RETURN_RET_LOG(screenId_ >= 0, MSERR_UNKNOWN, "CreateVirtualScreen failed, invalid screenId");
    MEDIA_LOGI("CreateVirtualScreen success, screenId: %{public}" PRIu64, screenId_);
    return PrepareVirtualScreenMirror();
}

int32_t ScreenCaptureServer::PrepareVirtualScreenMirror()
{
    for (size_t i = 0; i < contentFilter_.windowIDsVec.size(); i++) {
        MEDIA_LOGI("After CreateVirtualScreen windowIDsVec value :%{public}" PRIu64, contentFilter_.windowIDsVec[i]);
    }
    if (GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) == 0) {
        SetScreenScaleMode();
    }
    Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(screenId_, contentFilter_.windowIDsVec,
        surfaceIdList_);
    MEDIA_LOGI("PrepareVirtualScreenMirror screenId: %{public}" PRIu64, screenId_);
    auto screen = ScreenManager::GetInstance().GetScreenById(screenId_);
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
    if (missionIds_.size() > 0) {
        std::unordered_map<uint64_t, uint64_t> windowDisplayIdMap;
        auto ret = WindowManager::GetInstance().GetDisplayIdByWindowId(missionIds_, windowDisplayIdMap);
        MEDIA_LOGI("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR
            "GetWindowDisplayIds ret:%{public}d", FAKE_POINTER(this), ret);
        for (const auto& pair : windowDisplayIdMap) {
            MEDIA_LOGI("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR " WindowId:%{public}" PRIu64
                " in DisplayId:%{public}" PRIu64, FAKE_POINTER(this), pair.first, pair.second);
            defaultDisplayIdValue = pair.second;
        }
        MEDIA_LOGI("MakeVirtualScreenMirror 0x%{public}06" PRIXPTR
            " For Specific Window %{public}" PRIu64, FAKE_POINTER(this), defaultDisplayIdValue);
    }
    return defaultDisplayIdValue;
}

int32_t ScreenCaptureServer::MakeVirtualScreenMirror()
{
    MediaTrace trace("ScreenCaptureServer::MakeVirtualScreenMirror");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " MakeVirtualScreenMirror start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(screenId_ >= 0 && screenId_ != SCREEN_ID_INVALID, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed, invalid screenId");
    std::vector<sptr<Screen>> screens;
    DMError ret = ScreenManager::GetInstance().GetAllScreens(screens);
    CHECK_AND_RETURN_RET_LOG(screens.size() > 0, MSERR_UNKNOWN,
        "MakeVirtualScreenMirror failed to GetAllScreens, ret:%{public}d", ret);
    std::vector<ScreenId> mirrorIds;
    mirrorIds.push_back(screenId_);
    sptr<Rosen::Display> defaultDisplay = Rosen::DisplayManager::GetInstance().GetDefaultDisplaySync();
    CHECK_AND_RETURN_RET_LOG(defaultDisplay != nullptr, MSERR_UNKNOWN, "make mirror GetDefaultDisplaySync failed");
    ScreenId mirrorGroup = defaultDisplay->GetScreenId();
    if (captureConfig_.captureMode == CAPTURE_SPECIFIED_WINDOW) {
        uint64_t defaultDisplayId = GetDisplayIdOfWindows(defaultDisplay->GetScreenId());
        ret = ScreenManager::GetInstance().MakeMirror(defaultDisplayId, mirrorIds, mirrorGroup);
        CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
            "MakeVirtualScreenMirror failed to MakeMirror, captureMode:%{public}d, ret:%{public}d",
            captureConfig_.captureMode, ret);
        MEDIA_LOGI("MakeVirtualScreenMirror window screen success, screenId:%{public}" PRIu64, defaultDisplayId);
        return MSERR_OK;
    }
    if (captureConfig_.captureMode != CAPTURE_SPECIFIED_SCREEN) {
        MEDIA_LOGI("MakeVirtualScreenMirror DefaultDisplay, screenId:%{public}" PRIu64, defaultDisplay->GetScreenId());
        ret = ScreenManager::GetInstance().MakeMirror(defaultDisplay->GetScreenId(), mirrorIds, mirrorGroup);
        CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
            "MakeVirtualScreenMirror failed to MakeMirror, captureMode:%{public}d, ret:%{public}d",
            captureConfig_.captureMode, ret);
        MEDIA_LOGI("MakeVirtualScreenMirror default screen success, screenId:%{public}" PRIu64, screens[0]->GetId());
        return MSERR_OK;
    }
    for (uint32_t i = 0; i < screens.size() ; i++) {
        if (screens[i]->GetId() == captureConfig_.videoInfo.videoCapInfo.displayId) {
            ret = ScreenManager::GetInstance().MakeMirror(screens[i]->GetId(), mirrorIds, mirrorGroup);
            CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNKNOWN,
                "MakeVirtualScreenMirror failed to MakeMirror for CAPTURE_SPECIFIED_SCREEN, ret:%{public}d", ret);
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

void ScreenCaptureServer::DestroyVirtualScreen()
{
    MediaTrace trace("ScreenCaptureServer::DestroyVirtualScreen");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " DestroyVirtualScreen start.", FAKE_POINTER(this));
    if (screenId_ >=0 && screenId_ != SCREEN_ID_INVALID) {
        if (isConsumerStart_) {
            std::vector<ScreenId> screenIds;
            screenIds.push_back(screenId_);
            ScreenManager::GetInstance().StopMirror(screenIds);
        }
        ScreenManager::GetInstance().DestroyVirtualScreen(screenId_);
        screenId_ = SCREEN_ID_INVALID;
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
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " InitVirtualScreenOption start, naem:%{public}s.",
        FAKE_POINTER(this), name.c_str());
    VirtualScreenOption virScrOption = {
        .name_ = name,
        .width_ = captureConfig_.videoInfo.videoCapInfo.videoFrameWidth,
        .height_ = captureConfig_.videoInfo.videoCapInfo.videoFrameHeight,
        .density_ = 0,
        .surface_ = consumer,
        .flags_ = 0,
        .isForShot_ = true,
        .missionIds_ = {},
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
        MEDIA_LOGI("ScreenCaptureServer::GetMissionIds taskId : %{public}s", std::to_string(taskId).c_str());
        uint64_t uintNum = static_cast<uint64_t>(taskId);
        missionIds.push_back(uintNum);
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::AcquireAudioBuffer(std::shared_ptr<AudioBuffer> &audioBuffer, AudioCaptureSourceType type)
{
    MediaTrace trace("ScreenCaptureServer::AcquireAudioBuffer");
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " AcquireAudioBuffer start, state:%{public}d, "
        "type:%{public}d.", FAKE_POINTER(this), captureState_, type);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "AcquireAudioBuffer failed, capture is not STARTED, state:%{public}d, type:%{public}d", captureState_, type);

    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        micAudioCapture_ != nullptr && micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        return micAudioCapture_->AcquireAudioBuffer(audioBuffer);
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        innerAudioCapture_ != nullptr && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        return innerAudioCapture_->AcquireAudioBuffer(audioBuffer);
    }
    MEDIA_LOGE("AcquireAudioBuffer failed, source type not support, type:%{public}d", type);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "AcquireAudioBuffer failed, source type not support");
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::AcquireAudioBufferMix(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer, AVScreenCaptureMixMode type)
{
    if (captureState_ != AVScreenCaptureState::STARTED) {
        return MSERR_INVALID_OPERATION;
    }
    if (type == AVScreenCaptureMixMode::MIX_MODE && micAudioCapture_ != nullptr &&
        micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (micAudioCapture_->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture AcquireAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::MIX_MODE && innerAudioCapture_ != nullptr &&
        innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (innerAudioCapture_->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGE("innerAudioCapture AcquireAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::MIC_MODE && micAudioCapture_ != nullptr &&
        micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (micAudioCapture_->AcquireAudioBuffer(micAudioBuffer) != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture AcquireAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::INNER_MODE && innerAudioCapture_ != nullptr &&
        innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (innerAudioCapture_->AcquireAudioBuffer(innerAudioBuffer) != MSERR_OK) {
            MEDIA_LOGE("innerAudioCapture AcquireAudioBuffer failed");
        }
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ReleaseAudioBuffer(AudioCaptureSourceType type)
{
    MediaTrace trace("ScreenCaptureServer::ReleaseAudioBuffer");
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " ReleaseAudioBuffer start, state:%{public}d, "
        "type:%{public}d.", FAKE_POINTER(this), captureState_, type);
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "ReleaseAudioBuffer failed, capture is not STARTED, state:%{public}d, type:%{public}d", captureState_, type);

    if (((type == AudioCaptureSourceType::MIC) || (type == AudioCaptureSourceType::SOURCE_DEFAULT)) &&
        micAudioCapture_ != nullptr && micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        return micAudioCapture_->ReleaseAudioBuffer();
    }
    if (((type == AudioCaptureSourceType::ALL_PLAYBACK) || (type == AudioCaptureSourceType::APP_PLAYBACK)) &&
        innerAudioCapture_ != nullptr && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        return innerAudioCapture_->ReleaseAudioBuffer();
    }
    MEDIA_LOGE("ReleaseAudioBuffer failed, source type not support, type:%{public}d", type);
    FaultScreenCaptureEventWrite(appName_, instanceId_, avType_, dataMode_, SCREEN_CAPTURE_ERR_UNKNOWN,
        "ReleaseAudioBuffer failed, source type not support");
    return MSERR_UNKNOWN;
}

int32_t ScreenCaptureServer::ReleaseAudioBufferMix(AVScreenCaptureMixMode type)
{
    CHECK_AND_RETURN_RET_LOG(captureState_ == AVScreenCaptureState::STARTED, MSERR_INVALID_OPERATION,
        "ReleaseAudioBuffer failed, capture is not STARTED, state:%{public}d, type:%{public}d", captureState_, type);
    if (type == AVScreenCaptureMixMode::MIX_MODE && micAudioCapture_ != nullptr &&
        micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (micAudioCapture_->ReleaseAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture ReleaseAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::MIX_MODE && innerAudioCapture_ != nullptr &&
        innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (innerAudioCapture_->ReleaseAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("innerAudioCapture ReleaseAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::MIC_MODE && micAudioCapture_ != nullptr &&
        micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (micAudioCapture_->ReleaseAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture ReleaseAudioBuffer failed");
        }
    }
    if (type == AVScreenCaptureMixMode::INNER_MODE && innerAudioCapture_ != nullptr &&
        innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        if (innerAudioCapture_->ReleaseAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("innerAudioCapture ReleaseAudioBuffer failed");
        }
    }
    return MSERR_OK;
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
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer");
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
    MediaTrace trace("ScreenCaptureServer::ReleaseVideoBuffer");
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
        Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(screenId_, contentFilter_.windowIDsVec,
            surfaceIdList_);
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

int32_t ScreenCaptureServer::SetMicrophoneEnabled(bool isMicrophone)
{
    MediaTrace trace("ScreenCaptureServer::SetMicrophoneEnabled");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetMicrophoneEnabled isMicrophoneSwitchTurnOn_:"
        "%{public}d, new isMicrophone:%{public}d", FAKE_POINTER(this), isMicrophoneSwitchTurnOn_, isMicrophone);
    int32_t ret = MSERR_UNKNOWN;
    isMicrophoneSwitchTurnOn_ = isMicrophone;
    if (isMicrophone) {
        statisticalEventInfo_.enableMic = true;
    }
    if (captureState_ != AVScreenCaptureState::STARTED) {
        return MSERR_OK;
    }
    if (isMicrophone) {
        ret = SetMicrophoneOn();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOn failed");
        if (screenCaptureCb_ != nullptr) {
            screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNMUTED_BY_USER);
        }
    } else {
        ret = SetMicrophoneOff();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOff failed");
        if (screenCaptureCb_ != nullptr) {
            screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_MUTED_BY_USER);
        }
    }
    // For CAPTURE FILE, should call Recorder interface to make effect
    MEDIA_LOGI("SetMicrophoneEnabled OK.");
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMicrophoneOn()
{
    int32_t ret = MSERR_UNKNOWN;
    if (!micAudioCapture_) {
        if (captureConfig_.dataType == DataType::ORIGINAL_STREAM) {
            ret = StartStreamMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "SetMicrophoneOn StartStreamMicAudioCapture failed");
        } else if (captureConfig_.dataType == DataType::CAPTURE_FILE) {
            ret = StartFileMicAudioCapture();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "StartFileMicAudioCapture failed");
        }
    } else if (micAudioCapture_->GetAudioCapturerState() == CAPTURER_PAUSED) {
        ret = micAudioCapture_->Resume();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("micAudioCapture Resume failed");
            if (screenCaptureCb_ != nullptr) {
                screenCaptureCb_->OnStateChange(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE);
            }
            return ret;
        }
    } else if (micAudioCapture_->GetAudioCapturerState() != CAPTURER_RECORDING) {
        MEDIA_LOGE("AudioCapturerState invalid");
    }
    usleep(AUDIO_CHANGE_TIME);
    if (innerAudioCapture_ && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING &&
        audioSource_ && audioSource_->GetSpeakerAliveStatus() && !audioSource_->GetIsInVoIPCall()) {
        ret = innerAudioCapture_->Pause();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Pause failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetMicrophoneOff()
{
    int32_t ret = MSERR_UNKNOWN;
    if (innerAudioCapture_ && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_PAUSED) {
        ret = innerAudioCapture_->Resume();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Resume failed");
    }
    usleep(AUDIO_CHANGE_TIME);
    if (micAudioCapture_ && micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        ret = micAudioCapture_->Pause();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "micAudioCapture Pause failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::OnSpeakerAliveStatusChanged(bool speakerAliveStatus)
{
    int32_t ret = MSERR_UNKNOWN;
    CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture_ is nullptr");
    if (!speakerAliveStatus && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_PAUSED) {
        ret = innerAudioCapture_->Resume();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Resume failed");
    } else if (speakerAliveStatus && micAudioCapture_ &&
        micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING && audioSource_ &&
        !audioSource_->GetIsInVoIPCall() && innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING) {
        ret = innerAudioCapture_->Pause();
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Pause failed");
    }
    return MSERR_OK;
}

int32_t ScreenCaptureServer::ReStartMicForVoIPStatusSwitch()
{
    int32_t ret = MSERR_OK;
    StopMicAudioCapture();
    if (isMicrophoneSwitchTurnOn_) {
        ret = StartFileMicAudioCapture();
        if (ret != MSERR_OK) {
            MEDIA_LOGE("OnVoIPStatusChanged StartFileMicAudioCapture failed, ret: %{public}d", ret);
        }
    }
    return ret;
}

int32_t ScreenCaptureServer::OnVoIPStatusChanged(bool isInVoIPCall)
{
    MEDIA_LOGI("OnVoIPStatusChanged, isInVoIPCall:%{public}d", isInVoIPCall);
    int32_t ret = MSERR_UNKNOWN;
    if (isInVoIPCall) {
        CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture is nullptr");
        if (innerAudioCapture_->GetAudioCapturerState() == CAPTURER_PAUSED) {
            ret = innerAudioCapture_->Resume();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Resume failed");
        }
        usleep(AUDIO_CHANGE_TIME);
        ReStartMicForVoIPStatusSwitch();
    } else {
        ReStartMicForVoIPStatusSwitch();
        usleep(AUDIO_CHANGE_TIME);
        CHECK_AND_RETURN_RET_LOG(innerAudioCapture_, MSERR_UNKNOWN, "innerAudioCapture is nullptr");
        if (innerAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING &&
            micAudioCapture_ && micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING &&
            audioSource_ && audioSource_->GetSpeakerAliveStatus()) {
            ret = innerAudioCapture_->Pause();
            CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "innerAudioCapture Pause failed");
        }
    }
    return MSERR_OK;
}

bool ScreenCaptureServer::GetMicWorkingState()
{
    MEDIA_LOGD("ScreenCaptureServer: 0x%{public}06" PRIXPTR " GetMicWorkingState", FAKE_POINTER(this));
    if (micAudioCapture_ != nullptr) {
        return micAudioCapture_->GetAudioCapturerState() == CAPTURER_RECORDING;
    }
    return false;
}

int32_t ScreenCaptureServer::SetCanvasRotation(bool canvasRotation)
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotation");
    std::lock_guard<std::mutex> lock(mutex_);
    canvasRotation_ = canvasRotation;
    MEDIA_LOGI("ScreenCaptureServer::SetCanvasRotation, canvasRotation:%{public}d", canvasRotation);
    if (captureState_ != AVScreenCaptureState::STARTED) { // Before Start
        return MSERR_OK;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotation end.", FAKE_POINTER(this));
    return SetCanvasRotationInner();
}

int32_t ScreenCaptureServer::SetCanvasRotationInner()
{
    MediaTrace trace("ScreenCaptureServer::SetCanvasRotationInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetCanvasRotationInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(screenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SetCanvasRotation failed virtual screen not init");
    auto ret = ScreenManager::GetInstance().SetVirtualMirrorScreenCanvasRotation(screenId_, canvasRotation_);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNSUPPORT,
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
    if (!showCursor_) {
        bool isRegsterMMI = RegisterMMISystemAbilityListener();
        if (!isRegsterMMI) {
            MEDIA_LOGE("Resiter MMI failed");
        }
        RegisterMouseChangeListener("change");
    } else {
        UnRegisterMMISystemAbilityListener();
        UnRegisterMouseChangeListener("change");
    }
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
    CHECK_AND_RETURN_RET_LOG(screenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
        "ShowCursorInner failed, virtual screen not init");
    if (!showCursor_) {
        MEDIA_LOGI("ScreenCaptureServer::ShowCursorInner, not show cursor");
        uint64_t surfaceId = {};
        int32_t ret = MMI::InputManager::GetInstance()->GetCursorSurfaceId(surfaceId);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret, "GetCursorSurfaceId failed");
        std::string surfaceIdStr = std::to_string(surfaceId);
        MEDIA_LOGI("GetCursorSurfaceId success, surfaceId: %{public}s", surfaceIdStr.c_str());
        surfaceIdList_ = {};
        surfaceIdList_.push_back(surfaceId);
    } else {
        MEDIA_LOGI("ScreenCaptureServer::ShowCursorInner, show cursor");
        return MSERR_OK;
    }
    Rosen::DisplayManager::GetInstance().SetVirtualScreenBlackList(screenId_, contentFilter_.windowIDsVec,
        surfaceIdList_);
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

    auto resizeRet = ScreenManager::GetInstance().ResizeVirtualScreen(screenId_, width, height);
    MEDIA_LOGI("ScreenCaptureServer::ResizeCanvas, ResizeVirtualScreen end, ret: %{public}d ", resizeRet);
    CHECK_AND_RETURN_RET_LOG(resizeRet == DMError::DM_OK, MSERR_UNSUPPORT, "ResizeVirtualScreen failed");

    return MSERR_OK;
}

int32_t ScreenCaptureServer::SkipPrivacyMode(std::vector<uint64_t> &windowIDsVec)
{
    MediaTrace trace("ScreenCaptureServer::SkipPrivacyMode");
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("ScreenCaptureServer::SkipPrivacyMode, windowIDsVec size:%{public}d",
        static_cast<int32_t>(windowIDsVec.size()));
    for (size_t i = 0; i < windowIDsVec.size(); i++) {
        MEDIA_LOGI("SkipPrivacyMode windowIDsVec value :%{public}" PRIu64, windowIDsVec[i]);
    }
    skipPrivacyWindowIDsVec_.assign(windowIDsVec.begin(), windowIDsVec.end());
    if (captureState_ != AVScreenCaptureState::STARTED) { // Before Start
        return MSERR_OK;
    }
    return SkipPrivacyModeInner();
}

int32_t ScreenCaptureServer::SkipPrivacyModeInner()
{
    MediaTrace trace("ScreenCaptureServer::SkipPrivacyModeInner");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SkipPrivacyModeInner start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(screenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SkipPrivacyMode failed virtual screen not init");
    auto ret = Rosen::DisplayManager::GetInstance().SetVirtualScreenSecurityExemption(screenId_,
        appInfo_.appPid, skipPrivacyWindowIDsVec_);
    CHECK_AND_RETURN_RET_LOG(ret == DMError::DM_OK, MSERR_UNSUPPORT,
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
    auto res = ScreenManager::GetInstance().SetVirtualScreenMaxRefreshRate(screenId_,
        static_cast<uint32_t>(frameRate), actualRefreshRate);

    CHECK_AND_RETURN_RET_LOG(res == DMError::DM_OK, MSERR_UNSUPPORT, "SetMaxVideoFrameRate failed");

    MEDIA_LOGI("ScreenCaptureServer::SetMaxVideoFrameRate end, frameRate:%{public}d, actualRefreshRate:%{public}u",
        frameRate, actualRefreshRate);
    return MSERR_OK;
}

int32_t ScreenCaptureServer::SetScreenScaleMode()
{
    MediaTrace trace("ScreenCaptureServer::SetScreenScaleMode");
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " SetScreenScaleMode start.", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(screenId_ != SCREEN_ID_INVALID, MSERR_INVALID_VAL,
                             "SetScreenScaleMode failed virtual screen not init");
    auto ret = ScreenManager::GetInstance().SetVirtualMirrorScreenScaleMode(
        screenId_, OHOS::Rosen::ScreenScaleMode::FILL_MODE);
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
    if (micAudioCapture_ != nullptr) {
        MediaTrace trace("ScreenCaptureServer::StopAudioCaptureMic");
        micAudioCapture_->Stop();
        micAudioCapture_ = nullptr;
    }

    if (innerAudioCapture_ != nullptr) {
        MediaTrace trace("ScreenCaptureServer::StopAudioCaptureInner");
        innerAudioCapture_->Stop();
        innerAudioCapture_ = nullptr;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopAudioCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopMicAudioCapture()
{
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopMicAudioCapture start.", FAKE_POINTER(this));
    if (micAudioCapture_ != nullptr) {
        MediaTrace trace("ScreenCaptureServer::StopAudioCaptureMic");
        micAudioCapture_->Stop();
        micAudioCapture_ = nullptr;
    }
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopMicAudioCapture end.", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t ScreenCaptureServer::StopVideoCapture()
{
    MediaTrace trace("ScreenCaptureServer::StopVideoCapture");
    MEDIA_LOGI("StopVideoCapture");
    if ((screenId_ < 0) || ((consumer_ == nullptr) && !isSurfaceMode_) || !isConsumerStart_) {
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
        ret = recorder_->Stop(false);
        if (ret != MSERR_OK) {
            MEDIA_LOGE("StopScreenCaptureRecorder recorder stop failed, ret:%{public}d", ret);
        }
        DestroyVirtualScreen();
        recorder_->Release();
        recorder_ = nullptr;
        StopAudioCapture();
    }
    UnRegisterMouseChangeListener("change");
    UnRegisterMMISystemAbilityListener();
    showCursor_ = true;
    surfaceIdList_ = {};
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
    std::lock_guard<std::mutex> lock(mutex_);
    return StopScreenCaptureInner(stateCode);
}

int32_t ScreenCaptureServer::StopScreenCaptureInner(AVScreenCaptureStateCode stateCode)
{
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
    displayListener_ = nullptr;
    if (captureState_ == AVScreenCaptureState::CREATED || captureState_ == AVScreenCaptureState::POPUP_WINDOW ||
        captureState_ == AVScreenCaptureState::STARTING) {
        captureState_ = AVScreenCaptureState::STOPPED;
        ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureFinished(appInfo_.appPid);
        if (screenCaptureCb_ != nullptr && stateCode != AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID) {
            screenCaptureCb_->OnStateChange(stateCode);
        }
        isSurfaceMode_ = false;
        surface_ = nullptr;
        SetErrorInfo(MSERR_OK, "normal stopped", StopReason::NORMAL_STOPPED, IsUserPrivacyAuthorityNeeded());
        return MSERR_OK;
    }
    CHECK_AND_RETURN_RET(captureState_ != AVScreenCaptureState::STOPPED, MSERR_OK);

    int32_t ret = MSERR_OK;
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
    captureState_ = AVScreenCaptureState::STOPPED;
    SetErrorInfo(MSERR_OK, "normal stopped", StopReason::NORMAL_STOPPED, IsUserPrivacyAuthorityNeeded());
    PostStopScreenCapture(stateCode);
    InCallObserver::GetInstance().UnregisterInCallObserverCallBack(screenCaptureObserverCb_);
    AccountObserver::GetInstance().UnregisterAccountObserverCallBack(screenCaptureObserverCb_);
    MEDIA_LOGI("ScreenCaptureServer: 0x%{public}06" PRIXPTR " StopScreenCaptureInner end.", FAKE_POINTER(this));
    return ret;
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
    ScreenCaptureMonitorServer::GetInstance()->CallOnScreenCaptureFinished(appInfo_.appPid);
    if (screenCaptureCb_ != nullptr && stateCode != AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID) {
        screenCaptureCb_->OnStateChange(stateCode);
    }
#ifdef SUPPORT_SCREEN_CAPTURE_WINDOW_NOTIFICATION
    if (isPrivacyAuthorityEnabled_ &&
        GetScreenCaptureSystemParam()["const.multimedia.screencapture.screenrecorderbundlename"]
            .compare(appName_) != 0) {
        // Remove real time notification
        int32_t ret = NotificationHelper::CancelNotification(notificationId_);
        MEDIA_LOGI("StopScreenCaptureInner CancelNotification id:%{public}d, ret:%{public}d ", notificationId_, ret);
        micCount_.store(0);
    }
#endif
    isPrivacyAuthorityEnabled_ = false;

    if (!LastPidUpdatePrivacyUsingPermissionState(appInfo_.appPid)) {
        MEDIA_LOGE("UpdatePrivacyUsingPermissionState STOP failed, dataType:%{public}d", captureConfig_.dataType);
    }
    std::unordered_map<std::string, std::string> payload;
    int64_t value = ResourceSchedule::ResType::ScreenCaptureStatus::STOP_SCREEN_CAPTURE;
    ResSchedReportData(value, payload);
    RemoveStartedSessionIdList(this->sessionId_);
    MEDIA_LOGI("PostStopScreenCapture sessionId: %{public}d is removed from list, list_size is %{public}d.",
        this->sessionId_, static_cast<uint32_t>(ScreenCaptureServer::startedSessionIDList_.size()));
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
        StopScreenCaptureInner(AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INVLID);
        MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner Stop done, sessionId:%{public}d",
            FAKE_POINTER(this), sessionId_);
    }
    MEDIA_LOGI("ScreenCaptureServer::ReleaseInner before RemoveScreenCaptureServerMap");
    RemoveScreenCaptureServerMap(sessionId_);
    sessionId_ = SESSION_ID_INVALID;
    MEDIA_LOGD("ReleaseInner removeMap success, mapSize: %{public}d",
        static_cast<int32_t>(ScreenCaptureServer::serverMap_.size()));
    skipPrivacyWindowIDsVec_.clear();
    SetMetaDataReport();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances ReleaseInner E", FAKE_POINTER(this));
}

ScreenCaptureObserverCallBack::ScreenCaptureObserverCallBack(
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer): taskQueObserverCb_("NotifyStopSc")
{
    screenCaptureServer_ = screenCaptureServer;
    taskQueObserverCb_.Start();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

bool ScreenCaptureObserverCallBack::StopAndRelease(AVScreenCaptureStateCode state)
{
    MEDIA_LOGI("ScreenCaptureObserverCallBack::StopAndRelease");
    auto scrServer = screenCaptureServer_.lock();
    if (scrServer && !scrServer->IsTelInCallSkipList()) {
        scrServer->StopScreenCaptureByEvent(state);
        scrServer->Release();
    }
    return true;
}

bool ScreenCaptureObserverCallBack::NotifyStopAndRelease(AVScreenCaptureStateCode state)
{
    MEDIA_LOGI("ScreenCaptureObserverCallBack::NotifyStopAndRelease START.");
    bool ret = true;
    auto task = std::make_shared<TaskHandler<void>>([&, this, state] {
        ret = StopAndRelease(state);
        return ret;
    });
    int32_t res = taskQueObserverCb_.EnqueueTask(task);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, false, "NotifyStopAndRelease EnqueueTask failed.");
    return true;
}

ScreenCaptureObserverCallBack::~ScreenCaptureObserverCallBack()
{
    taskQueObserverCb_.Stop();
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void ScreenCapBufferConsumerListener::OnBufferAvailable()
{
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailable");
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
    MediaTrace trace("ScreenCapConsumer::OnBufferAvailableAction");
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
    MediaTrace trace("ScreenCaptureServer::AcquireVideoBuffer");
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
    MediaTrace trace("ScreenCaptureServer::ReleaseVideoBuffer");
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
    audioSource_->SpeakerStateUpdate(audioRendererChangeInfos);
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
        MEDIA_LOGI("ChangeInfo Id: %{public}d, Client pid : %{public}d, State : %{public}d, DeviceType : %{public}d",
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
        MEDIA_LOGI("Client pid : %{public}d, State : %{public}d, DeviceType : %{public}d",
            changeInfo->clientPid, static_cast<int32_t>(changeInfo->rendererState),
            static_cast<int32_t>(changeInfo->outputDeviceInfo.deviceType_));
        if (changeInfo->rendererState == RendererState::RENDERER_RUNNING &&
            changeInfo->rendererInfo.streamUsage == AudioStandard::StreamUsage::STREAM_USAGE_VOICE_COMMUNICATION) {
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

int32_t AudioDataSource::ReadAt(std::shared_ptr<AVBuffer> buffer, uint32_t length)
{
    MEDIA_LOGD("AudioDataSource ReadAt start");
    std::shared_ptr<AudioBuffer> innerAudioBuffer = nullptr;
    std::shared_ptr<AudioBuffer> micAudioBuffer = nullptr;
    int32_t ret = MSERR_OK;
    if (screenCaptureServer_ == nullptr) {
        return MSERR_UNKNOWN;
    }
    ret = screenCaptureServer_->AcquireAudioBufferMix(innerAudioBuffer, micAudioBuffer, type_);
    if (ret != MSERR_OK) {
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGD("AcquireAudioBufferMix sucess");
    std::shared_ptr<AVMemory> &bufferMem = buffer->memory_;
    if (buffer->memory_ == nullptr) {
        MEDIA_LOGE("buffer->memory_ is nullptr");
        return MSERR_INVALID_VAL;
    }
    if (type_ == AVScreenCaptureMixMode::MIX_MODE) {
        return MixModeBufferWrite(innerAudioBuffer, micAudioBuffer, bufferMem);
    } else if (type_ == AVScreenCaptureMixMode::INNER_MODE && innerAudioBuffer != nullptr) {
        bufferMem->Write(reinterpret_cast<uint8_t*>(innerAudioBuffer->buffer), innerAudioBuffer->length, 0);
        return screenCaptureServer_->ReleaseAudioBufferMix(type_);
    } else if (type_ == AVScreenCaptureMixMode::MIC_MODE && micAudioBuffer != nullptr) {
        bufferMem->Write(reinterpret_cast<uint8_t*>(micAudioBuffer->buffer), micAudioBuffer->length, 0);
        return screenCaptureServer_->ReleaseAudioBufferMix(type_);
    }
    return MSERR_UNKNOWN;
}

int32_t AudioDataSource::MixModeBufferWrite(std::shared_ptr<AudioBuffer> &innerAudioBuffer,
    std::shared_ptr<AudioBuffer> &micAudioBuffer, std::shared_ptr<AVMemory> &bufferMem)
{
    if (innerAudioBuffer && innerAudioBuffer->buffer && micAudioBuffer && micAudioBuffer->buffer) {
        char* mixData = new char[innerAudioBuffer->length];
        char* srcData[2] = {nullptr};
        srcData[0] = reinterpret_cast<char*>(innerAudioBuffer->buffer);
        srcData[1] = reinterpret_cast<char*>(micAudioBuffer->buffer);
        int channels = 2;
        MixAudio(srcData, mixData, channels, innerAudioBuffer->length);
        bufferMem->Write(reinterpret_cast<uint8_t*>(mixData), innerAudioBuffer->length, 0);
        delete[] mixData;
    } else if (innerAudioBuffer && innerAudioBuffer->buffer) {
        bufferMem->Write(reinterpret_cast<uint8_t*>(innerAudioBuffer->buffer), innerAudioBuffer->length, 0);
    } else if (micAudioBuffer && micAudioBuffer->buffer) {
        bufferMem->Write(reinterpret_cast<uint8_t*>(micAudioBuffer->buffer), micAudioBuffer->length, 0);
    } else {
        MEDIA_LOGE("without buffer write");
        return MSERR_UNKNOWN;
    }
    if (innerAudioBuffer) {
        if (screenCaptureServer_->ReleaseInnerAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("ReleaseInnerAudioBuffer failed");
        }
    }
    if (micAudioBuffer) {
        if (screenCaptureServer_->ReleaseMicAudioBuffer() != MSERR_OK) {
            MEDIA_LOGE("ReleaseMicAudioBuffer failed");
        }
    }
    return MSERR_OK;
}

int32_t AudioDataSource::GetSize(int64_t &size)
{
    size_t bufferLen = 0;
    int32_t ret = screenCaptureServer_->GetInnerAudioCaptureBufferSize(bufferLen);
    MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
    if (ret == MSERR_OK) {
        size = static_cast<int64_t>(bufferLen);
        return ret;
    }
    ret = screenCaptureServer_->GetMicAudioCaptureBufferSize(bufferLen);
    MEDIA_LOGD("AudioDataSource::GetSize : %{public}zu", bufferLen);
    if (ret == MSERR_OK) {
        size = static_cast<int64_t>(bufferLen);
        return ret;
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
} // namespace Media
} // namespace OHOS
