/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_client.h"
#include "avmetadatahelper_client.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"
#include "i_standard_monitor_service.h"
#include "monitor_client.h"
#include <thread>
#ifdef SUPPORT_RECORDER
#include "i_standard_recorder_service.h"
#endif
#ifdef SUPPORT_TRANSCODER
#include "i_standard_transcoder_service.h"
#endif
#ifdef SUPPORT_PLAYER
#include "i_standard_player_service.h"
#endif
#ifdef SUPPORT_METADATA
#include "i_standard_avmetadatahelper_service.h"
#endif
#ifdef SUPPORT_SCREEN_CAPTURE
#include "i_standard_screen_capture_service.h"
#include "i_standard_screen_capture_monitor_service.h"
#endif
#ifdef SUPPORT_LPP_AUDIO_STRAMER
#include "i_standard_lpp_audio_streamer_service.h"
#endif
#ifdef SUPPORT_LPP_VIDEO_STRAMER
#include "i_standard_lpp_video_streamer_service.h"
#endif
#include "media_log.h"
#include "media_errors.h"
#include "player_xcollie.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaClient"};
}

namespace OHOS {
namespace Media {
constexpr int32_t LOAD_TIME = 30;
#ifdef SUPPORT_START_STOP_ON_DEMAND
constexpr int32_t SLEEP_TIME = 100;
constexpr int32_t RETRY_TIME = 3;
#endif
constexpr size_t MAX_PID_LIST_SIZE = 1000;
constexpr uint32_t MAX_WAIT_TIME = 5000;
std::shared_ptr<MediaClient> g_mediaClientInstance;
std::once_flag onceFlag_;

IMediaService &MediaServiceFactory::GetInstance()
{
    std::call_once(onceFlag_, [] {
        g_mediaClientInstance = std::make_shared<MediaClient>();
    });
    return *g_mediaClientInstance;
}

MediaClient::MediaClient() noexcept
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaClient::~MediaClient()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t MediaClient::ProxyForFreeze(const std::set<int32_t> &pidList, bool isProxy)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsAlived(), MSERR_SERVICE_DIED, "media service does not exist.");
    auto size = pidList.size();
    CHECK_AND_RETURN_RET_LOG(size <= MAX_PID_LIST_SIZE, MSERR_INVALID_VAL, "invalid pidList size");
    MEDIA_LOGD("received Freeze Notification, pidSize = %{public}d, isProxy = %{public}d",
               static_cast<int32_t>(size), isProxy);
    return mediaProxy_->FreezeStubForPids(pidList, isProxy);
}

int32_t MediaClient::ResetAllProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsAlived(), MSERR_SERVICE_DIED, "media service does not exist.");
    MEDIA_LOGI("received ResetAllProxy");
    return mediaProxy_->ResetAllProxy();
}

bool MediaClient::IsAlived()
{
    if (mediaProxy_ == nullptr) {
        mediaProxy_ = GetMediaProxy();
    }

    return (mediaProxy_ != nullptr) ? true : false;
}

void MediaClient::ReleaseClientListener()
{
    // there exist non-const methods of the sptr mediaProxy_, possible data-race.
    if (mediaProxy_ == nullptr) {
        return;
    }
    mediaProxy_->ReleaseClientListener();
    DoMediaServerDied(); // remove death recipient as well. Otherwise getting proxy after re-dlopen causes mem leak.
}

void MediaClient::CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility subSystemId,
    sptr<IRemoteObject> &object, std::unique_lock<std::mutex> &lock)
{
    (void)(lock);
#ifdef SUPPORT_START_STOP_ON_DEMAND
    int32_t tryTimes = RETRY_TIME;
    while (tryTimes-- > 0) {
        if (!IsAlived()) {
            MEDIA_LOGI("media service does not exist, sleep and retry");
            mediaProxyUpdatedCondition_.wait_for(lock, std::chrono::milliseconds(SLEEP_TIME));
            continue;
        }
        object = mediaProxy_->GetSubSystemAbilityWithTimeOut(subSystemId, listenerStub_->AsObject(), MAX_WAIT_TIME);
        if (object != nullptr) {
            return;
        }
        MEDIA_LOGI("GetSubSystemAbilityWithTimeOut failed, sleep and retry");
        mediaProxyUpdatedCondition_.wait_for(lock, std::chrono::milliseconds(SLEEP_TIME));
        continue;
    }
#else
    CHECK_AND_RETURN_LOG(IsAlived(), "media service does not exist.");
    object = mediaProxy_->GetSubSystemAbility(subSystemId, listenerStub_->AsObject());
#endif
}

#ifdef SUPPORT_RECORDER
std::shared_ptr<IRecorderService> MediaClient::CreateRecorderService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_RECORDER, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "recorder proxy object is nullptr.");

    sptr<IStandardRecorderService> recorderProxy = iface_cast<IStandardRecorderService>(object);
    CHECK_AND_RETURN_RET_LOG(recorderProxy != nullptr, nullptr, "recorder proxy is nullptr.");

    std::shared_ptr<RecorderClient> recorder = RecorderClient::Create(recorderProxy);
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, nullptr, "failed to create recorder client.");

    recorderClientList_.push_back(recorder);
    return recorder;
}

int32_t MediaClient::DestroyMediaProfileService(std::shared_ptr<IRecorderProfilesService> recorderProfiles)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(recorderProfiles != nullptr, MSERR_NO_MEMORY, "input recorderProfiles is nullptr.");
    recorderProfilesClientList_.remove(recorderProfiles);
    return MSERR_OK;
}

int32_t MediaClient::DestroyRecorderService(std::shared_ptr<IRecorderService> recorder)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(recorder != nullptr, MSERR_NO_MEMORY, "input recorder is nullptr.");
    recorderClientList_.remove(recorder);
    return MSERR_OK;
}

std::shared_ptr<IRecorderProfilesService> MediaClient::CreateRecorderProfilesService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::RECORDER_PROFILES, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "recorderProfiles proxy object is nullptr.");

    sptr<IStandardRecorderProfilesService> recorderProfilesProxy = iface_cast<IStandardRecorderProfilesService>(object);
    CHECK_AND_RETURN_RET_LOG(recorderProfilesProxy != nullptr, nullptr, "recorderProfiles proxy is nullptr.");

    std::shared_ptr<RecorderProfilesClient> recorderProfiles = RecorderProfilesClient::Create(recorderProfilesProxy);
    CHECK_AND_RETURN_RET_LOG(recorderProfiles != nullptr, nullptr, "failed to create recorderProfiles client.");

    recorderProfilesClientList_.push_back(recorderProfiles);
    return recorderProfiles;
}
#endif

#ifdef SUPPORT_TRANSCODER
std::shared_ptr<ITransCoderService> MediaClient::CreateTransCoderService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_TRANSCODER, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "transCoder proxy object is nullptr.");
 
    sptr<IStandardTransCoderService> transCoderProxy = iface_cast<IStandardTransCoderService>(object);
    CHECK_AND_RETURN_RET_LOG(transCoderProxy != nullptr, nullptr, "transCoder proxy is nullptr.");
 
    std::shared_ptr<TransCoderClient> transCoder = TransCoderClient::Create(transCoderProxy);
    CHECK_AND_RETURN_RET_LOG(transCoder != nullptr, nullptr, "failed to create transCoder client.");
 
    transCoderClientList_.push_back(transCoder);
    return transCoder;
}
 
int32_t MediaClient::DestroyTransCoderService(std::shared_ptr<ITransCoderService> transCoder)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(transCoder != nullptr, MSERR_NO_MEMORY, "input transCoder is nullptr.");
    transCoderClientList_.remove(transCoder);
    return MSERR_OK;
}
#endif

#ifdef SUPPORT_PLAYER
std::shared_ptr<IPlayerService> MediaClient::CreatePlayerService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
#ifdef SUPPORT_START_STOP_ON_DEMAND
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER, object, lock);
#else
    CHECK_AND_RETURN_RET_LOG(IsAlived(), nullptr, "media service does not exist.");
    object = mediaProxy_->GetSubSystemAbilityWithTimeOut(
        IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER, listenerStub_->AsObject(), MAX_WAIT_TIME);
#endif
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "player proxy object is nullptr.");

    sptr<IStandardPlayerService> playerProxy = iface_cast<IStandardPlayerService>(object);
    CHECK_AND_RETURN_RET_LOG(playerProxy != nullptr, nullptr, "player proxy is nullptr.");

    std::shared_ptr<PlayerClient> player = PlayerClient::Create(playerProxy);
    CHECK_AND_RETURN_RET_LOG(player != nullptr, nullptr, "failed to create player client.");

    playerClientList_.push_back(player);
    return player;
}

int32_t MediaClient::DestroyPlayerService(std::shared_ptr<IPlayerService> player)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(player != nullptr, MSERR_NO_MEMORY, "input player is nullptr.");
    playerClientList_.remove(player);
    return MSERR_OK;
}
#endif

#ifdef SUPPORT_METADATA
std::shared_ptr<IAVMetadataHelperService> MediaClient::CreateAVMetadataHelperService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_AVMETADATAHELPER, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "avmetadatahelper proxy object is nullptr.");

    sptr<IStandardAVMetadataHelperService> avMetadataHelperProxy = iface_cast<IStandardAVMetadataHelperService>(object);
    CHECK_AND_RETURN_RET_LOG(avMetadataHelperProxy != nullptr, nullptr, "avmetadatahelper proxy is nullptr.");

    std::shared_ptr<AVMetadataHelperClient> avMetadataHelper = AVMetadataHelperClient::Create(avMetadataHelperProxy);
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, nullptr, "failed to create avmetadatahelper client.");

    avMetadataHelperClientList_.push_back(avMetadataHelper);
    return avMetadataHelper;
}

int32_t MediaClient::DestroyAVMetadataHelperService(std::shared_ptr<IAVMetadataHelperService> avMetadataHelper)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(avMetadataHelper != nullptr, MSERR_NO_MEMORY,
        "input avmetadatahelper is nullptr.");
    avMetadataHelperClientList_.remove(avMetadataHelper);
    return MSERR_OK;
}
#endif

#ifdef SUPPORT_SCREEN_CAPTURE
std::shared_ptr<IScreenCaptureMonitorService> MediaClient::CreateScreenCaptureMonitorService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE_MONITOR, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "screenCaptureMonitor proxy object is nullptr.");

    sptr<IStandardScreenCaptureMonitorService> screenCaptureMonitorProxy =
        iface_cast<IStandardScreenCaptureMonitorService>(object);
    CHECK_AND_RETURN_RET_LOG(screenCaptureMonitorProxy != nullptr, nullptr, "screenCaptureMonitor proxy is nullptr.");

    std::shared_ptr<ScreenCaptureMonitorClient> screenCaptureMonitor =
        ScreenCaptureMonitorClient::Create(screenCaptureMonitorProxy);
    CHECK_AND_RETURN_RET_LOG(screenCaptureMonitor != nullptr, nullptr, "failed to create screenCaptureMonitor client.");
    screenCaptureMonitorClientList_.push_back(screenCaptureMonitor);
    return screenCaptureMonitor;
}

int32_t MediaClient::DestroyScreenCaptureMonitorService(
    std::shared_ptr<IScreenCaptureMonitorService> screenCaptureMonitor)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(screenCaptureMonitor != nullptr, MSERR_NO_MEMORY,
        "input screenCapture is nullptr.");
    screenCaptureMonitorClientList_.remove(screenCaptureMonitor);
    return MSERR_OK;
}

std::shared_ptr<IScreenCaptureService> MediaClient::CreateScreenCaptureService()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "screenCapture proxy object is nullptr.");

    sptr<IStandardScreenCaptureService> screenCaptureProxy = iface_cast<IStandardScreenCaptureService>(object);
    CHECK_AND_RETURN_RET_LOG(screenCaptureProxy != nullptr, nullptr, "screenCapture proxy is nullptr.");

    std::shared_ptr<ScreenCaptureClient> screenCapture = ScreenCaptureClient::Create(screenCaptureProxy);
    CHECK_AND_RETURN_RET_LOG(screenCapture != nullptr, nullptr, "failed to create screenCapture client.");

    screenCaptureClientList_.push_back(screenCapture);
    return screenCapture;
}

int32_t MediaClient::DestroyScreenCaptureService(std::shared_ptr<IScreenCaptureService> screenCapture)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(screenCapture != nullptr, MSERR_NO_MEMORY,
        "input screenCapture is nullptr.");
    screenCaptureClientList_.remove(screenCapture);
    return MSERR_OK;
}

std::shared_ptr<IScreenCaptureController> MediaClient::CreateScreenCaptureControllerClient()
{
    std::unique_lock<std::mutex> lock(mutex_);
    MEDIA_LOGI("MediaClient::CreateScreenCaptureControllerClient() start");

    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_SCREEN_CAPTURE_CONTROLLER,
        object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "screenCapture controller proxy object is nullptr.");

    sptr<IStandardScreenCaptureController> controllerProxy = iface_cast<IStandardScreenCaptureController>(object);
    CHECK_AND_RETURN_RET_LOG(controllerProxy != nullptr, nullptr, "controllerProxy is nullptr.");

    std::shared_ptr<ScreenCaptureControllerClient> controller = ScreenCaptureControllerClient::Create(controllerProxy);
    CHECK_AND_RETURN_RET_LOG(controller != nullptr, nullptr, "failed to create screenCapture controller.");

    screenCaptureControllerList_.push_back(controller);
    MEDIA_LOGI("MediaClient::CreateScreenCaptureControllerClient() end");
    return controller;
}

int32_t MediaClient::DestroyScreenCaptureControllerClient(std::shared_ptr<IScreenCaptureController> controller)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(controller != nullptr, MSERR_NO_MEMORY,
        "input screenCapture controller is nullptr.");
    screenCaptureControllerList_.remove(controller);
    return MSERR_OK;
}
#endif

std::vector<pid_t> MediaClient::GetPlayerPids()
{
    std::vector<pid_t> res;
    CHECK_AND_RETURN_RET_LOG(IsAlived(), res, "MediaServer Is Not Alived");
    return mediaProxy_->GetPlayerPids();
}

#ifdef SUPPORT_LPP_AUDIO_STRAMER
std::shared_ptr<ILppAudioStreamerService> MediaClient::CreateLppAudioStreamerService()
{
    MEDIA_LOGI("CreateLppAudioStreamerService start");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsAlived(), nullptr, "media service does not exist.");

    sptr<IRemoteObject> object = mediaProxy_->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_LPP_AUDIO_PLAYER, listenerStub_->AsObject());
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "lppAudioPlayer proxy object is nullptr.");

    sptr<IStandardLppAudioStreamerService> lppAudioPlayerProxy = iface_cast<IStandardLppAudioStreamerService>(object);
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayerProxy != nullptr, nullptr, "lppAudioPlayerProxy proxy is nullptr.");

    std::shared_ptr<LppAudioStreamerClient> lppAudioPlayer = LppAudioStreamerClient::Create(lppAudioPlayerProxy);
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayer != nullptr, nullptr, "failed to create lppAudioPlayer client.");

    lppAudioPlayerClientList_.push_back(lppAudioPlayer);
    MEDIA_LOGI("CreateLppAudioStreamerService end");
    return lppAudioPlayer;
}

int32_t MediaClient::DestroyLppAudioStreamerService(std::shared_ptr<ILppAudioStreamerService> lppAudioPlayer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(lppAudioPlayer != nullptr, MSERR_NO_MEMORY,
        "input lppAudioPlayer is nullptr.");
    lppAudioPlayerClientList_.remove(lppAudioPlayer);
    return MSERR_OK;
}
#endif

#ifdef SUPPORT_LPP_VIDEO_STRAMER
std::shared_ptr<ILppVideoStreamerService> MediaClient::CreateLppVideoStreamerService()
{
    MEDIA_LOGI("CreateLppVideoStreamerService start");
    std::unique_lock<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(IsAlived(), nullptr, "media service does not exist.");

    sptr<IRemoteObject> object = mediaProxy_->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_LPP_VIDEO_PLAYER, listenerStub_->AsObject());
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "lppVideoStreamer proxy object is nullptr.");

    sptr<IStandardLppVideoStreamerService> lppVideoStreamerProxy = iface_cast<IStandardLppVideoStreamerService>(object);
    CHECK_AND_RETURN_RET_LOG(lppVideoStreamerProxy != nullptr, nullptr, "lppVideoStreamerProxy proxy is nullptr.");

    std::shared_ptr<LppVideoStreamerClient> lppVideoStreamer = LppVideoStreamerClient::Create(lppVideoStreamerProxy);
    CHECK_AND_RETURN_RET_LOG(lppVideoStreamer != nullptr, nullptr, "failed to create lppVideoStreamer client.");

    lppVideoStreamerClientList_.push_back(lppVideoStreamer);
    MEDIA_LOGI("CreateLppVideoStreamerService end");
    return lppVideoStreamer;
}

int32_t MediaClient::DestroyLppVideoStreamerService(std::shared_ptr<ILppVideoStreamerService> lppVideoStreamer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(lppVideoStreamer != nullptr, MSERR_NO_MEMORY,
        "input lppVideoStreamer is nullptr.");
    lppVideoStreamerClientList_.remove(lppVideoStreamer);
    return MSERR_OK;
}
#endif

sptr<IStandardMonitorService> MediaClient::GetMonitorProxy()
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<IRemoteObject> object = nullptr;
    CreateMediaServiceInstance(IStandardMediaService::MediaSystemAbility::MEDIA_MONITOR, object, lock);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "monitor proxy object is nullptr.");

    sptr<IStandardMonitorService> monitorProxy = iface_cast<IStandardMonitorService>(object);
    CHECK_AND_RETURN_RET_LOG(monitorProxy != nullptr, nullptr, "monitor proxy is nullptr.");

    return monitorProxy;
}

sptr<IStandardMediaService> MediaClient::GetMediaProxy()
{
    MEDIA_LOGD("enter");
    sptr<ISystemAbilityManager> samgr = nullptr;
    samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(samgr != nullptr, nullptr, "system ability manager is nullptr.");
    sptr<IRemoteObject> object = nullptr;
    object = samgr->CheckSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID);
    if (object == nullptr) {
        MEDIA_LOGI("SA not load");
        object = samgr->LoadSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID, LOAD_TIME);
    }
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "media object is nullptr.");

    mediaProxy_ = iface_cast<IStandardMediaService>(object);
    CHECK_AND_RETURN_RET_LOG(mediaProxy_ != nullptr, nullptr, "media proxy is nullptr.");

    pid_t pid = 0;
    deathRecipient_ = new(std::nothrow) MediaDeathRecipient(pid);
    CHECK_AND_RETURN_RET_LOG(deathRecipient_ != nullptr, nullptr, "failed to new MediaDeathRecipient.");

    deathRecipient_->SetNotifyCb(std::bind(&MediaClient::MediaServerDied, std::placeholders::_1,
        g_mediaClientInstance));
    bool result = object->AddDeathRecipient(deathRecipient_);
    if (!result) {
        MEDIA_LOGE("failed to add deathRecipient");
        return nullptr;
    }

    listenerStub_ = new(std::nothrow) MediaListenerStub();
    CHECK_AND_RETURN_RET_LOG(listenerStub_ != nullptr, nullptr, "failed to new MediaListenerStub");
    return mediaProxy_;
}

void MediaClient::MediaServerDied(pid_t pid, std::weak_ptr<MediaClient> client)
{
    MEDIA_LOGE("media server is died, pid:%{public}d!", pid);
    auto instance = client.lock();
    CHECK_AND_RETURN_LOG(instance, "mediaClient instance has been released, maybe current process is exiting");
    instance->DoMediaServerDied();
}

void MediaClient::AVPlayerServerDied()
{
#ifdef SUPPORT_PLAYER
    for (auto &it : playerClientList_) {
        auto player = std::static_pointer_cast<PlayerClient>(it);
        if (player != nullptr) {
            player->MediaServerDied();
        }
    }
#endif

#ifdef SUPPORT_METADATA
    for (auto &it : avMetadataHelperClientList_) {
        auto avMetadataHelper = std::static_pointer_cast<AVMetadataHelperClient>(it);
        if (avMetadataHelper != nullptr) {
            avMetadataHelper->MediaServerDied();
        }
    }
#endif
}

void MediaClient::AVTranscoderServerDied()
{
#ifdef SUPPORT_TRANSCODER
    for (auto &it : transCoderClientList_) {
        auto transcoder = std::static_pointer_cast<TransCoderClient>(it);
        if (transcoder != nullptr) {
            transcoder->MediaServerDied();
        }
    }
#endif
}

void MediaClient::AVRecorderServerDied()
{
#ifdef SUPPORT_RECORDER
    for (auto &it : recorderClientList_) {
        auto recorder = std::static_pointer_cast<RecorderClient>(it);
        if (recorder != nullptr) {
            recorder->MediaServerDied();
        }
    }
    for (auto &it : recorderProfilesClientList_) {
        auto recorderProfilesClient = std::static_pointer_cast<RecorderProfilesClient>(it);
        if (recorderProfilesClient != nullptr) {
            recorderProfilesClient->MediaServerDied();
        }
    }
#endif
}

void MediaClient::AVScreenCaptureServerDied()
{
#ifdef SUPPORT_SCREEN_CAPTURE
    for (auto &it : screenCaptureClientList_) {
        auto screenCaptureClient = std::static_pointer_cast<ScreenCaptureClient>(it);
        if (screenCaptureClient != nullptr) {
            screenCaptureClient->MediaServerDied();
        }
    }
    for (auto &it : screenCaptureMonitorClientList_) {
        auto screenCaptureMonitorClient = std::static_pointer_cast<ScreenCaptureMonitorClient>(it);
        if (screenCaptureMonitorClient != nullptr) {
            screenCaptureMonitorClient->MediaServerDied();
        }
    }
    for (auto &it : screenCaptureControllerList_) {
        auto screenCaptureControllerClient = std::static_pointer_cast<ScreenCaptureControllerClient>(it);
        if (screenCaptureControllerClient != nullptr) {
            screenCaptureControllerClient->MediaServerDied();
        }
    }
#endif
}

void MediaClient::LppServerDied()
{
#ifdef SUPPORT_LPP_AUDIO_STRAMER
    for (auto &it : lppAudioPlayerClientList_) {
        auto audioStreamer = std::static_pointer_cast<LppAudioStreamerClient>(it);
        if (audioStreamer != nullptr) {
            audioStreamer->MediaServerDied();
        }
    }
#endif

#ifdef SUPPORT_LPP_VIDEO_STRAMER
    for (auto &it : lppVideoStreamerClientList_) {
        auto videoStreamer = std::static_pointer_cast<LppVideoStreamerClient>(it);
        if (videoStreamer != nullptr) {
            videoStreamer->MediaServerDied();
        }
    }
#endif
}

void MediaClient::DoMediaServerDied()
{
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGI("DoMediaServerDied");
    if (mediaProxy_ != nullptr) {
        sptr<IRemoteObject> object = mediaProxy_->AsObject();
        if (object != nullptr) {
            object->RemoveDeathRecipient(deathRecipient_);
        }
        mediaProxy_ = nullptr;
    }
    listenerStub_ = nullptr;
    deathRecipient_ = nullptr;
    std::shared_ptr<MonitorClient> monitor = MonitorClient::GetInstance();
    CHECK_AND_RETURN_LOG(monitor != nullptr, "Failed to get monitor Instance!");
    monitor->MediaServerDied();
    AVPlayerServerDied();
    AVTranscoderServerDied();
    AVRecorderServerDied();
    AVScreenCaptureServerDied();
    LppServerDied();
    mediaProxyUpdatedCondition_.notify_all();
}

bool MediaClient::CanKillMediaService()
{
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    CHECK_AND_RETURN_RET_LOG(lock.owns_lock(), false, "MediaClient mutex_ try_lock false, please try again later.");
    CHECK_AND_RETURN_RET_LOG(IsAlived(), false, "media service does not exist.");

    return mediaProxy_->CanKillMediaService();
}
} // namespace Media
} // namespace OHOS