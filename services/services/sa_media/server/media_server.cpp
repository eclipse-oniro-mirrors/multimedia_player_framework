/*
 * Copyright (C) 2021-2025 Huawei Device Co., Ltd.
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

#include "media_server.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "media_errors.h"
#include "system_ability_definition.h"
#include "media_server_manager.h"
#include "mem_mgr_client.h"
#include "mem_mgr_proxy.h"
#include "audio_background_adapter.h"
#ifdef SUPPORT_CALL
#include "incall_observer.h"
#endif

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaServer"};
}

namespace OHOS {
namespace Media {
constexpr int32_t SYSTEM_STATUS_START = 1;
constexpr int32_t SYSTEM_STATUS_STOP = 0;
constexpr int32_t SYSTEM_PROCESS_TYPE = 1;

#ifdef SUPPORT_START_STOP_ON_DEMAND
const int32_t SECOND_CONVERT_MS = 1000;
const std::string SA_ONDEMAND_CONFIG = std::string(SA_CONFIG_PATH);
const int32_t DEFAULT_DELAY_TIME = 180;
#ifdef CROSS_PLATFORM
using json = nlohmann::json;
const std::string SYSTEMABILITY = std::string("systemability");
const std::string STOPONDEMAND = std::string("stop-on-demand");
const std::string LONGTIMEUNUSED = std::string("longtimeunused-unload");
#endif
REGISTER_SYSTEM_ABILITY_BY_ID(MediaServer, PLAYER_DISTRIBUTED_SERVICE_ID, false)
#else
REGISTER_SYSTEM_ABILITY_BY_ID(MediaServer, PLAYER_DISTRIBUTED_SERVICE_ID, true)
#endif

MediaServer::MediaServer(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

MediaServer::~MediaServer()
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void MediaServer::OnDump()
{
    MEDIA_LOGD("MediaServer OnDump");
}

void MediaServer::OnStart()
{
    MEDIA_LOGD("MediaServer OnStart");
    bool res = Publish(this);
    MEDIA_LOGD("MediaServer OnStart res=%{public}d", res);
    AddSystemAbilityListener(MEMORY_MANAGER_SA_ID);
    AddSystemAbilityListener(AUDIO_POLICY_SERVICE_ID);
#ifdef SUPPORT_CALL
    MEDIA_LOGD("InCallObserver init OnStart");
    InCallObserver::GetInstance();
#endif
}

void MediaServer::OnStop()
{
    MEDIA_LOGD("MediaServer OnStop");
    Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(),
        SYSTEM_PROCESS_TYPE, SYSTEM_STATUS_STOP, OHOS::PLAYER_DISTRIBUTED_SERVICE_ID);
}

int32_t MediaServer::FreezeStubForPids(const std::set<int32_t> &pidList, bool isProxy)
{
    int32_t size = static_cast<int32_t>(pidList.size());
    MEDIA_LOGI("received Freeze Notification, pidSize = %{public}d, isProxy = %{public}d",
               size, isProxy);
    
    for (auto pid : pidList) {
        MEDIA_LOGI("received Freeze Pid, pid = %{public}d, isProxy = %{public}d",
            pid, isProxy);
    }
    return MediaServerManager::GetInstance().FreezeStubForPids(pidList, isProxy);
}

int32_t MediaServer::ResetAllProxy()
{
    return MediaServerManager::GetInstance().ResetAllProxy();
}

#ifdef SUPPORT_START_STOP_ON_DEMAND
int32_t MediaServer::OnIdle(const SystemAbilityOnDemandReason &idleReason)
{
    MEDIA_LOGD("MediaServer OnIdle");
    auto instanceCount = MediaServerManager::GetInstance().GetInstanceCountLocked();
    CHECK_AND_RETURN_RET_LOG(instanceCount == 0, -1, "%{public} " PRId32 "instance are not released", instanceCount);
    unloadDelayTime_ = unloadDelayTime_ == -1 ? GetUnloadDelayTime() : unloadDelayTime_;
    int64_t ildeTimeStart = MediaServerManager::GetInstance().GetAllInstancesReleasedTime();
    int64_t currentTime = MediaServerManager::GetInstance().GetCurrentSystemClockMs();
    int32_t idleTime = currentTime > ildeTimeStart  ? currentTime - ildeTimeStart : ildeTimeStart - currentTime;
    CHECK_AND_RETURN_RET_LOG(unloadDelayTime_ <= idleTime, -1, "%{public} " PRId32 "ms wait to unload",
        unloadDelayTime_ - idleTime);
    return 0;
}

int32_t MediaServer::GetUnloadDelayTime()
{
    int32_t delayTime = -1;
    int32_t defaultDelayTime = DEFAULT_DELAY_TIME * SECOND_CONVERT_MS;
#ifdef CROSS_PLATFORM
    std::ifstream sa_ondemand_config_file(SA_ONDEMAND_CONFIG);
    CHECK_AND_RETURN_RET_LOG(sa_ondemand_config_file.is_open(), defaultDelayTime, "open SA config failed");
    json SAOnDemandConfig;
    sa_ondemand_config_file >> SAOnDemandConfig;
    sa_ondemand_config_file.close();
    json systemability = SAOnDemandConfig[SYSTEMABILITY];
    CHECK_AND_RETURN_RET_LOG(systemability.is_array(), defaultDelayTime, "systemability not exist");
    for (auto& ability : systemability) {
        json stopOnDemand = ability[STOPONDEMAND];
        CHECK_AND_CONTINUE_LOG(stopOnDemand.is_object(), "stop-on-demand not exist");
        json longTimeUnusedUnload = stopOnDemand[LONGTIMEUNUSED];
        CHECK_AND_CONTINUE_LOG(longTimeUnusedUnload.is_number(), "longtimeunused-Unload not exist");
        delayTime = longTimeUnusedUnload.get<int32_t>() * SECOND_CONVERT_MS;
        break;
    }
#endif
    delayTime = delayTime <= 0 ? defaultDelayTime : delayTime;
    MEDIA_LOGI("the unload delay time is %{public}d", delayTime);
    return delayTime;
}
#endif

void MediaServer::OnAddSystemAbility(int32_t systemAbilityId, const std::string &deviceId)
{
    MEDIA_LOGD("OnAddSystemAbility systemAbilityId:%{public}d", systemAbilityId);
    if (systemAbilityId == MEMORY_MANAGER_SA_ID) {
        Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(),
            SYSTEM_PROCESS_TYPE, SYSTEM_STATUS_START, OHOS::PLAYER_DISTRIBUTED_SERVICE_ID);
        MediaServerManager::GetInstance().NotifyMemMgrLoaded();
    } else if (systemAbilityId == AUDIO_POLICY_SERVICE_ID) {
        AudioBackgroundAdapter::Instance().OnAudioRestart();
    }
}

sptr<IRemoteObject> MediaServer::GetSubSystemAbility(IStandardMediaService::MediaSystemAbility subSystemId,
    const sptr<IRemoteObject> &listener)
{
    MEDIA_LOGD("GetSubSystemAbility, subSystemId is %{public}d", subSystemId);
#ifdef SUPPORT_START_STOP_ON_DEMAND
    bool isSaInActive = (GetAbilityState() != SystemAbilityState::IDLE) || CancelIdle();
    CHECK_AND_RETURN_RET_LOG(isSaInActive, nullptr, "media service in idle state, but cancel idle failed");
    MediaServerManager::GetInstance().ResetAllInstancesReleasedTime();
#endif

    int32_t ret = MediaServiceStub::SetDeathListener(listener);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed set death listener");

    switch (subSystemId) {
        case MediaSystemAbility::MEDIA_RECORDER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDER);
        }
        case MediaSystemAbility::MEDIA_TRANSCODER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::TRANSCODER);
        }
        case MediaSystemAbility::MEDIA_PLAYER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::PLAYER);
        }
        case MediaSystemAbility::MEDIA_AVMETADATAHELPER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVMETADATAHELPER);
        }
        case MediaSystemAbility::MEDIA_CODECLIST: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODECLIST);
        }
        case MediaSystemAbility::MEDIA_AVCODEC: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::AVCODEC);
        }
        case MediaSystemAbility::RECORDER_PROFILES: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::RECORDERPROFILES);
        }
        case MediaSystemAbility::MEDIA_MONITOR: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::MONITOR);
        }
        case MediaSystemAbility::MEDIA_SCREEN_CAPTURE: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE);
        }
        case MediaSystemAbility::MEDIA_SCREEN_CAPTURE_CONTROLLER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_CONTROLLER);
        }
        case MediaSystemAbility::MEDIA_SCREEN_CAPTURE_MONITOR: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::SCREEN_CAPTURE_MONITOR);
        }
        default: {
            return GetSubSystemAbilityPart(subSystemId);
        }
    }
}

sptr<IRemoteObject> MediaServer::GetSubSystemAbilityPart(IStandardMediaService::MediaSystemAbility subSystemId)
{
    switch (subSystemId) {
        case MediaSystemAbility::MEDIA_LPP_AUDIO_PLAYER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::LPP_AUDIO_PLAYER);
        }
        case MediaSystemAbility::MEDIA_LPP_VIDEO_PLAYER: {
            return MediaServerManager::GetInstance().CreateStubObject(MediaServerManager::LPP_VIDEO_PLAYER);
        }
        default: {
            MEDIA_LOGE("default case, media client need check subSystemId");
            return nullptr;
        }
    }
}

sptr<IRemoteObject> MediaServer::GetSubSystemAbilityWithTimeOut(IStandardMediaService::MediaSystemAbility subSystemId,
    const sptr<IRemoteObject> &listener, uint32_t timeoutMs)
{
    (void) timeoutMs;
    return GetSubSystemAbility(subSystemId, listener);
}

int32_t MediaServer::Dump(int32_t fd, const std::vector<std::u16string> &args)
{
    CHECK_AND_RETURN_RET_LOG(fd > 0, OHOS::INVALID_OPERATION, "Failed to check fd.");

    auto ret = MediaServerManager::GetInstance().Dump(fd, args);
    CHECK_AND_RETURN_RET_LOG(ret == NO_ERROR,
        OHOS::INVALID_OPERATION, "Failed to call MediaServerManager::Dump.");
    return OHOS::NO_ERROR;
}

bool MediaServer::CanKillMediaService()
{
    return MediaServerManager::GetInstance().CanKillMediaService();
}
} // namespace Media
} // namespace OHOS
