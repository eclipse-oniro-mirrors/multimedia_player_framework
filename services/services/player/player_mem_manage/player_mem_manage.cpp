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

#include "player_mem_manage.h"
#include <unistd.h>
#include <functional>
#include "media_log.h"
#include "media_errors.h"
#include "mem_mgr_client.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN, "PlayerMemManage"};
}

namespace OHOS {
namespace Media {
constexpr double APP_BACK_GROUND_DESTROY_MEMERY_TIME = 60.0;
constexpr double APP_FRONT_GROUND_DESTROY_MEMERY_TIME = 120.0;
constexpr int32_t RESERVE_BACK_GROUND_APP_NUM = 1;
PlayerMemManage& PlayerMemManage::GetInstance()
{
    static PlayerMemManage instance;
    if (!instance.Init()) {
        MEDIA_LOGE("GetInstance Init Failed");
    }
    return instance;
}

PlayerMemManage::PlayerMemManage()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

PlayerMemManage::~PlayerMemManage()
{
    Memory::MemMgrClient::GetInstance().UnsubscribeAppState(*appStateListener_);
    existTask_ = true;
    if (isCreateProbeTask_) {
        probeTaskQueue_->Stop();
    }
    playerManage_.clear();
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void PlayerMemManage::FindBackGroundPlayerFromVec(AppPlayerInfo &appPlayerInfo)
{
    if (appPlayerInfo.appState != static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND) ||
        appPlayerInfo.isReserve) {
        return;
    }
    std::chrono::duration<double> durationCost = std::chrono::duration_cast<
        std::chrono::duration<double>>(std::chrono::steady_clock::now() - appPlayerInfo.appEnterBackTime);
    if (durationCost.count() <= APP_BACK_GROUND_DESTROY_MEMERY_TIME) {
        return;
    }

    for (auto iter = appPlayerInfo.memRecallStructVec.begin(); iter != appPlayerInfo.memRecallStructVec.end(); iter++) {
        ((*iter).resetBackGroundRecall)();
    }
}

void PlayerMemManage::FindFrontGroundPlayerFromVec(AppPlayerInfo &appPlayerInfo)
{
    if (appPlayerInfo.appState != static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND)) {
        return;
    }

    std::chrono::duration<double> durationCost = std::chrono::duration_cast<
        std::chrono::duration<double>>(std::chrono::steady_clock::now() - appPlayerInfo.appEnterFrontTime);
    if (durationCost.count() <= APP_FRONT_GROUND_DESTROY_MEMERY_TIME) {
        return;
    }

    for (auto iter = appPlayerInfo.memRecallStructVec.begin(); iter != appPlayerInfo.memRecallStructVec.end(); iter++) {
        ((*iter).resetFrontGroundRecall)();
    }
}

bool PlayerMemManage::BackGroundTimeGreaterSort(AppPlayerInfo *a, AppPlayerInfo *b)
{
    return std::chrono::duration_cast<
        std::chrono::duration<double>>(a->appEnterBackTime - b->appEnterBackTime).count() > 0;
}

void PlayerMemManage::SetLastestExitBackGroundApp()
{
    std::vector<AppPlayerInfo*> allAppVec;
    for (auto &[uid, pidPlayersInfo] : playerManage_) {
        for (auto &[pid, appPlayerInfo] : pidPlayersInfo) {
            if (appPlayerInfo.appState != static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND)) {
                continue;
            }
            allAppVec.push_back(&appPlayerInfo);
        }
    }
    std::sort(allAppVec.begin(), allAppVec.end(), BackGroundTimeGreaterSort);

    int32_t cnt = 0;
    for (auto iter = allAppVec.begin(); iter != allAppVec.end(); iter++) {
        if (cnt < RESERVE_BACK_GROUND_APP_NUM) {
            (*iter)->isReserve = true;
        } else {
            (*iter)->isReserve = false;
        }
        cnt++;
    }
}

void PlayerMemManage::FindProbeTaskPlayer()
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    SetLastestExitBackGroundApp();
    for (auto &[uid, pidPlayersInfo] : playerManage_) {
        for (auto &[pid, appPlayerInfo] : pidPlayersInfo) {
            FindFrontGroundPlayerFromVec(appPlayerInfo);
            FindBackGroundPlayerFromVec(appPlayerInfo);
        }
    }
}

void PlayerMemManage::ProbeTask()
{
    while (!existTask_) {
        FindProbeTaskPlayer();
        sleep(1);  // 1 : one second interval check
    }
}

bool PlayerMemManage::Init()
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    if (isParsered_) {
        if (appStateListener_ != nullptr && appStateListenerRomoteDied_) {
            MEDIA_LOGE("MemMgrClient died, SubscribeAppState again");
            Memory::MemMgrClient::GetInstance().SubscribeAppState(*appStateListener_);
        }
        return true;
    }
    MEDIA_LOGI("Create PlayerMemManage");
    playerManage_.clear();
    if (isCreateProbeTask_) {
        probeTaskQueue_ = std::make_unique<TaskQueue>("probeTaskQueue");
        CHECK_AND_RETURN_RET_LOG(probeTaskQueue_->Start() == MSERR_OK, false, "init task failed");
        auto task = std::make_shared<TaskHandler<void>>([this] {
            ProbeTask();
        });
        CHECK_AND_RETURN_RET_LOG(probeTaskQueue_->EnqueueTask(task) == MSERR_OK, false, "enque task fail");
    }

    appStateListener_ = std::make_shared<AppStateListener>();
    CHECK_AND_RETURN_RET_LOG(appStateListener_ != nullptr, false, "failed to new AppStateListener");

    Memory::MemMgrClient::GetInstance().SubscribeAppState(*appStateListener_);
    isParsered_ = true;
    return true;
}

int32_t PlayerMemManage::RegisterPlayerServer(int32_t uid, int32_t pid, const MemManageRecall &memRecallStruct)
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);

    MEDIA_LOGI("Register PlayerServerTask uid:%{public}d, pid:%{public}d", uid, pid);
    auto objIter = playerManage_.find(uid);
    if (objIter == playerManage_.end()) {
        MEDIA_LOGI("new user in uid:%{public}d", uid);
        auto ret = playerManage_.emplace(uid, PidPlayersInfo {});
        objIter = ret.first;
    }

    auto &pidPlayersInfo = objIter->second;
    auto pidIter = pidPlayersInfo.find(pid);
    if (pidIter == pidPlayersInfo.end()) {
        MEDIA_LOGI("new app in pid:%{public}d", pid);
        auto ret = pidPlayersInfo.emplace(pid, AppPlayerInfo {std::vector<MemManageRecall>(),
            static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND), false,
            std::chrono::steady_clock::now(), std::chrono::steady_clock::now()});
        Memory::MemMgrClient::GetInstance().RegisterActiveApps(pid, uid);
        pidIter = ret.first;
    }

    auto &appPlayerInfo = pidIter->second;
    appPlayerInfo.memRecallStructVec.push_back(memRecallStruct);

    return MSERR_OK;
}

void PlayerMemManage::FindDeregisterPlayerFromVec(bool &isFind, AppPlayerInfo &appPlayerInfo,
    const MemManageRecall &memRecallStruct)
{
    for (auto iter = appPlayerInfo.memRecallStructVec.begin(); iter != appPlayerInfo.memRecallStructVec.end();) {
        if ((*iter).signAddr == memRecallStruct.signAddr) {
            iter = appPlayerInfo.memRecallStructVec.erase(iter);
            MEDIA_LOGI("Remove PlayerServerTask from vector size:%{public}u",
                static_cast<uint32_t>(appPlayerInfo.memRecallStructVec.size()));
            isFind = true;
            break;
        } else {
            iter++;
        }
    }
}

int32_t PlayerMemManage::DeregisterPlayerServer(const MemManageRecall &memRecallStruct)
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);

    MEDIA_LOGI("Deregister PlayerServerTask");
    bool isFind = false;
    for (auto &[uid, pidPlayersInfo] : playerManage_) {
        for (auto &[pid, appPlayerInfo] : pidPlayersInfo) {
            FindDeregisterPlayerFromVec(isFind, appPlayerInfo, memRecallStruct);
            if (appPlayerInfo.memRecallStructVec.size() == 0) {
                Memory::MemMgrClient::GetInstance().DeregisterActiveApps(pid, uid);
                pidPlayersInfo.erase(pid);
                MEDIA_LOGI("DeregisterActiveApps pid:%{public}d uid:%{public}d pidPlayersInfo size:%{public}u",
                    pid, uid, static_cast<uint32_t>(pidPlayersInfo.size()));
                break;
            }
        }
        if (pidPlayersInfo.size() == 0) {
            playerManage_.erase(uid);
            MEDIA_LOGI("remove uid:%{public}d playerManage_ size:%{public}u",
                uid, static_cast<uint32_t>(playerManage_.size()));
            break;
        }
    }

    if (!isFind) {
        MEDIA_LOGW("Not find memRecallPair, maybe already deregister");
        return MSERR_INVALID_OPERATION;
    }

    return MSERR_OK;
}

/* mem_mgr_client : currently dose not support the trigger this interface */
int32_t PlayerMemManage::HandleForceReclaim(int32_t uid, int32_t pid)
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);

    MEDIA_LOGI("Enter ForceReclaim pid:%{public}d uid:%{public}d", pid, uid);
    for (auto &[findUid, pidPlayersInfo] : playerManage_) {
        if (findUid != uid) {
            continue;
        }
        for (auto &[findPid, appPlayerInfo] : pidPlayersInfo) {
            if (findPid != pid) {
                continue;
            }
            if (appPlayerInfo.appState != static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND)) {
                MEDIA_LOGE("HandleForceReclaim appState not allow");
                return MSERR_INVALID_OPERATION;
            }
            for (auto iter = appPlayerInfo.memRecallStructVec.begin();
                iter != appPlayerInfo.memRecallStructVec.end(); iter++) {
                ((*iter).resetMemmgrRecall)();
                MEDIA_LOGI("call ResetForMemManageRecall success");
            }
            return MSERR_OK;
        }
    }
    return MSERR_OK;
}

void PlayerMemManage::HandleOnTrimLevelLow()
{
    for (auto &[findUid, pidPlayersInfo] : playerManage_) {
        for (auto &[findPid, appPlayerInfo] : pidPlayersInfo) {
            if (appPlayerInfo.appState != static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND)) {
                continue;
            }

            for (auto iter = appPlayerInfo.memRecallStructVec.begin();
                iter != appPlayerInfo.memRecallStructVec.end(); iter++) {
                ((*iter).resetMemmgrRecall)();
                MEDIA_LOGI("call ResetForMemManageRecall success");
            }
        }
    }
}

int32_t PlayerMemManage::HandleOnTrim(Memory::SystemMemoryLevel level)
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    MEDIA_LOGI("Enter OnTrim level:%{public}d", level);

    switch (level) {
        case Memory::SystemMemoryLevel::MEMORY_LEVEL_MODERATE:  // remain 800MB trigger
            break;

        case Memory::SystemMemoryLevel::MEMORY_LEVEL_LOW:  // remain 700MB trigger
            HandleOnTrimLevelLow();
            break;

        case Memory::SystemMemoryLevel::MEMORY_LEVEL_CRITICAL: // remain 600MB trigger
            break;

        default:
            break;
    }

    return MSERR_OK;
}

void PlayerMemManage::AwakeFrontGroundAppMedia(AppPlayerInfo &appPlayerInfo)
{
    for (auto iter = appPlayerInfo.memRecallStructVec.begin();
        iter != appPlayerInfo.memRecallStructVec.end(); iter++) {
        ((*iter).recoverRecall)();
    }
    MEDIA_LOGI("call RecoverByMemManageRecall success");
}

void PlayerMemManage::SetAppPlayerInfo(AppPlayerInfo &appPlayerInfo, int32_t state)
{
    if (appPlayerInfo.appState != state) {
        appPlayerInfo.appState = state;
        if (state == static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND)) {
            appPlayerInfo.appEnterFrontTime = std::chrono::steady_clock::now();
            AwakeFrontGroundAppMedia(appPlayerInfo);
        } else if (state == static_cast<int32_t>(AppState::APP_STATE_BACK_GROUND)) {
            appPlayerInfo.appEnterBackTime = std::chrono::steady_clock::now();
        }
    }
}

int32_t PlayerMemManage::RecordAppState(int32_t uid, int32_t pid, int32_t state)
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    MEDIA_LOGI("Enter OnAppStateChanged pid:%{public}d uid:%{public}d state:%{public}d", pid, uid, state);
    for (auto &[findUid, pidPlayersInfo] : playerManage_) {
        if (findUid != uid) {
            continue;
        }
        for (auto &[findPid, appPlayerInfo] : pidPlayersInfo) {
            if (findPid != pid) {
                continue;
            }
            SetAppPlayerInfo(appPlayerInfo, state);
            return MSERR_OK;
        }
    }

    return MSERR_OK;
}

void PlayerMemManage::RemoteDieAgainRegisterActiveApps()
{
    MEDIA_LOGI("Enter");
    for (auto &[findUid, pidPlayersInfo] : playerManage_) {
        for (auto &[findPid, appPlayerInfo] : pidPlayersInfo) {
            MEDIA_LOGI("Again RegisterActiveApps uid:%{public}d, pid:%{public}d", findUid, findPid);
            Memory::MemMgrClient::GetInstance().RegisterActiveApps(findPid, findUid);
        }
    }
}

void PlayerMemManage::HandleOnConnected()
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    MEDIA_LOGI("Enter RemoteDied:%{public}d", appStateListenerRomoteDied_);
    appStateListenerIsConnected_ = true;
    if (appStateListenerRomoteDied_) {
        RemoteDieAgainRegisterActiveApps();
        appStateListenerRomoteDied_ = false;
    }
}

void PlayerMemManage::HandleOnDisconnected()
{
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    MEDIA_LOGI("Enter");
    appStateListenerIsConnected_ = false;
}

void PlayerMemManage::HandleOnRemoteDied(const wptr<IRemoteObject> &object)
{
    (void)object;
    std::lock_guard<std::recursive_mutex> lock(recMutex_);
    MEDIA_LOGI("Enter");
    appStateListenerRomoteDied_ = true;
    appStateListenerIsConnected_ = false;

    for (auto &[findUid, pidPlayersInfo] : playerManage_) {
        for (auto &[findPid, appPlayerInfo] : pidPlayersInfo) {
            MEDIA_LOGI("Set all App front ground, uid:%{public}d, pid:%{public}d", findUid, findPid);
            appPlayerInfo.appState = static_cast<int32_t>(AppState::APP_STATE_FRONT_GROUND);
            appPlayerInfo.appEnterFrontTime = std::chrono::steady_clock::now();
        }
    }
}
}
}