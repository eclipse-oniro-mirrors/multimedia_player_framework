/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "screen_capture_server_manager.h"
#include <set>
#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServerManager"};
}

namespace OHOS {
namespace Media {

ScreenCaptureServerManager &ScreenCaptureServerManager::GetInstance()
{
    static ScreenCaptureServerManager instance;
    return instance;
}

ScreenCaptureServerManager::ScreenCaptureServerManager() : idGenerator_(maxSessionId_)
{
    MEDIA_LOGD("ScreenCaptureServerManager create");
}

int32_t ScreenCaptureServerManager::GetNewSessionId()
{
    return idGenerator_.GetNewID();
}

void ScreenCaptureServerManager::RegisterServer(int32_t sessionId, std::weak_ptr<ScreenCaptureServer> server,
    int32_t appUid)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    serverMap_[sessionId] = {server, appUid, static_cast<DataType>(0)};
    MEDIA_LOGI("RegisterServer sessionId: %{public}d, serverMap size: %{public}d", sessionId,
        static_cast<uint32_t>(serverMap_.size()));
}

void ScreenCaptureServerManager::RemoveScreenCaptureServerMap(int32_t sessionId)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    serverMap_.erase(sessionId);
    int32_t returnId = idGenerator_.ReturnID(sessionId);
    if (returnId == -1) {
        MEDIA_LOGI("RemoveScreenCaptureServerMap returnId: %{public}d is invalid", returnId);
    }
    MEDIA_LOGI("RemoveScreenCaptureServerMap end. sessionId: %{public}d, serverMap size: %{public}d.", sessionId,
        static_cast<uint32_t>(serverMap_.size()));
}

void ScreenCaptureServerManager::UpdateServerAppUid(int32_t sessionId, int32_t appUid)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = serverMap_.find(sessionId);
    if (it != serverMap_.end()) {
        it->second.appUid = appUid;
    }
}

void ScreenCaptureServerManager::UpdateServerDataType(int32_t sessionId, DataType dataType)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = serverMap_.find(sessionId);
    if (it != serverMap_.end()) {
        it->second.dataType = dataType;
    }
}

bool ScreenCaptureServerManager::CheckSCServerSpecifiedDataTypeNum(int32_t curAppUid, DataType dataType)
{
    MEDIA_LOGI("CheckSCServerSpecifiedDataTypeNum curAppUid: %{public}d, dataType: %{public}d", curAppUid, dataType);
    std::shared_lock<std::shared_mutex> lock(mutex_);
    int32_t count = 0;
    for (const auto &entry : serverMap_) {
        if (entry.second.appUid == curAppUid && entry.second.dataType == dataType) {
            count++;
        }
        CHECK_AND_RETURN_RET_LOG(count <= maxSCServerDataTypePerUid_, false,
            "uid(%{public}d) has too many instances of dataType(%{public}d)", curAppUid, dataType);
    }
    return true;
}

std::weak_ptr<ScreenCaptureServer> ScreenCaptureServerManager::GetScreenCaptureServerById(int32_t id)
{
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = serverMap_.find(id);
    if (it == serverMap_.end()) {
        return {};
    }
    return it->second.server;
}

bool ScreenCaptureServerManager::CanScreenCaptureInstanceBeCreate(int32_t appUid)
{
    MEDIA_LOGI("CanScreenCaptureInstanceBeCreate curAppUid: %{public}d", appUid);
    std::shared_lock<std::shared_mutex> lock(mutex_);
    CHECK_AND_RETURN_RET_LOG(serverMap_.size() <= maxSessionId_, false, "exceed ScreenCaptureServer instances limit.");
    std::set<int32_t> appUidSet;
    int32_t countForUid = 0;
    for (const auto &entry : serverMap_) {
        appUidSet.insert(entry.second.appUid);
        if (entry.second.appUid == appUid) {
            countForUid++;
        }
        CHECK_AND_RETURN_RET_LOG(countForUid <= maxSessionPerUid_, false,
            "uid(%{public}d) has created too many ScreenCaptureServer instances", appUid);
    }
    CHECK_AND_RETURN_RET_LOG(static_cast<int32_t>(appUidSet.size()) <= maxAppLimit_, false,
        "CurScreenCaptureAppNum reach limit, cannot create more app.");
    return true;
}

void ScreenCaptureServerManager::AddSaAppInfoMap(int32_t saUid, int32_t curAppUid)
{
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (saUidAppUidMap_.find(saUid) == saUidAppUidMap_.end()) {
        saUidAppUidMap_.insert({saUid, std::make_pair(curAppUid, 1)});
        MEDIA_LOGI("AddSaAppInfoMap insert SUCCESS! mapSize: %{public}d",
            static_cast<uint32_t>(saUidAppUidMap_.size()));
    } else {
        saUidAppUidMap_[saUid].second++;
    }
}

void ScreenCaptureServerManager::RemoveSaAppInfoMap(int32_t saUid)
{
    CHECK_AND_RETURN(saUid != -1);
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = saUidAppUidMap_.find(saUid);
    if (it != saUidAppUidMap_.end() && it->second.second > 0) {
        it->second.second--;
        if (it->second.second == 0) {
            saUidAppUidMap_.erase(it);
        }
    }
    MEDIA_LOGI("RemoveSaAppInfoMap saUid: %{public}d, mapSize: %{public}d", saUid,
        static_cast<uint32_t>(saUidAppUidMap_.size()));
}

bool ScreenCaptureServerManager::IsSAUidValid(int32_t saUid, int32_t appUid)
{
    CHECK_AND_RETURN_RET_LOG(saUid >= 0 && appUid >= 0, false, "saUid or appUid is invalid.");
    CHECK_AND_RETURN_RET_LOG(IsSACalling(), false, "fake SAServiceCalling!");
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto it = saUidAppUidMap_.find(saUid);
    if (it != saUidAppUidMap_.end() && (it->second.first != appUid || it->second.second >= maxSessionPerUid_)) {
        MEDIA_LOGI("saUid Invalid! saUid: %{public}d linked with appUid: %{public}d, curAppUid: %{public}d", saUid,
            it->second.first, appUid);
        return false;
    }
    return true;
}

} // namespace Media
} // namespace OHOS
