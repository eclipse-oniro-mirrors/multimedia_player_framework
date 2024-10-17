/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <climits>
#include <sstream>
#include "media_log.h"
#include "media_errors.h"
#include "media_dfx.h"
#include "media_server_manager.h"
#include "media_app_frozen_state_observer.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaAppFrozenStateObserver"};
}

namespace OHOS {
namespace Media {
void MediaAppFrozenStateObserver::OnActive(const std::vector<int32_t> &pidList, const int32_t uid)
{
    MEDIA_LOGI("Current uid: %{public}d OnActive\n", uid);
    if (pidList.empty()) {
        MEDIA_LOGI("OnActive pidList empty");
        return;
    }
    MediaServerManager::GetInstance().HandlePlayerActive(pidList, uid);
    // do something
}
 
void MediaAppFrozenStateObserver::OnDoze(const int32_t uid)
{
    MEDIA_LOGD("Current uid: %{public}d OnDoze\n", uid);
}

void MediaAppFrozenStateObserver::OnFrozen(const std::vector<int32_t> &pidList, const int32_t uid)
{
    MEDIA_LOGI("Current uid: %{public}d OnFrozen\n", uid);
    if (pidList.empty()) {
        MEDIA_LOGI("OnFrozen pidList empty");
        return;
    }
    // do something
    MediaServerManager::GetInstance().HandlePlayerFrozen(pidList, uid);
}
} // namespace Memory
} // namespace OHOS
