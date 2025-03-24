/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "system_sound_manager_utils.h"

#include <fstream>
#include "ringtone_proxy_uri.h"
#include "system_sound_log.h"
#include "media_errors.h"
#include "os_account_manager.h"
#include "system_tone_player_impl.h"
#include "parameter.h"

using namespace std;
using namespace nlohmann;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::DataShare;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "SystemSoundManagerUtils"};
}

namespace OHOS {
namespace Media {

constexpr int32_t RETRY_TIME_S = 5;
constexpr int64_t SLEEP_TIME_S = 1;

int32_t SystemSoundManagerUtils::GetCurrentUserId()
{
    std::vector<int32_t> ids;
    int32_t currentuserId = -1;
    ErrCode result;
    int32_t retry = RETRY_TIME_S;
    while (retry--) {
        result = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
        if (result == ERR_OK && !ids.empty()) {
            currentuserId = ids[0];
            MEDIA_LOGD("current userId is :%{public}d", currentuserId);
            break;
        }

        // sleep and wait for 1 millisecond
        sleep(SLEEP_TIME_S);
    }
    if (result != ERR_OK || ids.empty()) {
        MEDIA_LOGW("current userId is empty");
    }
    return currentuserId;
}

shared_ptr<DataShare::DataShareHelper> SystemSoundManagerUtils::CreateDataShareHelperUri(int32_t systemAbilityId)
{
    MEDIA_LOGI("ringtoneplayer::CreateDataShareHelperUri : Enter the CreateDataShareHelperUri interface");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        return nullptr;
    }
    MEDIA_LOGI("CreateDataShareHelperUri : Enter CreateDataShareHelperUri()");
    int32_t useId = SystemSoundManagerUtils::GetCurrentUserId();
    std::string uri = RINGTONE_LIBRARY_PROXY_URI + "?" + "user=" + std::to_string(useId);
    MEDIA_LOGI("uri : %{public}s", uri.c_str());
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> dataShare =
        DataShare::DataShareHelper::Create(remoteObj, uri, "");
    MEDIA_LOGI("errcode : %{public}d", dataShare.first);
    return dataShare.second;
}

shared_ptr<DataShare::DataShareHelper> SystemSoundManagerUtils::CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_LOGI("CreateDataShareHelper : Enter CreateDataShareHelper()");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_LOGE("Get system ability manager failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    if (remoteObj == nullptr) {
        MEDIA_LOGE("Get system ability:[%{public}d] failed.", systemAbilityId);
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, RINGTONE_URI);
}
} // namesapce Media
} // namespace OHOS