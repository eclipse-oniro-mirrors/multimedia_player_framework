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
const std::string SANDBOX_PREFIX = "/data/storage/el2/base/files/";
const char RINGTONE_PARAMETER_SCANNER_USERID_KEY[] = "ringtone.scanner.userId";
const int32_t RINGTONEPARA_SIZE = 64;

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
    MEDIA_LOGI("Enter CreateDataShareHelperUri()");
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

    int32_t useId = SystemSoundManagerUtils::GetCurrentUserId();
    std::string uri = RINGTONE_LIBRARY_PROXY_URI + "?" + "user=" + std::to_string(useId);
    std::pair<int, std::shared_ptr<DataShare::DataShareHelper>> dataShare =
        DataShare::DataShareHelper::Create(remoteObj, uri, "");
    MEDIA_LOGI("CreateDataShareHelperUri with : %{public}s. errcode : %{public}d", uri.c_str(), dataShare.first);
    return dataShare.second;
}

shared_ptr<DataShare::DataShareHelper> SystemSoundManagerUtils::CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_LOGI("Enter CreateDataShareHelper()");
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

bool SystemSoundManagerUtils::VerifyCustomPath(const std::string &audioUri)
{
    bool flag = false;
    if (audioUri.substr(0, SANDBOX_PREFIX.size()) == SANDBOX_PREFIX) {
        flag = true;
    }
    return flag;
}

bool SystemSoundManagerUtils::IdExists(const std::string &ids, int32_t id)
{
    MEDIA_LOGI("IdExists Start.");
    if (ids.empty()) {
        return false;
    }

    size_t pos = 0;
    std::string idStr = std::to_string(id);

    while ((pos = ids.find(idStr, pos)) != std::string::npos) {
        bool startPos = (pos == 0) || (ids[pos - 1] == ' ');
        bool endPos = (pos + idStr.length() == ids.length()) || (ids[pos + idStr.length()] == ' ');
        if (startPos && endPos) {
            return true;
        }
        pos += idStr.length();
    }
    MEDIA_LOGI("IdExists End.");
    return false;
}

bool SystemSoundManagerUtils::CheckCurrentUser()
{
    MEDIA_LOGI("CheckCurrentUser Start.");
    char paramValue[RINGTONEPARA_SIZE] = {0};
    GetParameter(RINGTONE_PARAMETER_SCANNER_USERID_KEY, "", paramValue, RINGTONEPARA_SIZE);
    std::string ids(paramValue);
    MEDIA_LOGI("GetParameter end, paramValue: %{private}s .", ids.c_str());
    int32_t currentUserId = GetCurrentUserId();
    if (IdExists(ids, currentUserId)) {
        return true;
    }
    if (!ids.empty() && ids.back() != ' ') {
        ids += " ";
    }
    ids += std::to_string(currentUserId);
    int result = SetParameter(RINGTONE_PARAMETER_SCANNER_USERID_KEY, ids.c_str());
    MEDIA_LOGI("CheckCurrentUser End. SetParameter result: %{public}d ,CurrentUserIds: %{private}s .",
        result, ids.c_str());
    return false;
}
} // namesapce Media
} // namespace OHOS