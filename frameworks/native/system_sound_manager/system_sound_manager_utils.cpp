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
#include "system_sound_manager.h"
#include "system_tone_player_impl.h"
#include "parameter.h"
#include "hitrace_meter.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "directory_ex.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"
#include "token_setproc.h"

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
const char RINGTONE_PARAMETER_SCANNER_FIRST_KEY[] = "ringtone.scanner.first";
const char RINGTONE_PARAMETER_SCANNER_FIRST_FALSE[] = "false";
const char RINGTONE_PARAMETER_SCANNER_FIRST_TRUE[] = "true";
const int32_t RINGTONEPARA_SIZE = 64;
const int32_t INVALID_DATASHARE = -2;
const int32_t OPEN_FAILED = -3;
const int32_t QUERY_FAILED = -4;

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

void SystemSoundManagerUtils::CreateDataShareHelper(int32_t systemAbilityId, bool &isProxy,
    shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    Security::AccessToken::AccessTokenID tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t result =  Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenCaller,
        "ohos.permission.ACCESS_CUSTOM_RINGTONE");
    isProxy = (result == Security::AccessToken::PermissionState::PERMISSION_GRANTED &&
        GetScannerFirstParameter(RINGTONE_PARAMETER_SCANNER_FIRST_KEY, RINGTONEPARA_SIZE) &&
        CheckCurrentUser()) ? true : false;
    dataShareHelper = isProxy ? CreateDataShareHelperUri(systemAbilityId) : CreateDataShareHelper(systemAbilityId);
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
    char paramValue[RINGTONEPARA_SIZE] = {0};
    GetParameter(RINGTONE_PARAMETER_SCANNER_USERID_KEY, "", paramValue, RINGTONEPARA_SIZE);
    std::string ids(paramValue);
    int32_t currentUserId = GetCurrentUserId();
    if (IdExists(ids, currentUserId)) {
        return true;
    }
    if (!ids.empty() && ids.back() != ' ') {
        ids += " ";
    }
    ids += std::to_string(currentUserId);
    MEDIA_LOGI("CheckCurrentUser End. SetParameter CurrentUserIds: %{private}s .", ids.c_str());
    return false;
}

bool SystemSoundManagerUtils::GetScannerFirstParameter(const char* key, int32_t maxSize)
{
    char paramValue[RINGTONEPARA_SIZE] = {0};
    maxSize = RINGTONEPARA_SIZE;
    GetParameter(key, "", paramValue, maxSize);
    std::string parameter(paramValue);
    MEDIA_LOGI("GetParameter end paramValue:%{public}s .", parameter.c_str());
    if (strcmp(paramValue, RINGTONE_PARAMETER_SCANNER_FIRST_TRUE) == 0) {
        return true;
    }
    if (strcmp(paramValue, RINGTONE_PARAMETER_SCANNER_FIRST_FALSE) == 0) {
        return false;
    }
    return false;
}

int32_t SystemSoundManagerUtils::GetTypeForSystemSoundUri(const std::string &audioUri)
{
    if (audioUri == NO_SYSTEM_SOUND || audioUri == NO_RING_SOUND) {
        return SystemToneUriType::NO_RINGTONES;
    }

    size_t pos = audioUri.find("sys_prod");
    if (pos == 0 || pos == 1) {
        // The audioUri of a preset ringtone starts with "sys prod” or "/sys prod".
        return SystemToneUriType::PRESET_RINGTONES;
    }
    pos = audioUri.find("data");
    if (pos == 0 || pos == 1) {
        // The audioUri of a custom ringtone starts with "data" or "/data".
        return SystemToneUriType::CUSTOM_RINGTONES;
    }
    return UNKNOW_RINGTONES;
}

std::string SystemSoundManagerUtils::GetErrorReason(const int32_t &errorCode)
{
    std::string errorReason = "";
    if (errorCode == MSERR_OK) {
        errorReason = "system tone playback successfully";
    } else {
        errorReason = "system tone playback failed";
    }
    return errorReason;
}

std::string SystemSoundManagerUtils::GetTonePlaybackErrorReason(const int32_t &errorCode)
{
    std::string errorReason = "";
    if (errorCode == INVALID_DATASHARE) {
        errorReason = "Failed to CreateDataShareHelper!";
    } else if (errorCode == OPEN_FAILED) {
        errorReason = "Open audio uri failed!";
    } else if (errorCode == QUERY_FAILED) {
        errorReason = "query failed, ringtone library error!";
    } else {
        errorReason = "Invalid error";
    }
    return errorReason;
}

MediaTrace::MediaTrace(const std::string &funcName)
{
    StartTrace(HITRACE_TAG_ZMEDIA, funcName);
    isSync_ = true;
}

void MediaTrace::TraceBegin(const std::string &funcName, int32_t taskId)
{
    StartAsyncTrace(HITRACE_TAG_ZMEDIA, funcName, taskId);
}

void MediaTrace::TraceEnd(const std::string &funcName, int32_t taskId)
{
    FinishAsyncTrace(HITRACE_TAG_ZMEDIA, funcName, taskId);
}

void MediaTrace::CounterTrace(const std::string &varName, int32_t val)
{
    CountTrace(HITRACE_TAG_ZMEDIA, varName, val);
}

MediaTrace::~MediaTrace()
{
    if (isSync_) {
        FinishTrace(HITRACE_TAG_ZMEDIA);
    }
}
} // namesapce Media
} // namespace OHOS