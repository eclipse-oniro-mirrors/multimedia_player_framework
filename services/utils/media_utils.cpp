/*
* Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include <cmath>
#include <media_errors.h>
#include <sstream>
#include <unordered_map>
#include "common/log.h"
#include "media_utils.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#include <unordered_set>
#include "media_log.h"
#include "parameter.h"
#include "os_account_manager.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "MediaUtils" };
}

namespace OHOS {
namespace Media {
namespace {
const std::pair<Status, int> g_statusPair[] = {
    {Status::OK, MSERR_OK},
    {Status::ERROR_UNKNOWN, MSERR_UNKNOWN},
    {Status::ERROR_AGAIN, MSERR_UNKNOWN},
    {Status::ERROR_UNIMPLEMENTED, MSERR_UNSUPPORT},
    {Status::ERROR_INVALID_PARAMETER, MSERR_INVALID_VAL},
    {Status::ERROR_INVALID_OPERATION, MSERR_INVALID_OPERATION},
    {Status::ERROR_UNSUPPORTED_FORMAT, MSERR_UNSUPPORT_CONTAINER_TYPE},
    {Status::ERROR_NOT_EXISTED, MSERR_OPEN_FILE_FAILED},
    {Status::ERROR_TIMED_OUT, MSERR_UNKNOWN},
    {Status::ERROR_NO_MEMORY, MSERR_UNKNOWN},
    {Status::ERROR_INVALID_STATE, MSERR_INVALID_STATE},
    {Status::ERROR_FILE_NOT_FOUND, MSERR_IO_FILE_NOT_FOUND},
    {Status::ERROR_FILE_BAD_HANDLE, MSERR_IO_FILE_BAD_HANDLE},
    {Status::ERROR_FILE_PERMISSION_DENIED, MSERR_IO_FILE_PERMISSION_DENIED},
    {Status::ERROR_FILE_INVALID_DATA, MSERR_IO_DATA_ABNORMAL},
    {Status::ERROR_FILE_ILLEGAL_OPERATION, MSERR_IO_FILE_ACCESS_DENIED},
    {Status::ERROR_AUDIO_DEC_INIT_FAILED, MSERR_IO_AUDIO_DEC_INIT_FAILED},
    {Status::ERROR_AUDIO_DEC_UNAVAILABLE, MSERR_IO_AUDIO_DEC_UNAVAILABLE},
    {Status::ERROR_VIDEO_DEC_INIT_FAILED, MSERR_IO_VIDEO_DEC_INIT_FAILED},
    {Status::ERROR_VIDEO_DEC_UNAVAILABLE, MSERR_IO_VIDEO_DEC_UNAVAILABLE},
    {Status::ERROR_AUDIO_ENC_INIT_FAILED, MSERR_IO_AUDIO_ENC_INIT_FAILED},
    {Status::ERROR_AUDIO_ENC_UNAVAILABLE, MSERR_IO_AUDIO_ENC_UNAVAILABLE},
    {Status::ERROR_VIDEO_ENC_INIT_FAILED, MSERR_IO_VIDEO_ENC_INIT_FAILED},
    {Status::ERROR_VIDEO_ENC_UNAVAILABLE, MSERR_IO_VIDEO_ENC_UNAVAILABLE},
};
const std::array<std::pair<PlaybackRateMode, float>, 10> PLAY_RATE_REFS = {
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_0_75_X, 0.75),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_00_X, 1.0),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_25_X, 1.25),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_75_X, 1.75),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_2_00_X, 2.00),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_0_50_X, 0.50),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_50_X, 1.50),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_3_00_X, 3.00),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_0_25_X, 0.25),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_0_125_X, 0.125),
};

static int g_readSysParaIdx = 0;
std::mutex readSysParaMapMtx_;
static std::unordered_map<std::string, std::string> g_readSysParaMap;
static int32_t FAULT_API_VERSION = -1;
static int32_t ROUND_VERSION_NUMBER = 100;
}  // namespace

std::string __attribute__((visibility("default"))) GetClientBundleName(int32_t uid, bool shouldLog)
{
    if (uid == 1003) { // 1003 is bootanimation uid
        return "bootanimation";
    }
    std::string bundleName = "";
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_LOG_E("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_LOG_E("object is NULL.");
        return bundleName;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_LOG_E("bundle manager service is NULL.");
        return bundleName;
    }

    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK) {
        MEDIA_LOG_E("Error GetBundleNameForUid fail");
        return "";
    }
    MEDIA_LOG_I("bundle name is %{public}s ", bundleName.c_str());

    return bundleName;
}

int32_t __attribute__((visibility("default"))) GetApiInfo(int32_t uid)
{
    if (uid == 1003) { // 1003 is bootanimation uid
        return FAULT_API_VERSION;
    }
    std::string bundleName = "";
    int32_t userId = 0;
    AppExecFwk::ApplicationInfo appInfo;
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_LOG_E("Get ability manager failed");
        return FAULT_API_VERSION;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_LOG_E("object is NULL.");
        return FAULT_API_VERSION;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_LOG_E("bundle manager service is NULL.");
        return FAULT_API_VERSION;
    }

    auto result = bms->GetNameForUid(uid, bundleName);
    if (result != ERR_OK) {
        MEDIA_LOG_E("Error GetBundleNameForUid fail");
        return FAULT_API_VERSION;
    }

    AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(uid, userId);
    auto flags = static_cast<int32_t>(AppExecFwk::GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    auto applicationResult = bms->GetApplicationInfo(bundleName, flags, userId, appInfo);
    if (applicationResult != true) {
        MEDIA_LOG_E("Error GetApplicationInfo fail");
        return FAULT_API_VERSION;
    }

    auto apiVersion = appInfo.apiTargetVersion;
    auto apiVersionResult = apiVersion % ROUND_VERSION_NUMBER;
    return apiVersionResult;
}

std::string __attribute__((visibility("default"))) GetBundleResourceLabel(std::string bundleName)
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        MEDIA_LOG_E("Get ability manager failed");
        return bundleName;
    }

    sptr<IRemoteObject> object = samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (object == nullptr) {
        MEDIA_LOG_E("object is NULL.");
        return bundleName;
    }

    sptr<OHOS::AppExecFwk::IBundleMgr> bms = iface_cast<OHOS::AppExecFwk::IBundleMgr>(object);
    if (bms == nullptr) {
        MEDIA_LOG_E("bundle manager service is NULL.");
        return bundleName;
    }

    auto bundleResourceProxy = bms->GetBundleResourceProxy();
    if (bundleResourceProxy == nullptr) {
        MEDIA_LOG_E("GetBundleResourceProxy fail");
        return bundleName;
    }
    AppExecFwk::BundleResourceInfo resourceInfo;
    auto result = bundleResourceProxy->GetBundleResourceInfo(bundleName,
        static_cast<uint32_t>(OHOS::AppExecFwk::ResourceFlag::GET_RESOURCE_INFO_ALL), resourceInfo);
    if (result != ERR_OK) {
        MEDIA_LOG_E("GetBundleResourceInfo failed");
        return bundleName;
    }
    MEDIA_LOG_I("bundle resource label is %{public}s ", (resourceInfo.label).c_str());
    return resourceInfo.label;
}


int __attribute__((visibility("default"))) TransStatus(Status status)
{
    for (const auto& errPair : g_statusPair) {
        if (errPair.first == status) {
            return errPair.second;
        }
    }
    return MSERR_UNKNOWN;
}

PlayerStates __attribute__((visibility("default"))) TransStateId2PlayerState(PlayerStateId state)
{
    PlayerStates playerState = PLAYER_STATE_ERROR;
    switch (state) {
        case PlayerStateId::IDLE:
            playerState = PLAYER_IDLE;
            break;
        case PlayerStateId::INIT:
            playerState = PLAYER_INITIALIZED;
            break;
        case PlayerStateId::PREPARING:
            playerState = PLAYER_PREPARING;
            break;
        case PlayerStateId::READY:
            playerState = PLAYER_PREPARED;
            break;
        case PlayerStateId::PAUSE:
            playerState = PLAYER_PAUSED;
            break;
        case PlayerStateId::PLAYING:
            playerState = PLAYER_STARTED;
            break;
        case PlayerStateId::STOPPED:
            playerState = PLAYER_STOPPED;
            break;
        case PlayerStateId::EOS:
            playerState = PLAYER_PLAYBACK_COMPLETE;
            break;
        default:
            break;
    }
    return playerState;
}

Plugins::SeekMode __attribute__((visibility("default"))) Transform2SeekMode(PlayerSeekMode mode)
{
    switch (mode) {
        case PlayerSeekMode::SEEK_NEXT_SYNC:
            return Plugins::SeekMode::SEEK_NEXT_SYNC;
        case PlayerSeekMode::SEEK_PREVIOUS_SYNC:
            return Plugins::SeekMode::SEEK_PREVIOUS_SYNC;
        case PlayerSeekMode::SEEK_CLOSEST_SYNC:
            return Plugins::SeekMode::SEEK_CLOSEST_SYNC;
        case PlayerSeekMode::SEEK_CLOSEST:
        default:
            return Plugins::SeekMode::SEEK_CLOSEST;
    }
}
const std::string& __attribute__((visibility("default"))) StringnessPlayerState(PlayerStates state)
{
    using StateString = std::pair<PlayerStates, std::string>;
    const static std::array<StateString, 9> maps = { // array size
        std::make_pair(PlayerStates::PLAYER_STATE_ERROR, "state error"),
        std::make_pair(PlayerStates::PLAYER_IDLE, "idle"),
        std::make_pair(PlayerStates::PLAYER_INITIALIZED, "init"),
        std::make_pair(PlayerStates::PLAYER_PREPARING, "preparing"),
        std::make_pair(PlayerStates::PLAYER_PREPARED, "prepared"),
        std::make_pair(PlayerStates::PLAYER_STARTED, "started"),
        std::make_pair(PlayerStates::PLAYER_PAUSED, "paused"),
        std::make_pair(PlayerStates::PLAYER_STOPPED, "stopped"),
        std::make_pair(PlayerStates::PLAYER_PLAYBACK_COMPLETE, "completed"),
    };
    const static std::string UNKNOWN = "unknown";
    auto ite = std::find_if(maps.begin(), maps.end(), [&] (const StateString& item) -> bool {
        return item.first == state;
    });
    if (ite == maps.end()) {
        return UNKNOWN;
    }
    return ite->second;
}
float __attribute__((visibility("default"))) TransformPlayRate2Float(PlaybackRateMode rateMode)
{
    auto ite = std::find_if(PLAY_RATE_REFS.begin(), PLAY_RATE_REFS.end(), [&](const auto& pair) ->bool {
        return pair.first == rateMode;
    });
    if (ite == PLAY_RATE_REFS.end()) {
        return 1.0f;
    }
    return ite->second;
}
PlaybackRateMode __attribute__((visibility("default"))) TransformFloat2PlayRate(float rate)
{
    auto ite = std::find_if(PLAY_RATE_REFS.begin(), PLAY_RATE_REFS.end(), [&](const auto& pair) ->bool {
        return std::fabs(rate - pair.second) < 1e-3;
    });
    if (ite == PLAY_RATE_REFS.end()) {
        return PlaybackRateMode::SPEED_FORWARD_1_00_X;
    }
    return ite->first;
}

bool __attribute__((visibility("default"))) IsEnableOptimizeDecode()
{
    char useOptimizeDecode[10] = {0}; // 10: system param usage
    auto res = GetParameter("debug.media_service.optimize_decode", "1", useOptimizeDecode, sizeof(useOptimizeDecode));
    return res == 1 && useOptimizeDecode[0] == '1';
}

bool __attribute__((visibility("default"))) IsAppEnableRenderFirstFrame(int32_t uid)
{
    return uid != 1003; // 1003 is bootanimation uid
}

bool __attribute__((visibility("default"))) GetPackageName(const char *key, std::string &value)
{
    CHECK_AND_RETURN_RET_LOG(key != nullptr, false, "key is nullptr");
    value = "";
    char paraValue[100] = {0};   // 100 for system parameter
    auto res = GetParameter(key, "-1", paraValue, sizeof(paraValue));
    CHECK_AND_RETURN_RET_LOG(res >= 0, false, "GetSysPara fail, key:%{public}s res:%{public}d", key, res);
    std::stringstream valueStr;
    valueStr << paraValue;
    valueStr >> value;
    MEDIA_LOG_I("Config parameter %{public}s : %{public}s", key, value.c_str());
    return true;
}

std::unordered_map<std::string, std::string>& __attribute__((visibility("default"))) GetScreenCaptureSystemParam()
{
    std::lock_guard<std::mutex> lock(readSysParaMapMtx_);
    if (g_readSysParaIdx == 0) {
        GetPackageName("const.multimedia.screencapture.dialogconnectionbundlename",
            g_readSysParaMap["const.multimedia.screencapture.dialogconnectionbundlename"]);
        GetPackageName("const.multimedia.screencapture.dialogconnectionabilityname",
            g_readSysParaMap["const.multimedia.screencapture.dialogconnectionabilityname"]);
        GetPackageName("const.multimedia.screencapture.screenrecorderbundlename",
            g_readSysParaMap["const.multimedia.screencapture.screenrecorderbundlename"]);
        GetPackageName("const.multimedia.screencapture.screenrecorderabilityname",
            g_readSysParaMap["const.multimedia.screencapture.screenrecorderabilityname"]);
        GetPackageName("const.multimedia.screencapture.hiviewcarebundlename",
            g_readSysParaMap["const.multimedia.screencapture.hiviewcarebundlename"]);
        g_readSysParaIdx++;
    }
    return g_readSysParaMap;
}
}  // namespace Media
}  // namespace OHOS
