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
#include "common/log.h"
#include "media_utils.h"

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
    {Status::ERROR_TIMED_OUT, MSERR_EXT_TIMEOUT},
    {Status::ERROR_NO_MEMORY, MSERR_EXT_NO_MEMORY},
    {Status::ERROR_INVALID_STATE, MSERR_INVALID_STATE},
};
const std::array<std::pair<PlaybackRateMode, float>, 5> PLAY_RATE_REFS = {
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_0_75_X, 0.75),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_00_X, 1.0),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_25_X, 1.25),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_1_75_X, 1.75),
    std::make_pair(PlaybackRateMode::SPEED_FORWARD_2_00_X, 2.00),
};
}  // namespace

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

double __attribute__((visibility("default"))) TransformPlayRateToSpeed(const PlaybackRateMode& mode)
{
    switch (mode) {
        case SPEED_FORWARD_0_75_X:
            return SPEED_0_75_X;
        case SPEED_FORWARD_1_00_X:
            return SPEED_1_00_X;
        case SPEED_FORWARD_1_25_X:
            return SPEED_1_25_X;
        case SPEED_FORWARD_1_75_X:
            return SPEED_1_75_X;
        case SPEED_FORWARD_2_00_X:
            return SPEED_2_00_X;
        default:
            MEDIA_LOG_I("unknown mode: " PUBLIC_LOG_D32, mode);
    }
    return SPEED_1_00_X;
}
}  // namespace Media
}  // namespace OHOS