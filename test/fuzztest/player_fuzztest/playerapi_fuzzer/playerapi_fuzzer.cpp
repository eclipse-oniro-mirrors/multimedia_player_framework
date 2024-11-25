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

#include "playerapi_fuzzer.h"
#include <iostream>
#include <unistd.h>
#include "stub_common.h"
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_player_service.h"
#include <fcntl.h>
#include "i_standard_player_listener.h"
#include "player.h"
#include "meta/media_types.h"
#include "common/media_core.h"
#include "fuzzer/FuzzedDataProvider.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
const char *DATA_PATH = "/data/test/fuzz_create.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
const int32_t PLAY_TIME_1_SEC = 1;

PlayerApiFuzzer::PlayerApiFuzzer()
{
}

PlayerApiFuzzer::~PlayerApiFuzzer()
{
}

void PlayerApiFuzzer::SelectTrack(const sptr<IRemoteStub<IStandardPlayerService>> &playerStub)
{
    std::vector<Format> audioTrack;
    std::vector<int32_t> audioTrackIds;
    int32_t currentAudioTrackIndex = -1;
    playerStub->GetAudioTrackInfo(audioTrack);
    playerStub->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex);
    for (Format audioTrackFormat: audioTrack) {
        int32_t trackIndex = -1;
        audioTrackFormat.GetIntValue("track_index", trackIndex);
        audioTrackIds.push_back(trackIndex);
    }
    for (int32_t trackIndex: audioTrackIds) {
        if (trackIndex != currentAudioTrackIndex) {
            playerStub->SelectTrack(trackIndex, PlayerSwitchMode::SWITCH_SMOOTH);
            playerStub->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex);
            sleep(PLAY_TIME_1_SEC);
            playerStub->DeselectTrack(currentAudioTrackIndex);
            playerStub->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex);
            sleep(PLAY_TIME_1_SEC);
        }
    }
    return;
}

sptr<IRemoteStub<IStandardPlayerService>> PlayerApiFuzzer::GetPlayStub()
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> player = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER, listener);
    if (player == nullptr) {
        return nullptr;
    }
    sptr<IRemoteStub<IStandardPlayerService>> playerStub = iface_cast<IRemoteStub<IStandardPlayerService>>(player);
    return playerStub;
}

bool PlayerApiFuzzer::RunFuzz(uint8_t *data, size_t size)
{
    int32_t fd = open(DATA_PATH, O_RDONLY);
    sptr<IRemoteStub<IStandardPlayerService>> playerStub = GetPlayStub();
    if (playerStub == nullptr) {
        return false;
    }
    playerStub->SetSource(fd, 0, size);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetRenderFirstFrame(false);
    AVPlayStrategy playbackStrategy = {.mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_AUD};
    playerStub->SetPlaybackStrategy(playbackStrategy);
    sleep(PLAY_TIME_1_SEC);
    playerStub->Prepare();
    sleep(PLAY_TIME_1_SEC);
    playerStub->SelectBitRate(0);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetVolume(1, 1);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetPlaybackSpeed(SPEED_FORWARD_0_50_X);
    sleep(PLAY_TIME_1_SEC);
    int32_t duration = 0;
    playerStub->GetDuration(duration);
    if (duration == 0) {
        playerStub->Release();
        sleep(PLAY_TIME_1_SEC);
        return false;
    }
    playerStub->SetPlayRange(0, duration);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true);
    sleep(PLAY_TIME_1_SEC);
    SelectTrack(playerStub);
    FuzzedDataProvider fdp(data, size);
    int seekTime = abs(fdp.ConsumeIntegral<int32_t>())%duration;
    playerStub->Seek(seekTime, SEEK_NEXT_SYNC);
    sleep(PLAY_TIME_1_SEC);
    playerStub->Play();
    sleep(PLAY_TIME_1_SEC);
    playerStub->Pause();
    sleep(PLAY_TIME_1_SEC);
    playerStub->Play();
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetLooping(true);
    sleep(PLAY_TIME_1_SEC);
    playerStub->Stop();
    sleep(PLAY_TIME_1_SEC);
    playerStub->Release();
    sleep(PLAY_TIME_1_SEC);
    close(fd);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < sizeof(int64_t)) {
        return false;
    }
    int32_t fd = open(DATA_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    int len = write(fd, data, size);
    if (len <= 0) {
        close(fd);
        return false;
    }
    close(fd);
    PlayerApiFuzzer player;
    player.RunFuzz(data, size);
    unlink(DATA_PATH);
    return 0;
}

