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

#include "playerdatasrc_fuzzer.h"
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
#include "media_data_source_stub.h"
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
int32_t g_duration = 0;

PlayerDataSrcFuzzer::PlayerDataSrcFuzzer(int32_t fd, size_t size) : fd_(fd), size_(size) {}

PlayerDataSrcFuzzer::~PlayerDataSrcFuzzer() {}

int32_t PlayerDataSrcFuzzer::ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    if (mem == nullptr) {
        return 0;
    }
    if (pos + static_cast<int64_t>(length) >= static_cast<int64_t>(size_)) {
        return -1;
    }
    if (pos > 0) {
        lseek(fd_, pos, SEEK_SET);
    }
    int32_t ans = read(fd_, mem->GetBase(), length);
    return ans;
}

int32_t PlayerDataSrcFuzzer::ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
{
    if (mem == nullptr) {
        return 0;
    }
    if (static_cast<int64_t>(length) >= static_cast<int64_t>(size_)) {
        return -1;
    }
    int ans = read(fd_, mem->GetBase(), length);
    return ans;
}

int32_t PlayerDataSrcFuzzer::ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1)
{
    int ans = ReadAt(pos, length, mem);
    return ans;
}

int32_t PlayerDataSrcFuzzer::GetSize(int64_t &size)
{
    size = static_cast<int32_t>(size_);
    return 0;
}

void PlayerDataSrcFuzzer::SetDataSrcSource(sptr<IRemoteStub<IStandardPlayerService>> &playerStub)
{
    int32_t fileDes = open(DATA_PATH, O_RDONLY);
    if (fileDes < 0) {
        return;
    }
    struct stat64 st;
    fstat(fileDes, &st);
    const std::shared_ptr<IMediaDataSource> src = std::make_shared<PlayerDataSrcFuzzer>(fileDes, st.st_size);
    sptr<MediaDataSourceStub> dataSrcStub_ = new(std::nothrow) MediaDataSourceStub(src);
    sptr<IRemoteObject> object = dataSrcStub_->AsObject();
    playerStub->SetSource(object);
    return;
}

sptr<IRemoteStub<IStandardPlayerService>> PlayerDataSrcFuzzer::GetPlayStub()
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

void PlayerDataSrcFuzzer::SelectTrack(sptr<IRemoteStub<IStandardPlayerService>> &playerStub)
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

bool PlayerDataSrcFuzzer::RunFuzz(uint8_t *data, size_t size)
{
    int32_t fd = open(DATA_PATH, O_RDONLY);
    sptr<IRemoteStub<IStandardPlayerService>> playerStub = GetPlayStub();
    if (playerStub == nullptr) {
        return false;
    }
    SetDataSrcSource(playerStub);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetRenderFirstFrame(false);
    sleep(PLAY_TIME_1_SEC);
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
    playerStub->GetDuration(g_duration);
    if (g_duration == 0) {
        playerStub->Release();
        sleep(PLAY_TIME_1_SEC);
        return false;
    }
    playerStub->SetPlayRange(0, g_duration);
    sleep(PLAY_TIME_1_SEC);
    playerStub->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true);
    sleep(PLAY_TIME_1_SEC);
    SelectTrack(playerStub);
    FuzzedDataProvider fdp(data, size);
    int seekTime = abs(fdp.ConsumeIntegral<int32_t>())%g_duration;
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
    PlayerDataSrcFuzzer player(0, 0);
    player.RunFuzz(data, size);
    unlink(DATA_PATH);
    return 0;
}

