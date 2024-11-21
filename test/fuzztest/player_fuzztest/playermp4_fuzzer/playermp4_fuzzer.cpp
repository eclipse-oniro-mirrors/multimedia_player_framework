/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "playermp4_fuzzer.h"
#include <iostream>
#include <unistd.h>
#include "stub_common.h"
#include "media_server.h"
#include "media_parcel.h"
#include "i_standard_player_service.h"
#include <fcntl.h>
#include "i_standard_player_listener.h"
#include "player.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

namespace OHOS {
namespace Media {
const char *DATA_PATH = "/data/test/fuzz_create.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;

PlayerMp4Fuzzer::PlayerMp4Fuzzer()
{
}

PlayerMp4Fuzzer::~PlayerMp4Fuzzer()
{
}

bool PlayerMp4Fuzzer::RunFuzz(uint8_t *data, size_t size)
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

    fd = open(DATA_PATH, O_RDONLY);

    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> player = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_PLAYER, listener);
    if (player == nullptr) {
        return false;
    }
    sptr<IRemoteStub<IStandardPlayerService>> playerStub = iface_cast<IRemoteStub<IStandardPlayerService>>(player);
    if (playerStub == nullptr) {
        return false;
    }
    playerStub->SetSource(fd, 0, size);
    sleep(1);
    playerStub->Prepare();
    sleep(1);
    playerStub->Play();
    sleep(1);
    playerStub->Pause();
    sleep(1);
    playerStub->Release();
    close(fd);
    unlink(DATA_PATH);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    PlayerMp4Fuzzer player;
    player.RunFuzz(data, size);
    return 0;
}

