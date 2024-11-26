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

#ifndef PLAYERAPI_FUZZER_H
#define PLAYERAPI_FUZZER_H

#include <iostream>
#define FUZZ_PROJECT_NAME "playerapi_fuzzer"
#include <iostream>
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "stub_common.h"
#include "i_standard_player_service.h"
#include <fcntl.h>
#include "i_standard_player_listener.h"
#include "player.h"

namespace OHOS {
namespace Media {
class PlayerApiFuzzer {
public:
    PlayerApiFuzzer();
    ~PlayerApiFuzzer();
    bool RunFuzz(uint8_t *data, size_t size);
    sptr<IRemoteStub<IStandardPlayerService>> GetPlayStub();
    void SelectTrack(const sptr<IRemoteStub<IStandardPlayerService>> &player);
};
} // namespace MEDIA
} // namespace OHOS
#endif

