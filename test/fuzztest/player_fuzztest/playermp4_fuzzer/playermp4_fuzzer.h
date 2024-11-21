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

#ifndef PLAYERMP4_FUZZER_H
#define PLAYERMP4_FUZZER_H

#include <iostream>
#define FUZZ_PROJECT_NAME "playermp4_fuzzer"
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
class PlayerMp4Fuzzer {
public:
    PlayerMp4Fuzzer();
    ~PlayerMp4Fuzzer();
    bool RunFuzz(uint8_t *data, size_t size);
};
} // namespace MEDIA
} // namespace OHOS
#endif

