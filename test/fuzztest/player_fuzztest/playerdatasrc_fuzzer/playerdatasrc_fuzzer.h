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

#ifndef PLAYERDATASRC_FUZZER_H
#define PLAYERDATASRC_FUZZER_H

#include <iostream>
#define FUZZ_PROJECT_NAME "playerdatasrc_fuzzer"
#include <filesystem>
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "stub_common.h"
#include "i_standard_player_service.h"
#include <fcntl.h>
#include "i_standard_player_listener.h"
#include "player.h"
#include <sys/stat.h>
#include "media_data_source_stub.h"


namespace OHOS {
namespace Media {
class PlayerDataSrcFuzzer : public IMediaDataSource {
public:
    PlayerDataSrcFuzzer(int32_t fd, size_t size);
    ~PlayerDataSrcFuzzer();
    bool RunFuzz(uint8_t *data, size_t size);
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos) override;
    int32_t GetSize(int64_t &size) override;
    sptr<IRemoteStub<IStandardPlayerService>> GetPlayStub();
    void SetDataSrcSource(sptr<IRemoteStub<IStandardPlayerService>> &player);
    void SelectTrack(sptr<IRemoteStub<IStandardPlayerService>> &player);

private:
    int32_t fd_{ 0 };
    size_t size_{ 0 };
};
} // namespace MEDIA
} // namespace OHOS
#endif

