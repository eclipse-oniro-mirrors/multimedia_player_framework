/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef SOUNDPOOL_MANAGER_MULTI_H
#define SOUNDPOOL_MANAGER_MULTI_H

#include <unistd.h>
#include <vector>
#include "media_log.h"
#include "soundpool.h"

namespace OHOS {
namespace Media {
class SoundPool;

class SoundPoolManagerMulti {
public:
    SoundPoolManagerMulti(const SoundPoolManagerMulti&) = delete;
    SoundPoolManagerMulti& operator = (const SoundPoolManagerMulti&) = delete;
    ~SoundPoolManagerMulti();

    static SoundPoolManagerMulti& GetInstance();
    int32_t GetSoundPoolInstance(std::shared_ptr<SoundPool>& soundPool);
    int32_t ReleaseInstance(std::shared_ptr<SoundPool> soundPool);

private:
    SoundPoolManagerMulti() {}
    std::mutex mutex_;
    std::vector<std::shared_ptr<SoundPool>> soundPools_;
};
} // namespace Media
} // namespace OHOS
#endif // SOUNDPOOL_MANAGER_MULTI_H
