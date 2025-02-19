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

#include "media_errors.h"
#include "media_log.h"
#include "soundpool_manager_multi.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPoolManagerMulti"};
    static const int32_t SOUNDPOOL_INSTANCE_MAX_NUM = 128;
}

namespace OHOS {
namespace Media {
SoundPoolManagerMulti::~SoundPoolManagerMulti()
{
    MEDIA_LOGI("Destruction SoundPoolManagerMulti");
    std::lock_guard<std::mutex> lock(mutex_);
    soundPools_.clear();
};

SoundPoolManagerMulti& SoundPoolManagerMulti::GetInstance()
{
    static SoundPoolManagerMulti instance;
    return instance;
}

int32_t SoundPoolManagerMulti::GetSoundPoolInstance(std::shared_ptr<SoundPool>& soundPool)
{
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t instanceNum = soundPools_.size();
    if (instanceNum >= SOUNDPOOL_INSTANCE_MAX_NUM) {
        MEDIA_LOGI("create soundpool fail, instanceNum:%{public}u", instanceNum);
        return MSERR_INVALID_OPERATION;
    } else {
        soundPool = std::make_shared<SoundPool>();
        soundPools_.push_back(soundPool);
        MEDIA_LOGI("create soundpool success, instanceNum:%{public}zu", soundPools_.size());
    }

    return MSERR_OK;
}

int32_t SoundPoolManagerMulti::ReleaseInstance(std::shared_ptr<SoundPool> soundPool)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = soundPools_.begin(); it != soundPools_.end();) {
        if (*it == soundPool) {
            it = soundPools_.erase(it);
            break;
        } else {
            ++it;
        }
    }
    MEDIA_LOGI("release soundpool after, instanceNum:%{public}zu", soundPools_.size());
    return MSERR_OK;
}

} // namespace Media
} // namespace OHOS
