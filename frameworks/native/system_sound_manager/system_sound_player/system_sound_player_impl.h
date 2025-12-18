/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef SYSTEM_SOUND_PLAYER_IMPL_H
#define SYSTEM_SOUND_PLAYER_IMPL_H

#include "system_sound_player.h"

#include <map>

#include "isoundpool.h"

namespace OHOS {
namespace Media {
class PlayerSoundPoolCallback;

class SystemSoundPlayerImpl : public SystemSoundPlayer,
    public std::enable_shared_from_this<SystemSoundPlayerImpl> {
public:
    SystemSoundPlayerImpl();
    ~SystemSoundPlayerImpl();

    // SystemSoundPlayer override
    int32_t Load(SystemSoundType systemSoundType) override;
    int32_t Play(SystemSoundType systemSoundType) override;
    int32_t Unload(SystemSoundType systemSoundType) override;
    int32_t Release() override;

    void OnLoadCompleted(int32_t soundId);
    void OnPlayFinished(int32_t streamID);
    void OnError(int32_t errorCode);

private:
    bool IsSystemSoundTypeValid(SystemSoundType systemSoundType);
    bool InitSoundPoolPlayer();
    int32_t ReleaseInternal();
    int32_t OpenSystemSoundFile(const std::string &filePath);
    int32_t LoadInternal(SystemSoundType systemSoundType);

    std::mutex systemSoundPlayerMutex_;
    std::map<SystemSoundType, int32_t> soundIds_;
    std::map<SystemSoundType, int32_t> soundFds_;
    std::shared_ptr<ISoundPool> soundPool_ = nullptr;
    std::shared_ptr<PlayerSoundPoolCallback> soundPoolCallback_ = nullptr;
    std::mutex loadMutex_;
    std::condition_variable loadCond_;
    std::atomic<bool> isLoadCompleted_ = false;
    std::atomic<bool> isReleased_ = false;
};

class PlayerSoundPoolCallback : public ISoundPoolCallback {
public:
    explicit PlayerSoundPoolCallback(std::shared_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl);
    virtual ~PlayerSoundPoolCallback() = default;

    // ISoundPoolCallback override
    void OnLoadCompleted(int32_t soundId) override;
    void OnPlayFinished(int32_t streamID) override;
    void OnError(int32_t errorCode) override;

private:
    std::weak_ptr<SystemSoundPlayerImpl> systemSoundPlayerImpl_;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_SOUND_PLAYER_IMPL_H
