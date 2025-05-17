/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
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

#include "audio_background_adapter.h"
#include <unistd.h>
#include "player.h"
#include "player_server.h"
#include "media_dfx.h"
#include "media_log.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "AudioBackgroundAdapter"};
}

namespace OHOS {
namespace Media {
std::shared_ptr<AudioBackgroundAdapter> AudioBackgroundAdapter::instance_;
std::once_flag AudioBackgroundAdapter::onceFlag_;

AudioBackgroundAdapter &AudioBackgroundAdapter::Instance()
{
    std::call_once(onceFlag_, [] {
        instance_ = std::make_shared<AudioBackgroundAdapter>();
    });
    return *instance_;
}

AudioBackgroundAdapter::AudioBackgroundAdapter()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AudioBackgroundAdapter::~AudioBackgroundAdapter()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void AudioBackgroundAdapter::Init()
{
    if (!init_.load()) {
        std::lock_guard<std::mutex> lock(initMutex_);
        if (!init_.load()) {
            MEDIA_LOGI("Init");
            auto audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
            CHECK_AND_RETURN_LOG(audioSystemManager != nullptr, "AudioSystemManager is nullptr");
            int32_t ret = audioSystemManager->SetBackgroundMuteCallback(shared_from_this());
            init_.store(ret == 0);
            CHECK_AND_RETURN_LOG(ret == 0, "failed to SetBackgroundMuteCallback");
        }
    }
}

void AudioBackgroundAdapter::AddListener(std::weak_ptr<IPlayerService> player, int32_t uid)
{
    Init();
    std::lock_guard<std::mutex> lock(mutex_);
    // clean map/list from listener list/map
    for (auto it1 = playerMap_.begin(); it1 != playerMap_.end();) {
        std::list<std::weak_ptr<IPlayerService>> &playerList = it1->second;
        for (auto it2 = playerList.begin(); it2 != playerList.end();) {
            std::weak_ptr<IPlayerService> &temp = *it2;
            if (temp.lock() == nullptr) {
                it2 = playerList.erase(it2);
            } else {
                ++it2;
            }
        }
        if (playerList.empty()) {
            it1 = playerMap_.erase(it1);
        } else {
            ++it1;
        }
    }
    MEDIA_LOGI("DelListener uid num %{public}zu", playerMap_.size());

    // add player to listener list/map
    auto it = playerMap_.find(uid);
    if (it != playerMap_.end()) {
        std::list<std::weak_ptr<IPlayerService>> &playerList = it->second;
        playerList.push_back(player);
        MEDIA_LOGI("AddListener uid %{public}d, player num %{public}zu", uid, playerList.size());
    } else {
        std::list<std::weak_ptr<IPlayerService>> playerList;
        playerList.push_back(player);
        playerMap_[uid] = playerList;
        MEDIA_LOGI("AddListener uid %{public}d, player num %{public}zu", uid, playerList.size());
    }
}

void AudioBackgroundAdapter::OnAudioRestart()
{
    std::lock_guard<std::mutex> lock(initMutex_);
    MEDIA_LOGI("ReInit");
    init_.store(false);
    auto audioSystemManager = AudioStandard::AudioSystemManager::GetInstance();
    CHECK_AND_RETURN_LOG(audioSystemManager != nullptr, "AudioSystemManager is nullptr");
    int32_t ret = audioSystemManager->SetBackgroundMuteCallback(shared_from_this());
    init_.store(ret == 0);
    CHECK_AND_RETURN_LOG(ret == 0, "failed to SetBackgroundMuteCallback");
}

void AudioBackgroundAdapter::OnBackgroundMute(const int32_t uid)
{
    std::list<std::weak_ptr<IPlayerService>> playerList;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it1 = playerMap_.find(uid);
        if (it1 != playerMap_.end()) {
            playerList = it1->second; // copylist and unlock mutex, Avoid locking the addlist
        }
    }

    MEDIA_LOGW("The application uid %{public}d is restricted by audio policy control", uid);
    for (auto &it2 : playerList) {
        auto player = it2.lock();
        if (player != nullptr && player->IsPlaying()) {
            MediaTrace trace("AudioBackgroundAdapter::Pause");
            auto playerServer = std::static_pointer_cast<PlayerServer>(player);
            (void)playerServer->BackGroundChangeState(PlayerStates::PLAYER_PAUSED, true);
            MEDIA_LOGW("The application has been logged back to the background");
        }
    }
}
} // namespace Media
} // namespace OHOS