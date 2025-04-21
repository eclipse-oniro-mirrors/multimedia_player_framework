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

#include "audio_renderer_manager.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "AudioRendererManager"};
    static const int32_t AUDIO_RENDERER_MAX_NUM = 20;
}

namespace OHOS {
namespace Media {
AudioRendererManager::~AudioRendererManager()
{
    MEDIA_LOGI("Destruction AudioRendererManager.");
};

AudioRendererManager& AudioRendererManager::GetInstance()
{
    static AudioRendererManager instance;
    return instance;
}

int32_t AudioRendererManager::GetGlobeId()
{
    std::lock_guard<std::mutex> lock(renderMgrMutex_);
    globeIdNext_ = globeIdNext_ == INT32_MAX ? 1 : globeIdNext_ + 1;
    return globeIdNext_;
}

std::unique_ptr<AudioStandard::AudioRenderer> AudioRendererManager::GetAudioRendererInstance(int32_t globeId)
{
    MediaTrace trace("AudioRendererManager::GetAudioRendererInstance");
    std::lock_guard<std::mutex> lock(renderMgrMutex_);
    std::unique_ptr<AudioStandard::AudioRenderer> findInstance;
    for (auto it = audioRendererVector_.begin(); it != audioRendererVector_.end();) {
        if (it->first == globeId) {
            findInstance = std::move(it->second);
            it = audioRendererVector_.erase(it);
            break;
        } else {
            ++it;
        }
    }
    MEDIA_LOGI("AudioRendererManager::GetAudioRendererInstance audioRendererVector_ size:%{public}zu",
        audioRendererVector_.size());
    return findInstance;
}

void AudioRendererManager::SetAudioRendererInstance(int32_t globeId,
    std::unique_ptr<AudioStandard::AudioRenderer> audioRenderer)
{
    MediaTrace trace("AudioRendererManager::SetAudioRendererInstance");
    renderMgrMutex_.lock();
    audioRendererVector_.push_back(std::make_pair(globeId, std::move(audioRenderer)));
    int32_t removeGlobeId = -1;
    MEDIA_LOGI("AudioRendererManager::SetAudioRendererInstance audioRendererVector_ size:%{public}zu",
        audioRendererVector_.size());
    int32_t excessNum =  static_cast<int32_t>(audioRendererVector_.size()) - AUDIO_RENDERER_MAX_NUM;
    if (excessNum > 0) {
        MEDIA_LOGI("AudioRendererManager::SetAudioRendererInstance release audioRenderer");
        SoundPoolXCollie soundPoolXCollie("AudioRenderer::Release time out",
            [](void *) {
                MEDIA_LOGI("AudioRenderer::Release time out");
            });
        removeGlobeId = audioRendererVector_.front().first;
        (audioRendererVector_.front().second)->Release();
        soundPoolXCollie.CancelXCollieTimer();
        audioRendererVector_.pop_front();
    }
    renderMgrMutex_.unlock();
    if (removeGlobeId > 0) {
        DeleteManager(removeGlobeId);
    }
}

void AudioRendererManager::RemoveOldAudioRenderer()
{
    MediaTrace trace("AudioRendererManager::RemoveOldAudioRenderer");
    renderMgrMutex_.lock();
    int32_t removeGlobeId = -1;
    if (audioRendererVector_.size() > 0) {
        SoundPoolXCollie soundPoolXCollie("AudioRenderer::RemoveOld time out",
            [](void *) {
                MEDIA_LOGI("AudioRenderer::RemoveOld time out");
            });
        removeGlobeId = audioRendererVector_.front().first;
        (audioRendererVector_.front().second)->Release();
        soundPoolXCollie.CancelXCollieTimer();
        audioRendererVector_.pop_front();
    }
    renderMgrMutex_.unlock();
    if (removeGlobeId > 0) {
        DeleteManager(removeGlobeId);
    }
}

void AudioRendererManager::SetParallelManager(std::weak_ptr<ParallelStreamManager> parallelManager)
{
    std::lock_guard<std::mutex> lock(renderMgrMutex_);
    parallelManagerList_.push_back(parallelManager);
}

void AudioRendererManager::SetStreamIDManager(std::weak_ptr<StreamIDManager> streamIDManager)
{
    std::lock_guard<std::mutex> lock(renderMgrMutex_);
    streamIDManagerList_.push_back(streamIDManager);
}

void AudioRendererManager::DeleteManager(int32_t globeId)
{
    for (const auto& weakManager : parallelManagerList_) {
        if (auto sharedManager = weakManager.lock()) {
            sharedManager->DelGlobeId(globeId);
        }
    }
}

} // namespace Media
} // namespace OHOS
