/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <unistd.h>
#include "media_errors.h"
#include "media_log.h"
#include "soundpool_manager.h"
#include "soundpool_manager_multi.h"
#include "soundpool.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPool"};
    static const int32_t SOUNDPOOL_API_VERSION_ISOLATION = 18;
    static const int32_t FAULT_API_VERSION = -1;
    static const int32_t ERROR_RETURN = -1;
}

namespace OHOS {
namespace Media {
std::shared_ptr<ISoundPool> SoundPoolFactory::CreateSoundPool(int maxStreams,
    AudioStandard::AudioRendererInfo audioRenderInfo)
{
    MEDIA_LOGI("SoundPoolFactory::CreateSoundPool");
    std::shared_ptr<SoundPool> impl;
    if (!SoundPool::CheckInitParam(maxStreams, audioRenderInfo)) {
        return nullptr;
    }
    int32_t apiVersion = GetAPIVersion();
    CHECK_AND_RETURN_RET_LOG(apiVersion > 0 || apiVersion == FAULT_API_VERSION, nullptr, "invalid apiVersion");
    if (apiVersion > 0 && apiVersion < SOUNDPOOL_API_VERSION_ISOLATION) {
        MEDIA_LOGI("SoundPoolFactory::CreateSoundPool go old version");
        SoundPoolManager::GetInstance().SetSoundPool(getpid(), impl);
        SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl);
        CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to get SoundPool");

        int32_t ret = impl->Init(maxStreams, audioRenderInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init SoundPool");
        impl->SetApiVersion(apiVersion);

        return impl;
    } else {
        int32_t ret = SoundPoolManagerMulti::GetInstance().GetSoundPoolInstance(impl);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK && impl != nullptr, nullptr, "failed to get SoundPoolMulti");

        ret = impl->Init(maxStreams, audioRenderInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init SoundPoolMulti");
        impl->SetApiVersion(apiVersion);

        return impl;
    }
}

std::shared_ptr<ISoundPool> SoundPoolFactory::CreateParallelSoundPool(int maxStreams,
    AudioStandard::AudioRendererInfo audioRenderInfo)
{
    MEDIA_LOGI("SoundPoolFactory::CreateParallelSoundPool");
    std::shared_ptr<SoundPool> impl;
    if (!SoundPool::CheckInitParam(maxStreams, audioRenderInfo)) {
        return nullptr;
    }
    int32_t apiVersion = GetAPIVersion();
    CHECK_AND_RETURN_RET_LOG(apiVersion > 0 || apiVersion == FAULT_API_VERSION, nullptr, "invalid apiVersion");
    int32_t ret = SoundPoolManagerMulti::GetInstance().GetSoundPoolInstance(impl);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK && impl != nullptr, nullptr, "failed to get SoundPoolMulti");

    ret = impl->InitParallel(maxStreams, audioRenderInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init SoundPoolMulti");
    impl->SetApiVersion(apiVersion);

    return impl;
}

SoundPool::SoundPool()
{
    MEDIA_LOGI("Construction SoundPool.");
}

SoundPool::~SoundPool()
{
    MEDIA_LOGI("Destruction SoundPool.");
    ReleaseInner();
}

int32_t SoundPool::Init(int maxStreams, AudioStandard::AudioRendererInfo audioRenderInfo)
{
    // start contruct stream manager
    std::lock_guard lock(soundPoolLock_);
    streamIdManager_ = std::make_shared<StreamIDManager>(maxStreams, audioRenderInfo);
    int ret = streamIdManager_->InitThreadPool();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "failed to init streamIdManager");
    soundIDManager_ = std::make_shared<SoundIDManager>();
    return MSERR_OK;
}

int32_t SoundPool::InitParallel(int maxStreams, AudioStandard::AudioRendererInfo audioRenderInfo)
{
    std::lock_guard lock(soundPoolLock_);
    soundIDManager_ = std::make_shared<SoundIDManager>();
    parallelStreamManager_ = std::make_shared<ParallelStreamManager>(maxStreams, audioRenderInfo);
    int ret = parallelStreamManager_->InitThreadPool();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "failed to init parallelStreamManager");
    parallelStreamFlag_ = true;
    return MSERR_OK;
}

bool SoundPool::CheckInitParam(int maxStreams, AudioStandard::AudioRendererInfo audioRenderInfo)
{
    if (maxStreams <= 0) {
        return false;
    }
    if (audioRenderInfo.contentType < AudioStandard::CONTENT_TYPE_UNKNOWN
        || audioRenderInfo.contentType > AudioStandard::CONTENT_TYPE_ULTRASONIC
        || audioRenderInfo.streamUsage < AudioStandard::STREAM_USAGE_UNKNOWN
        || audioRenderInfo.streamUsage > AudioStandard::STREAM_USAGE_VOICE_MODEM_COMMUNICATION
        || audioRenderInfo.rendererFlags < 0 || audioRenderInfo.rendererFlags > 1) {
        return false;
    }
    return true;
}

int32_t SoundPool::Load(const std::string url)
{
    MediaTrace trace("SoundPool::Load url");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Load url::%{public}s", url.c_str());
    CHECK_AND_RETURN_RET_LOG(!url.empty(), -1, "Failed to obtain SoundPool for load");
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "sound id manager have released.");
    return soundIDManager_->Load(url, apiVersion_);
}

int32_t SoundPool::Load(int32_t fd, int64_t offset, int64_t length)
{
    MediaTrace trace("SoundPool::Load fd");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Load fd::%{public}d, offset::%{public}s, length::%{public}s", fd,
        std::to_string(offset).c_str(), std::to_string(length).c_str());
    CHECK_AND_RETURN_RET_LOG((fd > 0 && length > 0 && offset >= 0), -1, "Invalid fd param.");
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "sound id manager have released.");
    return soundIDManager_->Load(fd, offset, length, apiVersion_);
}

int32_t SoundPool::Play(int32_t soundID, PlayParams playParameters)
{
    MediaTrace trace("SoundPool::Play");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Play soundID::%{public}d ,priority::%{public}d", soundID, playParameters.priority);
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "sound id manager have released.");
    std::shared_ptr<SoundParser> soundParser = soundIDManager_->FindSoundParser(soundID);

    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "Invalid sound.");
    if (!soundParser->IsSoundParserCompleted()) {
        MEDIA_LOGE("sound load no completed. ");
        return -1;
    }
    int32_t streamID;
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, ERROR_RETURN,
            "parallelStreamManager_ have released.");
        streamID = parallelStreamManager_->Play(soundParser, playParameters);
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, ERROR_RETURN, "sound pool have released.");
        streamID = streamIdManager_->Play(soundParser, playParameters);
    }
    MEDIA_LOGI("SoundPool::Play streamID::%{public}d", streamID);
    return streamID;
}

int32_t SoundPool::Stop(int32_t streamID)
{
    MediaTrace trace("SoundPool::Stop");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Stop streamID::%{public}d", streamID);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->Stop();
        }
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            return cacheBuffer->Stop(streamID);
        }
    }
    MEDIA_LOGI("SoundPool::Stop can not find stream or cachebuffer streamID::%{public}d", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetLoop(int32_t streamID, int32_t loop)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetLoop streamID:%{public}d, loop:%{public}d", streamID, loop);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->SetLoop(loop);
        }
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            return cacheBuffer->SetLoop(streamID, loop);
        }
    }
    MEDIA_LOGI("SoundPool::SetLoop can not find stream or cachebuffer streamID::%{public}d", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetPriority(int32_t streamID, int32_t priority)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetPriority streamID::%{public}d ,priority::%{public}d", streamID, priority);
    if (priority < MIN_STREAM_PRIORITY) {
        MEDIA_LOGI("Invalid priority, align priority to min.");
        priority = MIN_STREAM_PRIORITY;
    }
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            int32_t ret = stream->SetPriority(priority);
            parallelStreamManager_->ReorderStream();
            return ret;
        }
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            int32_t ret = cacheBuffer->SetPriority(streamID, priority);
            streamIdManager_->ReorderStream(streamID, priority);
            return ret;
        }
    }
    MEDIA_LOGI("SoundPool::SetPriority can not find stream or cachebuffer streamID::%{public}d", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetRate(int32_t streamID, AudioStandard::AudioRendererRate renderRate)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetRate streamID:%{public}d, renderRate:%{public}d", streamID, renderRate);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->SetRate(renderRate);
        }
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            return cacheBuffer->SetRate(streamID, renderRate);
        }
    }
    MEDIA_LOGI("SoundPool::SetRate can not find stream or cachebuffer streamID::%{public}d", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetVolume(int32_t streamID, float leftVolume, float rightVolume)
{
    if (!CheckVolumeVaild(&leftVolume, &rightVolume)) {
        return MSERR_INVALID_VAL;
    }
    MEDIA_LOGI("SoundPool::SetVolume streamID:%{public}d, leftVolume:%{public}f, rightVolume:%{public}f",
        streamID, leftVolume, rightVolume);
    std::lock_guard lock(soundPoolLock_);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->SetVolume(leftVolume, rightVolume);
        }
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            return cacheBuffer->SetVolume(streamID, leftVolume, rightVolume);
        }
    }
    MEDIA_LOGI("SoundPool::SetVolume can not find stream or cachebuffer streamID::%{public}d", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::Unload(int32_t soundID)
{
    MediaTrace trace("SoundPool::Unload");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Unload soundID::%{public}d", soundID);
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "sound id manager have released.");
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        parallelStreamManager_->UnloadStream(soundID);
    } else {
        CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
        int32_t streamID = streamIdManager_->GetStreamIDBySoundID(soundID);
        if (std::shared_ptr<CacheBuffer> cacheBuffer = streamIdManager_->FindCacheBufferLock(streamID)) {
            cacheBuffer->Stop(streamID);
            cacheBuffer->Release();
            streamIdManager_->ClearStreamIDInDeque(streamID, soundID);
        }
    }
    return soundIDManager_->Unload(soundID);
}

int32_t SoundPool::Release()
{
    MEDIA_LOGI("SoundPool::Release");
    return ReleaseInner();
}

int32_t SoundPool::ReleaseInner()
{
    MediaTrace trace("SoundPool::ReleaseInner");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::ReleaseInner");
    if (streamIdManager_ != nullptr) {
        streamIdManager_.reset();
    }
    if (soundIDManager_ != nullptr) {
        soundIDManager_.reset();
    }
    if (parallelStreamManager_ != nullptr) {
        parallelStreamManager_.reset();
    }
    if (callback_ != nullptr) {
        callback_.reset();
    }
    if (frameWriteCallback_ != nullptr) {
        frameWriteCallback_.reset();
    }
    
    if (apiVersion_ > 0 && apiVersion_ < SOUNDPOOL_API_VERSION_ISOLATION && !parallelStreamFlag_) {
        SoundPoolManager::GetInstance().Release(getpid());
    } else if (apiVersion_ == FAULT_API_VERSION || apiVersion_ >= SOUNDPOOL_API_VERSION_ISOLATION ||
        parallelStreamFlag_) {
        std::shared_ptr<SoundPool> sharedPtr(this, [](SoundPool*) {
        });
        SoundPoolManagerMulti::GetInstance().ReleaseInstance(sharedPtr);
    } else {
        MEDIA_LOGI("SoundPool::ReleaseInner error apiVersion_: %{public}d", apiVersion_);
    }
    return MSERR_OK;
}

int32_t SoundPool::SetSoundPoolCallback(const std::shared_ptr<ISoundPoolCallback> &soundPoolCallback)
{
    MEDIA_LOGI("SoundPool::SetSoundPoolCallback");
    if (soundIDManager_ != nullptr) {
        soundIDManager_->SetCallback(soundPoolCallback);
    }
    if (streamIdManager_ != nullptr) {
        streamIdManager_->SetCallback(soundPoolCallback);
    }
    if (parallelStreamManager_ != nullptr) {
        parallelStreamManager_->SetCallback(soundPoolCallback);
    }
    callback_ = soundPoolCallback;
    return MSERR_OK;
}

int32_t SoundPool::SetSoundPoolFrameWriteCallback(
    const std::shared_ptr<ISoundPoolFrameWriteCallback> &frameWriteCallback)
{
    MEDIA_LOGI("SoundPool::SetSoundPoolFrameWriteCallback");
    if (streamIdManager_ != nullptr) {
        streamIdManager_->SetFrameWriteCallback(frameWriteCallback);
    }
    if (parallelStreamManager_ != nullptr) {
        parallelStreamManager_->SetFrameWriteCallback(frameWriteCallback);
    }
    frameWriteCallback_ = frameWriteCallback;
    return MSERR_OK;
}

bool SoundPool::CheckVolumeVaild(float *leftVol, float *rightVol)
{
    if (*leftVol != std::clamp(*leftVol, 0.f, 1.f) ||
        *rightVol != std::clamp(*rightVol, 0.f, 1.f)) {
        MEDIA_LOGI("volume l=%{public}f r=%{public}f out of (0.f, 1.f) bounds, using 1.f", *leftVol, *rightVol);
        *leftVol = *rightVol = 1.f;
    }
    if (*leftVol != *rightVol) {
        MEDIA_LOGI("left volume %{public}f set not eq the right volume %{public}f ,use the left volume",
            *leftVol, *rightVol);
        *rightVol = *leftVol;
    }
    return true;
}

void SoundPool::SetApiVersion(int32_t apiVersion)
{
    std::lock_guard lock(soundPoolLock_);
    apiVersion_ = apiVersion;
}

} // namespace Media
} // namespace OHOS
