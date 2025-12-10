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
#include "soundpool.h"
#include "soundpool_manager.h"
#include "soundpool_manager_multi.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPool"};
    static const int32_t MIN_STREAM_PRIORITY = 0;
    static const int32_t SOUNDPOOL_API_VERSION_ISOLATION = 18;
    static const int32_t FAULT_API_VERSION = -1;
    static const int32_t ERROR_RETURN = -1;
}

namespace OHOS {
namespace Media {
std::shared_ptr<ISoundPool> SoundPoolFactory::CreateSoundPool(int maxStreams,
    const AudioStandard::AudioRendererInfo &audioRenderInfo, InterruptMode interruptMode)
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
        SoundPoolManager::GetInstance().GetSoundPool(getpid(), impl);
        CHECK_AND_RETURN_RET_LOG(impl != nullptr, nullptr, "failed to get SoundPool");

        int32_t ret = impl->Init(maxStreams, audioRenderInfo);
        CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init SoundPool");
        impl->SetApiVersion(apiVersion);

        return impl;
    }
    int32_t ret = SoundPoolManagerMulti::GetInstance().GetSoundPoolInstance(impl);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK && impl != nullptr, nullptr, "failed to get SoundPoolMulti");

    ret = impl->Init(maxStreams, audioRenderInfo);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, nullptr, "failed to init SoundPoolMulti");
    impl->SetApiVersion(apiVersion);

    return impl;
}

std::shared_ptr<ISoundPool> SoundPoolFactory::CreateParallelSoundPool(int maxStreams,
    const AudioStandard::AudioRendererInfo &audioRenderInfo)
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
    MEDIA_LOGI("SoundPool Constructor");
}

SoundPool::~SoundPool()
{
    MEDIA_LOGI("SoundPool Destructor");
    ReleaseInner();
}

int32_t SoundPool::Init(int maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo)
{
    // start contruct stream manager
    std::lock_guard lock(soundPoolLock_);
    soundIDManager_ = std::make_shared<SoundIDManager>();
    streamIdManager_ = std::make_shared<StreamIDManager>(maxStreams, audioRenderInfo, interruptMode_);
    int ret = streamIdManager_->InitThreadPool();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "failed to init streamIdManager");
    return MSERR_OK;
}

int32_t SoundPool::InitParallel(int maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo)
{
    std::lock_guard lock(soundPoolLock_);
    soundIDManager_ = std::make_shared<SoundIDManager>();
    parallelStreamManager_ = std::make_shared<ParallelStreamManager>(maxStreams, audioRenderInfo);
    int ret = parallelStreamManager_->InitThreadPool();
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, MSERR_INVALID_VAL, "failed to init parallelStreamManager");
    parallelStreamFlag_ = true;
    return MSERR_OK;
}

bool SoundPool::CheckInitParam(int maxStreams, const AudioStandard::AudioRendererInfo &audioRenderInfo)
{
    if (maxStreams <= 0) {
        return false;
    }
    bool isRendererFlagsInvalid = !CheckRendererFlagsValid(audioRenderInfo);
    if (audioRenderInfo.contentType < AudioStandard::CONTENT_TYPE_UNKNOWN ||
        audioRenderInfo.contentType > AudioStandard::CONTENT_TYPE_ULTRASONIC ||
        audioRenderInfo.streamUsage < AudioStandard::STREAM_USAGE_UNKNOWN ||
        audioRenderInfo.streamUsage > AudioStandard::STREAM_USAGE_VOICE_MODEM_COMMUNICATION ||
        isRendererFlagsInvalid) {
        return false;
    }
    return true;
}

int32_t SoundPool::Load(const std::string &url)
{
    MediaTrace trace("SoundPool::Load url");
    std::lock_guard lock(soundPoolLock_);
    CHECK_AND_RETURN_RET_LOG(!url.empty(), -1, "url is empty");
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "soundIDManager_ has been released");
    return soundIDManager_->Load(url);
}

int32_t SoundPool::Load(int32_t fd, int64_t offset, int64_t length)
{
    MediaTrace trace("SoundPool::Load fd");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("fd is %{public}d, offset is %{public}s, length is %{public}s", fd, std::to_string(offset).c_str(),
        std::to_string(length).c_str());
    CHECK_AND_RETURN_RET_LOG((fd > 0 && length > 0 && offset >= 0), -1, "Invalid fd param.");
    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "soundIDManager_ has been released");
    return soundIDManager_->Load(fd, offset, length, apiVersion_);
}

int32_t SoundPool::Play(int32_t soundID, const PlayParams &playParameters)
{
    MediaTrace trace("SoundPool::Play");
    MEDIA_LOGI("SoundPool::Play start");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Play, soundID is %{public}d ,priority is %{public}d", soundID, playParameters.priority);

    CHECK_AND_RETURN_RET_LOG(soundIDManager_ != nullptr, -1, "soundIDManager_ has been released");
    std::shared_ptr<SoundParser> soundParser = soundIDManager_->FindSoundParser(soundID);
    CHECK_AND_RETURN_RET_LOG(soundParser != nullptr, -1, "soundParser is nullptr");
    if (!soundParser->IsSoundParserCompleted()) {
        MEDIA_LOGE("SoundPool::Play, soundID(%{public}d) has not been loaded completely", soundID);
        return -1;
    }
    int32_t streamID = 0;
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, ERROR_RETURN,
            "parallelStreamManager_ have released.");
        streamID = parallelStreamManager_->Play(soundParser, playParameters);
        MEDIA_LOGI("SoundPool::Play end, streamID is %{public}d", streamID);
        return streamID;
    }

    // New playback path
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, ERROR_RETURN, "sound pool have released.");
    if (interruptMode_ == InterrruptMode::SAME_SOUND_INTERRUPT) {
        streamID = streamIdManager_->PlayWithSameSoundInterrupt(soundParser, playParameters);
        MEDIA_LOGI("SoundPool::Play end, streamID is %{public}d", streamID);
        return streamID;
    }
    if (interruptMode_ == InterruptMode::NO_INTERRUPT) {
        streamID = streamIdManager_->PlayWithNoInterrupt(soundParser, playParameters);
        MEDIA_LOGI("SoundPool::Play end, streamID is %{public}d", streamID);
        return streamID;
    }
    return streamID;
}

int32_t SoundPool::Stop(int32_t streamID)
{
    MediaTrace trace("SoundPool::Stop");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Stop, streamID(%{public}d) will be stopped", streamID);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->Stop();
        }
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL,
        "SoundPool::Stop, streamIdManager_ is nullptr");
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->FindCacheBufferLock(streamID)) {
        return stream->Stop(streamID);
    }
    MEDIA_LOGI("SoundPool::Stop, can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetLoop(int32_t streamID, int32_t loop)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetLoop start, streamID is %{public}d, loop is %{public}d", streamID, loop);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ has been released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->SetLoop(loop);
        }
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
        return stream->SetLoop(loop);
    }
    MEDIA_LOGI("SoundPool::SetLoop, can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetPriority(int32_t streamID, int32_t priority)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetPriority start, streamID is %{public}d, priority is %{public}d", streamID, priority);
    if (priority < MIN_STREAM_PRIORITY) {
        MEDIA_LOGI("Invalid priority, priority is invalid, assign lowest priority by default");
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
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL,
        "SoundPool::SetPriority, streamIdManager_ is nullptr");
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
        int32_t ret = stream->SetPriority(priority);
        streamIdManager_->ReorderStream(priority);
        return ret;
    }
    MEDIA_LOGI("SoundPool::SetPriority, can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
} 

int32_t SoundPool::SetRate(int32_t streamID, const AudioStandard::AudioRendererRate &renderRate)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetRate streamID:%{public}d, renderRate:%{public}d", streamID, renderRate);
    if (parallelStreamFlag_) {
        CHECK_AND_RETURN_RET_LOG(parallelStreamManager_ != nullptr, MSERR_INVALID_VAL,
            "parallelStreamManager_ have released.");
        if (std::shared_ptr<Stream> stream = parallelStreamManager_->FindStreamLock(streamID)) {
            return stream->SetRate(renderRate);
        }
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL,
        "SoundPool::SetRate, streamIdManager_ is nullptr");
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
        return stream->SetRate(renderRate);
    }
    MEDIA_LOGI("SoundPool::SetRate can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
}

int32_t SoundPool::SetVolume(int32_t streamID, float leftVolume, float rightVolume)
{
    if (!CheckVolumeValid(&leftVolume, &rightVolume)) {
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
        return MSERR_INVALID_OPERATION;
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "sound pool have released.");
    if (std::shared_ptr<AudioStream> audioStream = streamIdManager_->FindCacheBufferLock(streamID)) {
        return audioStream->SetVolume(streamID, leftVolume, rightVolume);
    }
    MEDIA_LOGI("SoundPool::SetVolume, can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
}

void SoundPool::SetInterruptMode(InterruptMode interruptMode)
{
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::SetInterruptMode, current interruptMode is %{public}d, new interruptMode is %{public}d",
        interruptMode_, interruptMode);
    if (interruptMode < interruptMode::NO_INTERRUPT || interruptMode > InterruptMode::SAME_SOUND_INTERRUPT) {
        MEDIA_LOGE("interruptMode(%{public}d) is invalid", interruptMode);
        return;
    }
    interruptMode_ = interruptMode;
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
        return soundIDManager_->Unload(soundID);
    }
    CHECK_AND_RETURN_RET_LOG(streamIdManager_ != nullptr, MSERR_INVALID_VAL, "streamIdManager_ has been released");
    int32_t streamID = streamIdManager_->GetStreamIDBySoundIDWithLock(soundID);
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
        stream->Stop();
        stream->Release();
        streamIdManager_->ClearStreamIDInDeque(soundID, streamID);
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
    
    if (apiVersion_ > 0 && apiVersion_ < SOUNDPOOL_API_VERSION_ISOLATION && !parallelStreamFlag_ && !isReleased_) {
        SoundPoolManager::GetInstance().Release(getpid());
        isReleased_ = true;
        MEDIA_LOGI("ReleaseInner Out");
        return MSERR_OK;
    }
    if (apiVersion_ == FAULT_API_VERSION || apiVersion_ >= SOUNDPOOL_API_VERSION_ISOLATION || parallelStreamFlag_) {
        std::shared_ptr<SoundPool> sharedPtr(this, [](SoundPool*) {});
        SoundPoolManagerMulti::GetInstance().ReleaseInstance(sharedPtr);
        return MSERR_OK;
    }
    MEDIA_LOGI("ReleaseInner error, apiVersion_ is %{public}d", apiVersion_);
    return MSERR_OK;
}

int32_t SoundPool::SetSoundPoolCallback(const std::shared_ptr<ISoundPoolCallback> &soundPoolCallback)
{
    MEDIA_LOGI("SetSoundPoolCallback");
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

bool SoundPool::CheckVolumeValid(float *leftVol, float *rightVol)
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
    soundIDManager_->SetApiVersion(apiVersion);
}

bool SoundPool::CheckRendererFlagsValid(AudioStandard::AudioRendererInfo audioRenderInfo)
{
    if (audioRenderInfo.rendererFlags == 0 || audioRenderInfo.rendererFlags == 1) {
        return true;
    }
    bool isBundleNameValid = false;
    std::string bundleName = AudioStandard::AudioSystemManager::GetInstance()->GetSelfBundleName(getuid());
    AudioStandard::AudioSystemManager::GetInstance()->CheckVKBInfo(bundleName, isBundleNameValid);
    if (audioRenderInfo.rendererFlags == AudioStandard::AUDIO_FLAG_VKB_NORMAL && isBundleNameValid) {
        return true;
    }
    if (audioRenderInfo.rendererFlags == AudioStandard::AUDIO_FLAG_VKB_FAST && isBundleNameValid) {
        return true;
    }
    return false;
}
} // namespace Media
} // namespace OHOS
