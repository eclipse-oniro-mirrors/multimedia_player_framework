/*
 * Copyright (C) 2023 Huawei Device Co., Ltd. 2025-2025. All rights reserved.
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
#include <thread>

#include "media_errors.h"
#include "media_log.h"
#include "media_utils.h"
#include "soundpool_manager.h"
#include "soundpool_manager_multi.h"
#include "soundpool.h"

#ifndef CROSS_PLATFORM
#include "nlohmann/json.hpp"
#include "ipc_skeleton.h"
#endif

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "SoundPool"};
    static const int32_t MIN_STREAM_PRIORITY = 0;
    static const int32_t SOUNDPOOL_API_VERSION_ISOLATION = 18;
    static const int32_t FAULT_API_VERSION = -1;
    static const int32_t ERROR_RETURN = -1;
    static const char *const MODULE_NAME = "SoundPool";
    static const char *const DFX_MSG_SUCCEED = "Succeed";
    static const char *const DFX_MSG_FAILED = "Failed";
    static const char *const DFX_API_LOAD = "Load";
    static const char *const DFX_API_PLAY = "Play";

    static inline void IncreaseStatistic(std::atomic<int32_t> &statisticVar)
    {
        statisticVar.fetch_add(1, std::memory_order_relaxed);
    }

    template <typename Task, typename ...Args> static inline void AsyncCall(Task &&task, Args ...args)
    {
        std::thread(std::move(task), std::forward<Args>(args)...).detach();
    }
}

namespace OHOS {
namespace Media {
#ifndef CROSS_PLATFORM
using Json = nlohmann::json;
#endif
std::shared_ptr<ISoundPool> SoundPoolFactory::CreateSoundPool(int maxStreams,
    const AudioStandard::AudioRendererInfo &audioRenderInfo)
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
    streamIDManagerWithSameSoundInterrupt_ = std::make_shared<StreamIDManagerWithSameSoundInterrupt>(maxStreams,
        audioRenderInfo);
    streamIDManagerWithNoInterrupt_ = std::make_shared<StreamIDManagerWithNoInterrupt>(maxStreams, audioRenderInfo);
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
    
    do {
        CHECK_AND_BREAK_LOG(!url.empty(), "url is empty");
        CHECK_AND_BREAK_LOG(soundIDManager_ != nullptr, "soundIDManager_ has been released");
        const int32_t soundId = soundIDManager_->Load(url);
        CHECK_AND_BREAK_LOG(soundId != -1, "soundIDManager load failed");
        IncreaseStatistic(loadSucceed_);
        return soundId;
    } while (false);
    IncreaseStatistic(loadFailed_);
    return ERROR_RETURN;
}

int32_t SoundPool::Load(int32_t fd, int64_t offset, int64_t length)
{
    MediaTrace trace("SoundPool::Load fd");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("fd is %{public}d, offset is %{public}s, length is %{public}s", fd, std::to_string(offset).c_str(),
        std::to_string(length).c_str());
    do {
        CHECK_AND_BREAK_LOG((fd > 0 && length > 0 && offset >= 0), "Invalid fd param.");
        CHECK_AND_BREAK_LOG(soundIDManager_ != nullptr, "soundIDManager_ has been released");
        const int32_t soundId = soundIDManager_->Load(fd, offset, length);
        CHECK_AND_BREAK_LOG(soundId != -1, "soundIDManager load failed");
        IncreaseStatistic(loadSucceed_);
        return soundId;
    } while (false);
    IncreaseStatistic(loadFailed_);
    return ERROR_RETURN;
}

int32_t SoundPool::Play(int32_t soundID, const PlayParams &playParameters)
{
    MediaTrace trace("SoundPool::Play");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::Play start, soundID is %{public}d, priority is %{public}d", soundID,
        playParameters.priority)

    do {
        CHECK_AND_BREAK_LOG(soundIDManager_ != nullptr, "soundIDManager_ has been released");
        std::shared_ptr<SoundParser> soundParser = soundIDManager_->GetSoundParserBySoundID(soundID);
        CHECK_AND_BREAK_LOG(soundParser != nullptr, "soundParser is nullptr");
        CHECK_AND_BREAK_LOG(soundParser->IsSoundParserCompleted(),
            "SoundPool::Play, soundID(%{public}d) has not been loaded completely", soundID);
        int32_t streamID = ERROR_RETURN;
        if (parallelStreamFlag_) {
            CHECK_AND_BREAK_LOG(parallelStreamManager_ != nullptr, "parallelStreamManager_ has been released.");
            streamID = parallelStreamManager_->Play(soundParser, playParameters);
            MEDIA_LOGI("SounPool::Play end, streamID is %{public}d", streamID);
            CHECK_AND_BREAK(streamID >= 0);
            IncreaseStatistic(playSucceed_);
            return streamID;
        }

        // New playback path
        if (!isSetInterruptMode_) {
            MEDIA_LOGI("interruptMode_ is %{public}d", interruptMode_);
            streamIdManager_ = (interruptMode_ == InterruptMode::SAME_SOUND_INTERRUPT) ?
                streamIDManagerWithSameSoundInterrupt_ : streamIDManagerWithNoInterrupt_;
            streamIDManagerWithSameSoundInterrupt_.reset();
            streamIDManagerWithNoInterrupt_.reset();
            CHECK_AND_BREAK_LOG(streamIdManager_ != nullptr, "Initialize streamIdManager_ failed.");
            int ret = streamIdManager_->InitThreadPool();
            CHECK_AND_BREAK_LOG(ret == MSERR_OK, ERROR_RETURN, "failed to init streamIdManager");
        }
        isSetInterruptMode_ = true;
        CHECK_AND_BREAK_LOG(streamIdManager_ != nullptr, "sound pool have released.");
        streamID = streamIdManager_->Play(soundParser, playParameters);
        MEDIA_LOGI("SoundPool::Play end, streamID is %{public}d", streamID);
        CHECK_AND_BREAK(streamID >= 0);
        IncreaseStatistic(loadSucceed_);
        return streamID;
    } while (false);
    IncreaseStatistic(playFailed_);
    return ERROR_RETURN;
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
    if (streamIdManager_ != nullptr) {
        std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID);
        CHECK_AND_RETURN_RET_LOG(stream != nullptr, MSERR_INVALID_VAL,
            "SoundPool::Stop, stream is nullptr");
        return stream->Stop();
    }
    MEDIA_LOGE("SoundPool::Stop, can not find the stream(%{public}d)", streamID);
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
        streamIdManager_->ReorderStream(streamID, priority);
        return ret;
    }
    MEDIA_LOGE("SoundPool::SetPriority, can not find the stream(%{public}d)", streamID);
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
    MEDIA_LOGE("SoundPool::SetRate can not find the stream(%{public}d)", streamID);
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
    if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
        return stream->SetVolume(leftVolume, rightVolume);
    }
    MEDIA_LOGE("SoundPool::SetVolume, can not find the stream(%{public}d)", streamID);
    return MSERR_INVALID_OPERATION;
}

void SoundPool::SetInterruptMode(InterruptMode interruptMode)
{
    std::lock_guard lock(soundPoolLock_);
    CHECK_AND_RETURN_LOG(!isSetInterruptMode_, "SoundPool::SetInterruptMode failed, InterruptMode has been set");
    MEDIA_LOGI("SoundPool::SetInterruptMode, current interruptMode is %{public}d, new interruptMode is %{public}d",
        interruptMode_, interruptMode);
    if (interruptMode < InterruptMode::NO_INTERRUPT || interruptMode > InterruptMode::SAME_SOUND_INTERRUPT) {
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

    if (streamIdManager_ != nullptr) {
        std::vector<int32_t> streamIDsToBeRemoved = streamIdManager_->GetStreamIDBySoundIDWithLock(soundID);
        for (int32_t streamID : streamIDsToBeRemoved) {
            if (std::shared_ptr<AudioStream> stream = streamIdManager_->GetStreamByStreamIDWithLock(streamID)) {
                stream->Stop();
                stream->Release();
                streamIdManager_->ClearStreamIDInDeque(soundID, streamID);
            }
        }
    }
    return soundIDManager_->Unload(soundID);
}

int32_t SoundPool::Release()
{
    MEDIA_LOGI("SoundPool::Release");
    
    int32_t playSucceed = playSucceed_.exchange(0, std:memory_order_relaxed);
    int32_t loadSucceed = loadSucceed_.exchange(0, std:memory_order_relaxed);
    int32_t playFailed = playFailed_.exchange(0, std:memory_order_relaxed);
    int32_t loadFailed = loadFailed_.exchange(0, std:memory_order_relaxed);

    AsyncCall([playSucceed, loadSucceed, playFailed, loadFailed]() {
        Json json;
        json[DFX_API_LOAD][DFX_MSG_SUCCEED] = loadSucceed;
        json[DFX_API_LOAD][DFX_MSG_FAILED] = loadFailed;
        json[DFX_API_PLAY][DFX_MSG_SUCCEED] = playSucceed;
        json[DFX_API_PLAY][DFX_MSG_FAILED] = playFailed;
        std::string jsonString = json.dump();

        const int32_t appUid = IPCSkeleton::GetCallingUid();
        const std::string appName = GetClientBundleName(appUid);

        HiSysEventWrite(OHOS::HiviewDFX::HiSysEvent::Domain::MULTI_MEDIA,
            "MEIDAKIT_STATISTICS",
            OHOS::HiviewDFX::HiSysEvent::EventType::STATISTIC,
            "SYSCAP", MODULE_NAME,
            "APP_NAME", appName,
            "API_CALL", "Load|Play",
            "MEDIA_EVENTS", jsonString);
    });
    return ReleaseInner();
}

int32_t SoundPool::ReleaseInner()
{
    MediaTrace trace("SoundPool::ReleaseInner");
    std::lock_guard lock(soundPoolLock_);
    MEDIA_LOGI("SoundPool::ReleaseInner");
    isSetInterruptMode_ = false;
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
    if (streamIDManagerWithSameSoundInterrupt_ != nullptr) {
        streamIDManagerWithSameSoundInterrupt_->SetCallback(soundPoolCallback);
    }
    if (streamIDManagerWithNoInterrupt_ != nullptr) {
        streamIDManagerWithNoInterrupt_->SetCallback(soundPoolCallback);
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
    if (streamIDManagerWithSameSoundInterrupt_ != nullptr) {
        streamIDManagerWithSameSoundInterrupt_->SetFrameWriteCallback(frameWriteCallback);
    }
    if (streamIDManagerWithNoInterrupt_ != nullptr) {
        streamIDManagerWithNoInterrupt_->SetFrameWriteCallback(frameWriteCallback);
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
