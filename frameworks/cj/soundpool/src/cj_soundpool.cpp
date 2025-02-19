/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_soundpool.h"
#include "media_core.h"

namespace OHOS {
namespace Media {
int64_t CJSoundPool::CreatSoundPool(int32_t maxStreams, AudioStandard::CAudioRendererInfo info, int32_t &errorcode)
{
    CJSoundPool *cjSoundPool = FFIData::Create<CJSoundPool>();
    if (cjSoundPool == nullptr) {
        MEDIA_LOGE("No memory!");
        errorcode = MSERR_EXT_API9_NO_MEMORY;
        return -1;
    }
    AudioStandard::AudioRendererInfo rendererInfo;
    rendererInfo.contentType = AudioStandard::CONTENT_TYPE_UNKNOWN;
    rendererInfo.streamUsage = static_cast<AudioStandard::StreamUsage>(info.usage);
    rendererInfo.rendererFlags = info.rendererFlags;

    cjSoundPool->soundPool_ = SoundPoolFactory::CreateSoundPool(maxStreams, rendererInfo);
    if (cjSoundPool->soundPool_ == nullptr) {
        delete cjSoundPool;
        MEDIA_LOGE("failed to CreateSoundPool");
        return -1;
    }

    if (cjSoundPool->callbackCj_ == nullptr && cjSoundPool->soundPool_ != nullptr) {
        cjSoundPool->callbackCj_ = std::make_shared<CJSoundPoolCallBack>();
        (void)cjSoundPool->soundPool_->SetSoundPoolCallback(cjSoundPool->callbackCj_);
    }
    MEDIA_LOGI("Constructor success");
    return cjSoundPool->GetID();
}

int32_t CJSoundPool::Load(std::shared_ptr<ISoundPool> soundPool, char *uri, int32_t &errorcode)
{
    int32_t soundID = soundPool->Load(uri);
    if (soundID < 0) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return soundID;
}

int32_t CJSoundPool::Load(std::shared_ptr<ISoundPool> soundPool, int32_t fd, int64_t offset, int64_t length,
    int32_t &errorcode)
{
    int32_t soundID = soundPool->Load(fd, offset, length);
    if (soundID < 0) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return soundID;
}

int32_t CJSoundPool::Play(std::shared_ptr<ISoundPool> soundPool, int32_t soundID, int32_t &errorcode)
{
    PlayParams params;
    params.cacheDir = "/data/storage/el2/base/temp";
    if (soundID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return -1;
    }
    int32_t streamID = soundPool->Play(soundID, params);
    if (streamID < 0) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return streamID;
}

int32_t CJSoundPool::Play(std::shared_ptr<ISoundPool> soundPool, int32_t soundID, CPlayParameters cParams,
    int32_t &errorcode)
{
    PlayParams params;
    params.loop = cParams.loop;
    params.rate = cParams.rate;
    params.leftVolume = cParams.leftVolume;
    params.rightVolume = cParams.rightVolume;
    params.priority = cParams.priority;
    params.cacheDir = "/data/storage/el2/base/temp";
    if (soundID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return -1;
    }
    int32_t streamID = soundPool->Play(soundID, params);
    if (streamID < 0) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return streamID;
}

int32_t CJSoundPool::Stop(std::shared_ptr<ISoundPool> soundPool, int32_t streamID)
{
    int32_t errorcode = MSERR_OK;
    if (streamID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return errorcode;
    }
    errorcode = soundPool->Stop(streamID);
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::SetLoop(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t loop)
{
    int32_t errorcode = MSERR_OK;
    if (streamID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return errorcode;
    }
    errorcode = soundPool->SetLoop(streamID, loop);
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::SetPriority(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t priority)
{
    int32_t errorcode = MSERR_OK;
    if (streamID <= 0 || priority < 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return errorcode;
    }
    errorcode = soundPool->SetPriority(streamID, priority);
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::SetRate(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t rate)
{
    int32_t errorcode = MSERR_OK;
    if (streamID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return errorcode;
    }
    errorcode = soundPool->SetRate(streamID, static_cast<AudioStandard::AudioRendererRate>(rate));
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::SetVolume(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, float leftVolume,
    float rightVolume)
{
    int32_t errorcode = MSERR_OK;
    if (streamID <= 0) {
        errorcode = MSERR_EXT_API9_INVALID_PARAMETER;
        return errorcode;
    }
    errorcode = soundPool->SetVolume(streamID, leftVolume, rightVolume);
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::Unload(std::shared_ptr<ISoundPool> soundPool, int32_t soundID)
{
    int32_t errorcode = MSERR_OK;
    if (soundID <= 0) {
        errorcode = MSERR_EXT_API9_IO;
        return errorcode;
    }
    errorcode = soundPool->Unload(soundID);
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

int32_t CJSoundPool::Release(std::shared_ptr<ISoundPool> soundPool)
{
    int32_t errorcode = MSERR_OK;
    errorcode = soundPool->Release();
    if (errorcode != MSERR_OK) {
        errorcode = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    return errorcode;
}

} // namespace Media
} // namespace OHOS
