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

#include <string>
#include "cj_soundpool.h"
#include "cj_soundpool_callback.h"
#include "soundpool_ffi.h"

namespace OHOS {
namespace Media {
using namespace OHOS::FFI;

extern "C"
{
    int64_t FfiSoundPoolCreateSoundPool(int32_t maxStreams, AudioStandard::CAudioRendererInfo info, int32_t *errorcode)
    {
        return CJSoundPool::CreatSoundPool(maxStreams, info, *errorcode);
    }

    int32_t FfiSoundPoolLoadURI(int64_t id, char *uri, int32_t *errorcode)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return -1;
        }
        return cjSoundPool->Load(soundPool_, uri, *errorcode);
    }

    int32_t FfiSoundPoolLoad(int64_t id, int32_t fd, int64_t offset, int64_t length, int32_t *errorcode)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return -1;
        }
        return cjSoundPool->Load(soundPool_, fd, offset, length, *errorcode);
    }

    int32_t FfiSoundPoolPlayParam(int64_t id, int32_t soundID, CPlayParameters params, int32_t *errorcode)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return -1;
        }
        return cjSoundPool->Play(soundPool_, soundID, params, *errorcode);
    }

    int32_t FfiSoundPoolPlay(int64_t id, int32_t soundID, int32_t *errorcode)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return -1;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return -1;
        }
        return cjSoundPool->Play(soundPool_, soundID, *errorcode);
    }

    int32_t FfiSoundPoolStop(int64_t id, int32_t streamID)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->Stop(soundPool_, streamID);
    }

    int32_t FfiSoundPoolSetLoop(int64_t id, int32_t streamID, int32_t loop)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->SetLoop(soundPool_, streamID, loop);
    }

    int32_t FfiSoundPoolSetPriority(int64_t id, int32_t streamID, int32_t priority)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->SetLoop(soundPool_, streamID, priority);
    }

    int32_t FfiSoundPoolSetRate(int64_t id, int32_t streamID, int32_t rate)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->SetRate(soundPool_, streamID, rate);
    }

    int32_t FfiSoundPoolSetVolume(int64_t id, int32_t streamID, float leftVolume, float rightVolume)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->SetVolume(soundPool_, streamID, leftVolume, rightVolume);
    }

    int32_t FfiSoundPoolUnload(int64_t id, int32_t soundID)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->Unload(soundPool_, soundID);
    }

    int32_t FfiSoundPoolRelease(int64_t id)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return ERR_INVALID_INSTANCE_CODE;
        }
        return cjSoundPool->Release(soundPool_);
    }

    void FfiSoundPoolOnLoadCompleted(int64_t id, int64_t callbackId)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return;
        }
        if (!cjSoundPool->callbackCj_) {
            MEDIA_LOGE("[CJSoundPool] callbackCj_ is nullptr!");
            return;
        }
        auto Cb_ = std::static_pointer_cast<CJSoundPoolCallBack>(cjSoundPool->callbackCj_);
        Cb_->InitLoadCompleted(callbackId);
        return;
    }

    void FfiSoundPoolOnPlayFinished(int64_t id, int64_t callbackId)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return;
        }
        if (!cjSoundPool->callbackCj_) {
            MEDIA_LOGE("[CJSoundPool] callbackCj_ is nullptr!");
            return;
        }
        auto Cb_ = std::static_pointer_cast<CJSoundPoolCallBack>(cjSoundPool->callbackCj_);
        Cb_->InitPlayFinished(callbackId);
        return;
    }

    void FfiSoundPoolOnError(int64_t id, int64_t callbackId)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return;
        }
        if (!cjSoundPool->callbackCj_) {
            MEDIA_LOGE("[CJSoundPool] callbackCj_ is nullptr!");
            return;
        }
        auto Cb_ = std::static_pointer_cast<CJSoundPoolCallBack>(cjSoundPool->callbackCj_);
        Cb_->InitError(callbackId);
        return;
    }

    void FfiSoundPoolOff(int64_t id, int8_t type)
    {
        auto cjSoundPool = FFIData::GetData<CJSoundPool>(id);
        if (!cjSoundPool) {
            MEDIA_LOGE("[CJSoundPool] instance is nullptr!");
            return;
        }
        std::shared_ptr<ISoundPool> soundPool_ = cjSoundPool->soundPool_;
        if (!soundPool_) {
            MEDIA_LOGE("[CJSoundPool] soundPool_ is nullptr!");
            return;
        }
        if (!cjSoundPool->callbackCj_) {
            MEDIA_LOGE("[CJSoundPool] callbackCj_ is nullptr!");
            return;
        }
        auto Cb_ = std::static_pointer_cast<CJSoundPoolCallBack>(cjSoundPool->callbackCj_);
        Cb_->UnRegister(type);
        return;
    }
}

} // namespace Media
} // namespace OHOS