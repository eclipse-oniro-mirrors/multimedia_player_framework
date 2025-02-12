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

#ifndef CJ_SOUNDPOOL_H
#define CJ_SOUNDPOOL_H

#include "cj_soundpool_callback.h"
#include "ffi_remote_data.h"
#include "isoundpool.h"
#include "multimedia_audio_ffi.h"
#include "media_log.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "CJSoundPool"};
}

struct CPlayParameters {
    int32_t loop = 0;
    int32_t rate = 0; // default AudioRendererRate::RENDER_RATE_NORMAL
    float leftVolume = (float)1.0;
    float rightVolume = (float)1.0;
    int32_t priority = 0;
    bool parallelPlayFlag = false;
    char *cacheDir;
};

namespace OHOS {
namespace Media {

class FFI_EXPORT CJSoundPool : public OHOS::FFI::FFIData {
    DECL_TYPE(CJSoundPool, OHOS::FFI::FFIData)
public:
    static int64_t CreatSoundPool(int32_t maxStreams, AudioStandard::CAudioRendererInfo info, int32_t &errorcode);
    int32_t Load(std::shared_ptr<ISoundPool> soundPool, char *uri, int32_t &errorcode);
    int32_t Load(std::shared_ptr<ISoundPool> soundPool, int32_t fd, int64_t offset, int64_t length, int32_t &errorcode);
    int32_t Play(std::shared_ptr<ISoundPool> soundPool, int32_t soundID, int32_t &errorcode);
    int32_t Play(std::shared_ptr<ISoundPool> soundPool, int32_t soundID, CPlayParameters cParams, int32_t &errorcode);
    int32_t Stop(std::shared_ptr<ISoundPool> soundPool, int32_t streamID);
    int32_t SetLoop(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t loop);
    int32_t SetPriority(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t priority);
    int32_t SetRate(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, int32_t rate);
    int32_t SetVolume(std::shared_ptr<ISoundPool> soundPool, int32_t streamID, float leftVolume, float rightVolume);
    int32_t Unload(std::shared_ptr<ISoundPool> soundPool, int32_t soundID);
    int32_t Release(std::shared_ptr<ISoundPool> soundPool);
    std::shared_ptr<ISoundPool> soundPool_;
    std::shared_ptr<ISoundPoolCallback> callbackCj_;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_SOUNDPOOL_H