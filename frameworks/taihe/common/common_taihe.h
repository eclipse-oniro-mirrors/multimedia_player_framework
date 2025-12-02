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

#ifndef COMMON_TAIHE_H
#define COMMON_TAIHE_H

#include "audio_info.h"
#include "taihe/runtime.hpp"

namespace ANI::Media {

namespace AVPlayerState {
    const std::string STATE_IDLE = "idle";
    const std::string STATE_INITIALIZED = "initialized";
    const std::string STATE_PREPARED = "prepared";
    const std::string STATE_PLAYING = "playing";
    const std::string STATE_PAUSED = "paused";
    const std::string STATE_STOPPED = "stopped";
    const std::string STATE_RELEASED = "released";
    const std::string STATE_ERROR = "error";
    const std::string STATE_COMPLETED = "completed";
}

class CommonTaihe {
public:
    static void ThrowError(const std::string &errMessage);
    static void ThrowError(int32_t code, const std::string &errMessage);

    static bool VerifySelfSystemPermission();
    static bool VerifyRingtonePermission();

    static ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message);
    static uintptr_t GetUndefinedPtr(ani_env *env);
    static ani_status EnumGetValueInt32(ani_env *env, ani_enum_item enumItem, int32_t &value);
    static ani_status ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptType value, ani_enum_item &aniEnumItem);
    static ani_status ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptForceType value,
        ani_enum_item &aniEnumItem);
    static ani_status ToAniEnum(ani_env *env, OHOS::AudioStandard::InterruptHint value, ani_enum_item &aniEnumItem);
    static ani_object ToAudioStandardInterruptEvent(ani_env *env,
        const OHOS::AudioStandard::InterruptEvent &interruptEvent);
    static ani_status ToAniEnum(ani_env *env, OHOS::AudioStandard::StreamUsage value,
        ani_enum_item &aniEnumItem);
    static ani_status VolumeModeToAniEnum(ani_env *env, int32_t value,
        ani_enum_item &aniEnumItem);
    static ani_object CreateAudioRendererInfo(ani_env *env,
        std::unique_ptr<OHOS::AudioStandard::AudioRendererInfo> &audioRendererInfo);
    static ani_status ToAniLongObject(ani_env *env, int64_t src, ani_object &aniObj);
};

struct AutoRef {
    AutoRef(ani_env *env, std::shared_ptr<uintptr_t> callback)
        : env_(env)
    {
        if (callback != nullptr) {
            callbackRef_ = callback;
        }
    }
    ~AutoRef()
    {
        env_ = nullptr;
        callbackRef_ = nullptr;
    }
    ani_env* env_ = nullptr;
    std::shared_ptr<uintptr_t> callbackRef_;
};

} // namespace ANI::Media
#endif // COMMON_TAIHE_H