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

#ifndef CJ_AUDIO_HAPTIC_MANAGER_H
#define CJ_AUDIO_HAPTIC_MANAGER_H

#include <cstdint>
#include "audio_haptic_manager.h"
#include "audio_info.h"
#include "cj_lambda.h"
#include "cj_common_ffi.h"

namespace OHOS {
namespace Media {

class CjAudioHapticManager : public OHOS::FFI::FFIData {
    DECL_TYPE(CjAudioHapticManager, OHOS::FFI::FFIData)
public:
    CjAudioHapticManager();
    ~CjAudioHapticManager();

    int32_t RegisterSource(const char* audioUri, const char* hapticUri, int32_t& resId);
    int32_t UnregisterSource(int32_t id);
    int32_t SetAudioLatencyMode(int32_t id, int32_t latencyMode);
    int32_t SetStreamUsage(int32_t id, int32_t streamUsage);
    int64_t CreatePlayer(int32_t id, bool muteAudio, bool muteHaptics, int32_t &errCode);

private:
    static bool IsLegalAudioLatencyMode(int32_t latencyMode);
    static bool IsLegalAudioStreamUsage(int32_t streamUsage);

    std::shared_ptr<AudioHapticManager> audioHapticMgrClient_ = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_AUDIO_HAPTIC_MANAGER_H
