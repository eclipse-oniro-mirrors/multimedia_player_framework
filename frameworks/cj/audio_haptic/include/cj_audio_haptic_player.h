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

#ifndef CJ_AUDIO_HAPTIC_PLAYER_H
#define CJ_AUDIO_HAPTIC_PLAYER_H

#include <cstdint>

#include "audio_info.h"
#include "audio_haptic_player.h"
#include "audio_haptic_log.h"
#include "media_errors.h"
#include "cj_lambda.h"
#include "cj_common_ffi.h"

namespace OHOS {
namespace Media {

const int64_t INVALID_OBJ = -1;
const int32_t INVALID_ID = -1;
const int32_t SUCCESS = 0;
const int32_t ERR_INVALID_ARG = 401;
const int32_t ERR_OPERATE_NOT_ALLOWED = 5400102;
const int32_t ERR_IO_ERROR = 5400103;
const int32_t ERR_UNSUPPORTED_FORMAT = 5400106;

class CjAudioHapticPlayerCallback : public AudioHapticPlayerCallback {
public:
    explicit CjAudioHapticPlayerCallback();
    ~CjAudioHapticPlayerCallback();
    void SaveCallbackReference(const std::string &callbackName, int64_t callbackId);
    void RemoveCallbackReference(const std::string &callbackName);
    void OnInterrupt(const AudioStandard::InterruptEvent &interruptEvent) override;
    void OnEndOfStream(void) override;
    void OnError(int32_t errorCode) override;
private:

    std::mutex cbMutex_;
    std::function<void(int32_t, int32_t, int32_t)> audioInterruptCb_{nullptr};
    std::function<void()> endOfStreamCb_{nullptr};
};

class CjAudioHapticPlayer : public OHOS::FFI::FFIData {
    DECL_TYPE(CjAudioHapticPlayer, OHOS::FFI::FFIData)
public:
    explicit CjAudioHapticPlayer(std::shared_ptr<AudioHapticPlayer> audioHapticPlayer);
    ~CjAudioHapticPlayer();

    int32_t IsMuted(int32_t type, bool &ret);
    int32_t Start();
    int32_t Stop();
    int32_t Release();
    int32_t On(const char* type, int64_t callbackId);
    int32_t Off(const char* type);
private:
    static bool IsLegalAudioHapticType(int32_t audioHapticType);

    std::shared_ptr<AudioHapticPlayer> audioHapticPlayer_ = nullptr;
    std::shared_ptr<CjAudioHapticPlayerCallback> cjCallback = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_AUDIO_HAPTIC_PLAYER_H