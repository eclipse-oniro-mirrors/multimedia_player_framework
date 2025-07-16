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

#ifndef AUDIO_HAPTIC_PLAYER_CALLBACK_TAIHE_H
#define AUDIO_HAPTIC_PLAYER_CALLBACK_TAIHE_H

#include <mutex>

#include "audio_haptic_common_taihe.h"
#include "audio_haptic_player.h"
#include "audio_info.h"
#include "common_taihe.h"
#include "event_handler.h"

namespace ANI::Media {

class AudioHapticPlayerCallbackTaihe : public OHOS::Media::AudioHapticPlayerCallback {
public:
    AudioHapticPlayerCallbackTaihe();
    ~AudioHapticPlayerCallbackTaihe();
    void SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> callback);
    void RemoveCallbackReference(const std::string &callbackName);

    void OnInterrupt(const OHOS::AudioStandard::InterruptEvent &interruptEvent) override;
    void OnEndOfStream(void) override;
    void OnError(int32_t errorCode) override;

    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
private:
    struct AudioHapticPlayerTaiheCallback {
        std::shared_ptr<AutoRef> callback = nullptr;
        std::string callbackName = "unknown";
        OHOS::AudioStandard::InterruptEvent interruptEvent;
    };

    void OnInterruptTaiheCallback(std::unique_ptr<AudioHapticPlayerTaiheCallback> &cb);
    void OnEndOfStreamTaiheCallback(std::unique_ptr<AudioHapticPlayerTaiheCallback> &cb);

    std::mutex cbMutex_;
    std::shared_ptr<AutoRef> audioInterruptCb_ = nullptr;
    std::shared_ptr<AutoRef> endOfStreamCb_ = nullptr;
};

} // namespace ANI::Media

#endif // AUDIO_HAPTIC_PLAYER_CALLBACK_TAIHE_H