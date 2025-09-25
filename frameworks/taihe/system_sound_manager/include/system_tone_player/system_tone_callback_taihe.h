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

#ifndef SYSTEM_TONE_PLAYER_CALLBACK_TAIHE_H
#define SYSTEM_TONE_PLAYER_CALLBACK_TAIHE_H

#include <list>
#include <map>
#include <mutex>

#include "systemTonePlayer.proj.hpp"
#include "systemTonePlayer.impl.hpp"
#include "taihe/runtime.hpp"

#include "common_taihe.h"
#include "event_handler.h"
#include "system_tone_player.h"

namespace ANI::Media {
using namespace taihe;
using namespace systemTonePlayer;

class SystemTonePlayerCallbackTaihe : public OHOS::Media::SystemTonePlayerFinishedAndErrorCallback {
public:
    SystemTonePlayerCallbackTaihe();
    virtual ~SystemTonePlayerCallbackTaihe();
    void SavePlayFinishedCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> autoRef,
        int32_t streamId);
    void SaveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> autoRef);
    void RemovePlayFinishedCallbackReference(int32_t streamId);
    void RemoveCallbackReference(const std::string &callbackName, std::shared_ptr<AutoRef> autoRef);
    void OnEndOfStream(int32_t streamId) override;
    void OnError(int32_t errorCode) override;

private:
    struct SystemTonePlayerTaiheCallback {
        std::shared_ptr<AutoRef> callback = nullptr;
        std::string callbackName = "unknown";
        int32_t streamId = 0;
        int32_t errorCode = 0;
        std::string errorMsg = "error";
    };

    bool IsSameRef(std::shared_ptr<AutoRef> src, std::shared_ptr<AutoRef> dst);
    bool IsExistCallback(const std::list<std::shared_ptr<AutoRef>> &cbList, std::shared_ptr<AutoRef> autoRef);
    void ProcessFinishedCallbacks(int32_t listenerId, int32_t streamId);
    void OnTaiheCallbackPlayFinished(std::shared_ptr<SystemTonePlayerTaiheCallback> &cb);
    void OnTaiheCallbackError(std::shared_ptr<SystemTonePlayerTaiheCallback> &cb);

    std::mutex mutex_;
    std::map<int32_t, std::list<std::shared_ptr<AutoRef>>> playFinishedCallbackMap_;
    std::list<std::shared_ptr<AutoRef>> errorCallback_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
};
} // namespace ANI::Media
#endif // SYSTEM_TONE_PLAYER_CALLBACK_TAIHE_H
