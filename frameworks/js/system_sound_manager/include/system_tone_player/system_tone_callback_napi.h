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

#ifndef SYSTEM_TONE_PLAYER_CALLBACK_NAPI_H
#define SYSTEM_TONE_PLAYER_CALLBACK_NAPI_H

#include "system_tone_player.h"
#include "common_napi.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
class SystemTonePlayerCallbackNapi : public SystemTonePlayerFinishedAndErrorCallback {
public:
    explicit SystemTonePlayerCallbackNapi(napi_env env);
    virtual ~SystemTonePlayerCallbackNapi();
    void SavePlayFinishedCallbackReference(const std::string &callbackName, napi_value args, int32_t streamId);
    void SaveCallbackReference(const std::string &callbackName, napi_value args);
    void RemovePlayFinishedCallbackReference(int32_t streamId);
    void RemoveCallbackReference(const std::string &callbackName, const napi_value &args);
    void OnEndOfStream(int32_t streamId) override;
    void OnError(int32_t errorCode) override;

private:
    struct SystemTonePlayerJsCallback {
        std::shared_ptr<AutoRef> callback = nullptr;
        std::string callbackName = "unknown";
        int32_t streamId = 0;
        int32_t errorCode = 0;
        std::string errorMsg = "error";
    };

    bool IsSameCallback(std::shared_ptr<AutoRef> cb, const napi_value args);
    bool IsExistCallback(const std::list<std::shared_ptr<AutoRef>> &cbList, const napi_value args);
    void ProcessFinishedCallbacks(int32_t listenerId, int32_t streamId);
    void OnJsCallbackPlayFinished(std::shared_ptr<SystemTonePlayerJsCallback> &jsCb);
    void OnJsCallbackError(std::shared_ptr<SystemTonePlayerJsCallback> &jsCb);

    std::mutex mutex_;
    napi_env env_ = nullptr;
    std::map<int32_t, std::list<std::shared_ptr<AutoRef>>> playFinishedCallbackMap_;
    std::list<std::shared_ptr<AutoRef>> errorCallback_;
};
} // namespace Media
} // namespace OHOS
#endif // SYSTEM_TONE_PLAYER_CALLBACK_NAPI_H
