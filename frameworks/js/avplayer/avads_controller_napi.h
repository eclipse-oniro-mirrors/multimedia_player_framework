/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef AVADS_CONTROLLER_NAPI_H
#define AVADS_CONTROLLER_NAPI_H

#include <memory>
#include <mutex>
#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "player.h"
#include "common_napi.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {

class AVPlayerNapi;

struct AdsAsyncContext : public MediaAsyncContext {
    explicit AdsAsyncContext(napi_env env) : MediaAsyncContext(env) {}
    ~AdsAsyncContext() = default;

    enum class OpType : uint8_t {
        ADD,
        REMOVE,
        SKIP,
        DISABLE_ALL,
    };

    OpType opType = OpType::ADD;
    std::shared_ptr<AVMediaSource> mediaSource = nullptr;
    int64_t startMs = 0;
    std::string adId;
    std::string outId;
    std::shared_ptr<Player> player = nullptr;
};

class AVAdsControllerNapi {
public:
    __attribute__((visibility("default"))) static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateInstance(napi_env env, AVPlayerNapi *player);

    AVAdsControllerNapi();
    ~AVAdsControllerNapi();

    void SetPlayer(AVPlayerNapi *player);
    AVPlayerNapi *GetPlayer() const;

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);

    static napi_value JsCreateAVAdsController(napi_env env, napi_callback_info info);
    static napi_value JsAddAdsMediaSource(napi_env env, napi_callback_info info);
    static napi_value JsRemoveAdsMediaSource(napi_env env, napi_callback_info info);
    static napi_value JsSkipCurrentAdsMediaSource(napi_env env, napi_callback_info info);
    static napi_value JsDisableAllAdsMediaSource(napi_env env, napi_callback_info info);
    static napi_value JsRelease(napi_env env, napi_callback_info info);
    static napi_value JsOnAdsChange(napi_env env, napi_callback_info info);
    static napi_value JsOffAdsChange(napi_env env, napi_callback_info info);

    static void ExecuteAdsTask(napi_env env, void *data);
    static void CompleteAdsTask(napi_env env, napi_status status, void *data);

    static thread_local napi_ref constructor_;
    AVPlayerNapi *player_ = nullptr;
    mutable std::mutex mutex_;
};

} // namespace Media
} // namespace OHOS

#endif // AVADS_CONTROLLER_NAPI_H
