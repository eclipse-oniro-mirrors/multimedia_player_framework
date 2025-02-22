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

#ifndef CJ_SOUNDPOOLCALLBACK_H
#define CJ_SOUNDPOOLCALLBACK_H

#include <mutex>
#include <shared_mutex>
#include "isoundpool.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SOUNDPOOL, "CJSoundPoolCallback"};
}

const int8_t EVENT_LOAD_COMPLETED = 0;
const int8_t EVENT_PLAY_FINISHED = 1;
const int8_t EVENT_ERROR = 2;

struct CJException {
    int32_t code;
    char *msg;
};

class CJSoundPoolCallBack : public ISoundPoolCallback {
public:
    CJSoundPoolCallBack() = default;
    ~CJSoundPoolCallBack() = default;
    void UnRegister(int8_t type);
    void InitLoadCompleted(int64_t sourceId);
    void InitPlayFinished(int64_t id);
    void InitError(int64_t id);

protected:
    void OnLoadCompleted(int32_t soundId) override;
    void OnPlayFinished(int32_t streamID) override;
    void OnError(int32_t errorCode) override;

private:
    std::function<void(int32_t sourceId)> onLoadCompleted;
    std::function<void()> onPlayFinished;
    std::function<void(CJException value)> onError;

    std::recursive_mutex mutex_;
    static std::mutex callbackMutex_;
    static std::shared_ptr<CJSoundPoolCallBack> callback_;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_SOUNDPOOLCALLBACK_H