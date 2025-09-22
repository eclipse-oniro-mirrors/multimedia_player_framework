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
#ifndef AVTRANSCODER_CALLBACK_TAIHE_H
#define AVTRANSCODER_CALLBACK_TAIHE_H

#include "transcoder.h"
#include "av_common.h"
#include "media_errors.h"
#include "scope_guard.h"
#include "avtranscoder_taihe.h"
#include "media_ani_common.h"
#include "event_handler.h"
namespace ANI {
namespace Media {
class AVTransCoderCallback : public TransCoderCallback {
public:
    AVTransCoderCallback() = default;
    ~AVTransCoderCallback() = default;
    std::string GetState();
    void SendStateCallback(const std::string &state, const OHOS::Media::StateChangeReason &reason);
    void CancelCallbackReference(const std::string &name);
    void ClearCallbackReference();

    void SendCompleteCallback();
    void SendProgressUpdateCallback(int32_t progress);
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void SendErrorCallback(MediaServiceExtErrCodeAPI9 errCode, const std::string &msg);
protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

private:
    struct AVTransCoderTaiheCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        std::string errorMsg = "unknown";
        int32_t errorCode = MSERR_EXT_UNKNOWN;
        int32_t reason = 1;
        std::string state = "unknown";
        int32_t progress;
    };
    void OnTaiheErrorCallBack(AVTransCoderTaiheCallback *taiheCb) const;
    void OnTaiheProgressUpdateCallback(AVTransCoderTaiheCallback *taiheCb) const;
    void OnTaiheCompleteCallBack(AVTransCoderTaiheCallback *taiheCb) const;
    std::mutex mutex_;
    std::string currentState_ = AVTransCoderState::STATE_IDLE;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};

}
}
#endif // AVTRANSCODER_CALLBACK_TAIHE_H