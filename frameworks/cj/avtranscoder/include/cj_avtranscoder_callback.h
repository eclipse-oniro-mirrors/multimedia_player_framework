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

#ifndef CJ_AVTRANSCODER_CALLBACK_H
#define CJ_AVTRANSCODER_CALLBACK_H

#include "transcoder.h"
#include "av_common.h"
#include "media_errors.h"
#include "media_log.h"
#include "cj_avtranscoder.h"
#include <shared_mutex>
#include <mutex>

namespace OHOS {
namespace Media {
class CJAVTranscoderCallback : public TransCoderCallback {
public:
    explicit CJAVTranscoderCallback();
    virtual ~CJAVTranscoderCallback();

    void SaveCallbackReference(CJAVTranscoderEvent event, int64_t callbackId);
    void CancelCallbackReference(CJAVTranscoderEvent event);
    void ClearCallbackReference();
    void SendErrorCallback(int32_t errCode, const std::string &msg);
    void SendStateCallback(CjAVTransCoderState state, const StateChangeReason &reason);
    void SendCompleteCallback();
    void SendProgressUpdateCallback(int32_t progress);
    CjAVTransCoderState GetState();

protected:
    void OnError(int32_t errCode, const std::string &errorMsg) override;
    void OnInfo(int32_t type, int32_t extra) override;

private:
    std::mutex mutex_;
    CjAVTransCoderState currentState_ = CjAVTransCoderState::STATE_IDLE;
    std::function<void(int32_t)> onprogressfunc;
    std::function<void(int32_t, const char*)> onerrorfunc;
    std::function<void(void)> oncompletefunc;
};
}
}
#endif