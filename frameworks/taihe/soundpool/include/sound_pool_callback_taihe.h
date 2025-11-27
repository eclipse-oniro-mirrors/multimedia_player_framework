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
#ifndef SOUND_POOL_CALLBACK_TAIHE_H
#define SOUND_POOL_CALLBACK_TAIHE_H

#include "media_errors.h"
#include "media_log.h"
#include "isoundpool.h"
#include "media_ani_common.h"
#include "event_handler.h"
namespace ANI {
namespace Media {
using namespace OHOS::Media;

namespace SoundPoolEvent {
    const std::string EVENT_LOAD_COMPLETED = "loadComplete";
    const std::string EVENT_PLAY_FINISHED = "playFinished";
    const std::string EVENT_PLAY_FINISHED_WITH_STREAM_ID = "playFinishedWithStreamId";
    const std::string EVENT_ERROR = "error";
    const std::string EVENT_ERROR_OCCURRED = "errorOccurred";
}

class SoundPoolCallBackTaihe : public OHOS::Media::ISoundPoolCallback {
public:
    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void CancelCallbackReference(const std::string &name);
    void ClearCallbackReference();
    void SendErrorCallback(int32_t errCode, const std::string &msg);
    void SendErrorOccurredCallback(const Format &errorInfo);
    void SendLoadCompletedCallback(int32_t soundId);
    void SendPlayCompletedCallback(int32_t streamID);
    ani_object ToBusinessError(ani_env *env, int32_t code, const std::string &message) const;
    ani_object ToErrorInfo(ani_env *env, const std::pair<int32_t, std::string>& errorPair,
        ERROR_TYPE errorType, int32_t soundId, int32_t streamId) const;
    ani_status ToAniEnum(ani_env *env, ERROR_TYPE errorType, ani_enum_item &aniEnumItem) const;
    ani_object IntToAniObject(ani_env *env, int32_t value) const;
    uintptr_t GetUndefined(ani_env* env) const;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;
protected:
    void OnLoadCompleted(int32_t soundId) override;
    void OnPlayFinished(int32_t streamID) override;
    void OnError(int32_t errorCode) override;
    void OnErrorOccurred(Format &errorInfo) override;

private:
    struct SoundPoolTaiheCallBack {
        void RunJsErrorCallBackTask(SoundPoolTaiheCallBack *event);
        void RunJsloadCompletedCallBackTask(SoundPoolTaiheCallBack *event);
        void RunJsplayCompletedCallBackTask(SoundPoolTaiheCallBack *event);
        void RunJsErrorOccurredCallBackTask(SoundPoolTaiheCallBack *event);
        
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        std::string errorMsg = "unknown";
        int32_t errorCode = MSERR_EXT_UNKNOWN;
        int32_t reason = 1;
        int32_t loadSoundId = 0;
        int32_t playFinishedStreamID = 0;
        ERROR_TYPE errorType = ERROR_TYPE::LOAD_ERROR;
    };
    void OnTaiheErrorCallBack(SoundPoolTaiheCallBack *jsCb) const;
    void OnTaiheErrorOccurredCallBack(SoundPoolTaiheCallBack *jsCb) const;
    void OnTaiheloadCompletedCallBack(SoundPoolTaiheCallBack *jsCb) const;
    void OnTaiheplayCompletedCallBack(SoundPoolTaiheCallBack *jsCb) const;
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
};
}
}
#endif // SOUND_POOL_CALLBACK_TAIHE_H