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
#ifndef RECODER_CALLBACK_TAIHE_H
#define RECODER_CALLBACK_TAIHE_H

#include "recorder.h"
#include "media_ani_common.h"
#include "event_handler.h"
namespace ANI {
namespace Media {
using namespace OHOS::Media;

const std::string ERROR_CALLBACK_NAME = "error";
const std::string PREPARE_CALLBACK_NAME = "prepare";
const std::string START_CALLBACK_NAME = "start";
const std::string PAUSE_CALLBACK_NAME = "pause";
const std::string RESUME_CALLBACK_NAME = "resume";
const std::string STOP_CALLBACK_NAME = "stop";
const std::string RESET_CALLBACK_NAME = "reset";
const std::string RELEASE_CALLBACK_NAME = "release";
class RecorderCallbackTaihe : public OHOS::Media::RecorderCallback {
public:
    explicit RecorderCallbackTaihe(bool isVideo);
    virtual ~RecorderCallbackTaihe();

    void SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref);
    void ClearCallbackReference();
    void SendErrorCallback(int32_t errCode);
    void SendStateCallback(const std::string &callbackName);
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_ = nullptr;

protected:
    void OnError(OHOS::Media::RecorderErrorType errorType, int32_t errCode) override;
    void OnInfo(int32_t type, int32_t extra) override;
    void OnAudioCaptureChange(const OHOS::Media::AudioRecorderChangeInfo &audioRecorderChangeInfo) override;

private:
    struct RecordTaiheCallback {
        std::weak_ptr<AutoRef> autoRef;
        std::string callbackName = "unknown";
        std::string errorMsg = "unknown";
        int32_t errorCode = MSERR_EXT_UNKNOWN;
    };
    void OnTaiheErrorCallBack(RecordTaiheCallback *taiheCb) const;
    void OnTaiheStateCallBack(RecordTaiheCallback *taiheCb) const;
    std::mutex mutex_;
    std::map<std::string, std::weak_ptr<AutoRef>> refMap_;
    bool isVideo_ = false;
};
}
}
#endif // RECODER_CALLBACK_TAIHE_H