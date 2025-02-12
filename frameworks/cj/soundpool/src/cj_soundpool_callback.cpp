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

#include "cj_lambda.h"
#include "cj_soundpool_callback.h"
#include "media_core.h"

namespace OHOS {
namespace Media {

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char *res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

void CJSoundPoolCallBack::UnRegister(int8_t type)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    switch (type) {
        case EVENT_LOAD_COMPLETED:
            onLoadCompleted = nullptr;
            break;
        case EVENT_PLAY_FINISHED:
            onPlayFinished = nullptr;
            break;
        case EVENT_ERROR:
            onError = nullptr;
            break;
        default:
            return;
    }
}

void CJSoundPoolCallBack::InitLoadCompleted(int64_t id)
{
    auto callback = reinterpret_cast<void (*)(const int32_t)>(id);
    onLoadCompleted = [lambda = CJLambda::Create(callback)](int32_t sourceId) -> void {
        lambda(sourceId);
    };
}

void CJSoundPoolCallBack::OnLoadCompleted(int32_t soundId)
{
    if (onLoadCompleted == nullptr) {
        MEDIA_LOGD("onLoadCompleted null");
        return;
    }

    MEDIA_LOGD("onLoadCompleted runs");
    return onLoadCompleted(soundId);
}

void CJSoundPoolCallBack::InitPlayFinished(int64_t id)
{
    auto callback = reinterpret_cast<void (*)()>(id);
    onPlayFinished = [lambda = CJLambda::Create(callback)]() -> void {
        lambda();
    };
}

void CJSoundPoolCallBack::OnPlayFinished(int32_t streamID)
{
    if (onPlayFinished == nullptr) {
        MEDIA_LOGD("onPlayFinished null");
        return;
    }

    MEDIA_LOGD("onPlayFinished runs");
    return onPlayFinished();
}

void CJSoundPoolCallBack::InitError(int64_t id)
{
    auto callback = reinterpret_cast<void (*)(const CJException)>(id);
    onError = [lambda = CJLambda::Create(callback)](CJException value) -> void {
        lambda(value);
    };
}

void CJSoundPoolCallBack::OnError(int32_t errorCode)
{
    if (onError == nullptr) {
        MEDIA_LOGD("onError null");
        return;
    }

    MEDIA_LOGI("OnError recived:error:%{public}d", errorCode);
    CJException exception;
    if (errorCode == MSERR_INVALID_OPERATION) {
        exception.code = MSERR_EXT_API9_OPERATE_NOT_PERMIT;
        exception.msg = MallocCString("The soundpool timed out. Please confirm that the input stream is normal.");
    } else if (errorCode == MSERR_NO_MEMORY) {
        exception.code = MSERR_EXT_API9_NO_MEMORY;
        exception.msg = MallocCString("soundpool memery error.");
    } else if (errorCode == MSERR_SERVICE_DIED) {
        exception.code = MSERR_EXT_API9_SERVICE_DIED;
        exception.msg = MallocCString("releated server died");
    } else {
        exception.code = MSERR_EXT_API9_IO;
        exception.msg = MallocCString("IO error happened.");
    }

    return onError(exception);
}

} // namespace Media
} // namespace OHOS