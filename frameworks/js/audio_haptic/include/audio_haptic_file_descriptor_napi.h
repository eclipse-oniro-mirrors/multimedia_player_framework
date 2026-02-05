/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_H
#define AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_H

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
extern const std::string AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_CLASS_NAME;

class AudioHapticFileDescriptorNapi {
public:
    AudioHapticFileDescriptorNapi();
    ~AudioHapticFileDescriptorNapi();

    static napi_value Init(napi_env env, napi_value exports);
    static napi_value CreateAudioHapticFileDescriptorWrapper(napi_env env,
        int32_t fd, int64_t length, int64_t offset);
private:
    static void Destructor(napi_env env, void *nativeObject, void *finalize_hint);
    static napi_value Construct(napi_env env, napi_callback_info info);
    static napi_value GetFd(napi_env env, napi_callback_info info);
    static napi_value SetFd(napi_env env, napi_callback_info info);
    static napi_value GetLength(napi_env env, napi_callback_info info);
    static napi_value SetLength(napi_env env, napi_callback_info info);
    static napi_value GetOffset(napi_env env, napi_callback_info info);
    static napi_value SetOffset(napi_env env, napi_callback_info info);

    static thread_local napi_ref sConstructor_;

    static int32_t sFd_;
    static int64_t sLength_;
    static int64_t sOffset_;

    int32_t fd_ = 0;
    int64_t length_ = 0;
    int64_t offset_ = 0;
    napi_env env_;
};
}
}
#endif // AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_H