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

#include "audio_haptic_file_descriptor_napi.h"
#include "audio_haptic_log.h"

using namespace std;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_AUDIO_NAPI, "AudioHapticFileDescriptorNapi"};
}

namespace OHOS {
namespace Media {
const std::string AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_CLASS_NAME = "AudioHapticFileDescriptor";
thread_local napi_ref AudioHapticFileDescriptorNapi::sConstructor_ = nullptr;

int32_t AudioHapticFileDescriptorNapi::sFd_ = 0;
int64_t AudioHapticFileDescriptorNapi::sLength_ = 0;
int64_t AudioHapticFileDescriptorNapi::sOffset_ = 0;

AudioHapticFileDescriptorNapi::AudioHapticFileDescriptorNapi() : env_(nullptr)
{
}

AudioHapticFileDescriptorNapi::~AudioHapticFileDescriptorNapi() = default;

void AudioHapticFileDescriptorNapi::Destructor(napi_env env, void *nativeObject, void *finalize_hint)
{
    if (nativeObject != nullptr) {
        auto obj = static_cast<AudioHapticFileDescriptorNapi *>(nativeObject);
        delete obj;
        obj = nullptr;
    }
}

napi_value AudioHapticFileDescriptorNapi::Init(napi_env env, napi_value exports)
{
    napi_status status;
    napi_value constructor;
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_property_descriptor audio_haptic_file_descriptor_properties[] = {
        DECLARE_NAPI_GETTER_SETTER("fd", GetFd, SetFd),
        DECLARE_NAPI_GETTER_SETTER("length", GetLength, SetLength),
        DECLARE_NAPI_GETTER_SETTER("offset", GetOffset, SetOffset)
    };

    status = napi_define_class(env, AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Construct,
        nullptr, sizeof(audio_haptic_file_descriptor_properties) / sizeof(audio_haptic_file_descriptor_properties[0]),
        audio_haptic_file_descriptor_properties, &constructor);
    if (status != napi_ok) {
        return result;
    }

    status = napi_create_reference(env, constructor, 1, &sConstructor_);
    if (status == napi_ok) {
        status = napi_set_named_property(env, exports,
            AUDIO_HAPTIC_FILE_DESCRIPTOR_NAPI_CLASS_NAME.c_str(), constructor);
        if (status == napi_ok) {
            return exports;
        }
    }
    MEDIA_LOGE("Failure in AudioHapticFileDescriptorNapi::Init()");

    return result;
}

napi_value AudioHapticFileDescriptorNapi::Construct(napi_env env, napi_callback_info info)
{
    napi_status status;
    napi_value jsThis = nullptr;
    size_t argCount = 0;

    status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    if (status == napi_ok) {
        unique_ptr<AudioHapticFileDescriptorNapi> obj = make_unique<AudioHapticFileDescriptorNapi>();
        if (obj != nullptr) {
            obj->env_ = env;
            obj->fd_ = sFd_;
            obj->length_ = sLength_;
            obj->offset_ = sOffset_;
            status = napi_wrap(env, jsThis, static_cast<void*>(obj.get()),
                AudioHapticFileDescriptorNapi::Destructor, nullptr, nullptr);
            if (status == napi_ok) {
                obj.release();
                return jsThis;
            }
        }
    }

    MEDIA_LOGE("Failed in AudioHapticFileDescriptorNapi::Construct()!");
    napi_get_undefined(env, &jsThis);

    return jsThis;
}

napi_value AudioHapticFileDescriptorNapi::CreateAudioHapticFileDescriptorWrapper(napi_env env,
    int32_t fd, int64_t length, int64_t offset)
{
    napi_status status;
    napi_value result = nullptr;
    napi_value constructor;

    status = napi_get_reference_value(env, sConstructor_, &constructor);
    if (status == napi_ok) {
        sFd_ = fd;
        sLength_ = length;
        sOffset_ = offset;
        status = napi_new_instance(env, constructor, 0, nullptr, &result);
        if (status == napi_ok) {
            return result;
        }
    }
    MEDIA_LOGE("Failed in CreateAudioHapticFileDescriptorWrapper, %{public}d", status);

    napi_get_undefined(env, &result);

    return result;
}

napi_value AudioHapticFileDescriptorNapi::GetFd(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr) {
        MEDIA_LOGE("GetFd: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        status = napi_create_int32(env, audioHapticFileDescriptorNapi->fd_, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return jsResult;
}

napi_value AudioHapticFileDescriptorNapi::SetFd(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    int32_t fd = 0;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr || args[0] == nullptr) {
        MEDIA_LOGE("SetFd: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
            MEDIA_LOGE("SetFd: failed for wrong data type");
            return jsResult;
        }
    }

    status = napi_get_value_int32(env, args[0], &fd);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        audioHapticFileDescriptorNapi->fd_ = fd;
    }

    return jsResult;
}

napi_value AudioHapticFileDescriptorNapi::GetLength(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr) {
        MEDIA_LOGE("GetLength: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        status = napi_create_int64(env, audioHapticFileDescriptorNapi->length_, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return jsResult;
}

napi_value AudioHapticFileDescriptorNapi::SetLength(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    int64_t length = 0;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr || args[0] == nullptr) {
        MEDIA_LOGE("SetLength: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
            MEDIA_LOGE("SetLength: failed for wrong data type");
            return jsResult;
        }
    }

    status = napi_get_value_int64(env, args[0], &length);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        audioHapticFileDescriptorNapi->length_ = length;
    }

    return jsResult;
}

napi_value AudioHapticFileDescriptorNapi::GetOffset(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 0;
    napi_value jsThis = nullptr;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, nullptr, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr) {
        MEDIA_LOGE("GetOffset: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        status = napi_create_int64(env, audioHapticFileDescriptorNapi->offset_, &jsResult);
        if (status == napi_ok) {
            return jsResult;
        }
    }

    return jsResult;
}

napi_value AudioHapticFileDescriptorNapi::SetOffset(napi_env env, napi_callback_info info)
{
    napi_status status;
    AudioHapticFileDescriptorNapi *audioHapticFileDescriptorNapi = nullptr;
    size_t argc = 1;
    napi_value args[1] = { nullptr };
    napi_value jsThis = nullptr;
    int64_t offset = 0;
    napi_value jsResult = nullptr;
    napi_get_undefined(env, &jsResult);

    status = napi_get_cb_info(env, info, &argc, args, &jsThis, nullptr);
    if (status != napi_ok || jsThis == nullptr || args[0] == nullptr) {
        MEDIA_LOGE("SetOffset: failed for napi_get_cb_info");
        return jsResult;
    }

    status = napi_unwrap(env, jsThis, (void **)&audioHapticFileDescriptorNapi);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        napi_valuetype valueType = napi_undefined;
        if (napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_number) {
            MEDIA_LOGE("SetOffset: failed for wrong data type");
            return jsResult;
        }
    }

    status = napi_get_value_int64(env, args[0], &offset);
    if (status == napi_ok && audioHapticFileDescriptorNapi != nullptr) {
        audioHapticFileDescriptorNapi->offset_ = offset;
    }

    return jsResult;
}
}  // namespace Media
}  // namespace OHOS