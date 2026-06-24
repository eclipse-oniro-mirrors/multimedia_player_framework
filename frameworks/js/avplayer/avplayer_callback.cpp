/*
 * Copyright (C) 2022-2026 Huawei Device Co., Ltd.
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

#include <map>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <uv.h>
#include "avplayer_napi.h"
#include "media_errors.h"
#include "media_log.h"
#include "player.h"
#include "scope_guard.h"
#include "event_queue.h"
#include "avplayer_callback.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "AVPlayerCallback" };
constexpr int32_t ARGS_TWO = 2;
constexpr int32_t ARGS_THREE = 3;
constexpr int32_t ARGS_FOUR = 4;
constexpr int32_t ARGS_FIVE = 5;
constexpr int32_t ARGS_SIX = 6;
constexpr int32_t ARGS_SEVEN = 7;
constexpr int32_t ARGS_EIGHT = 8;
constexpr int32_t ARGS_NINE = 9;
constexpr int32_t ARGS_TEN = 10;
constexpr int32_t INDEX_IS_LOCAL_FD = 3;
constexpr int32_t INDEX_VIDEO_WIDTH_BEFORE = 4;
constexpr int32_t INDEX_VIDEO_HEIGHT_BEFORE = 5;
constexpr int32_t INDEX_VIDEO_WIDTH_AFTER = 6;
constexpr int32_t INDEX_VIDEO_HEIGHT_AFTER = 7;
constexpr int32_t INDEX_VIDEO_FRAMERATE_BEFORE = 8;
constexpr int32_t INDEX_VIDEO_FRAMERATE_AFTER = 9;
constexpr int32_t INDEX_AUDIO_CHANNELS_BEFORE = 10;
constexpr int32_t INDEX_AUDIO_CHANNELS_AFTER = 11;
constexpr int32_t INDEX_AUDIO_SAMPLE_RATE_BEFORE = 12;
constexpr int32_t INDEX_AUDIO_SAMPLE_RATE_AFTER = 13;
constexpr int32_t INDEX_STREAM_ID_BEFORE = 14;
constexpr int32_t INDEX_STREAM_ID_AFTER = 15;
constexpr int32_t INDEX_BITRATE_BEFORE = 16;
constexpr int32_t INDEX_BITRATE_AFTER = 17;
constexpr int32_t STRING_INDEX_STREAM_TYPE = 0;
constexpr int32_t STRING_INDEX_CHANGE_REASON = 1;
constexpr int32_t STRING_INDEX_CHANGE_RESULT = 2;
constexpr int32_t STRING_INDEX_AUDIO_LANG_BEFORE = 3;
constexpr int32_t STRING_INDEX_AUDIO_LANG_AFTER = 4;
constexpr int32_t STRING_INDEX_SUBTITLE_LANG_BEFORE = 5;
constexpr int32_t STRING_INDEX_SUBTITLE_LANG_AFTER = 6;
constexpr int32_t STRING_INDEX_AUDIO_MIME_TYPE_BEFORE = 7;
constexpr int32_t STRING_INDEX_AUDIO_MIME_TYPE_AFTER = 8;
constexpr int32_t STRING_INDEX_VIDEO_MIME_TYPE_BEFORE = 9;
constexpr int32_t STRING_INDEX_VIDEO_MIME_TYPE_AFTER = 10;
constexpr int32_t STRING_INDEX_VIDEO_TYPE_BEFORE = 11;
constexpr int32_t STRING_INDEX_VIDEO_TYPE_AFTER = 12;
constexpr int32_t STRING_INDEX_CODECS_BEFORE = 13;
constexpr int32_t STRING_INDEX_CODECS_AFTER = 14;
constexpr int32_t STRING_INDEX_ORIGIN_CODECS_BEFORE = 15;
constexpr int32_t STRING_INDEX_ORIGIN_CODECS_AFTER = 16;
constexpr int32_t VIDEO_TYPE_SDR = 0;
constexpr int32_t VIDEO_TYPE_HDR_VIVID = 1;
constexpr int32_t VIDEO_TYPE_HDR_10 = 2;
constexpr int32_t INTERRUPT_HINT_NONE = 0;
constexpr int32_t INTERRUPT_HINT_RESUME = 1;
constexpr int32_t INTERRUPT_HINT_PAUSE = 2;
constexpr int32_t INTERRUPT_HINT_STOP = 3;
constexpr int32_t INTERRUPT_HINT_DUCK = 4;
constexpr int32_t INTERRUPT_HINT_UNDUCK = 5;

std::string GetVideoTypeStr(int32_t videoType)
{
    switch (videoType) {
        case VIDEO_TYPE_SDR: return "SDR";
        case VIDEO_TYPE_HDR_VIVID: return "HDR_VIVID";
        case VIDEO_TYPE_HDR_10: return "HDR_10";
        default: return "UNKNOWN";
    }
}

std::string GetInterruptHintStr(int32_t interruptHint)
{
    switch (interruptHint) {
        case INTERRUPT_HINT_NONE: return "NONE";
        case INTERRUPT_HINT_RESUME: return "RESUME";
        case INTERRUPT_HINT_PAUSE: return "PAUSE";
        case INTERRUPT_HINT_STOP: return "STOP";
        case INTERRUPT_HINT_DUCK: return "DUCK";
        case INTERRUPT_HINT_UNDUCK: return "UNDUCK";
        default: return "UNKNOWN";
    }
}
}

namespace OHOS {
namespace Media {
class NapiCallback {
public:
    struct Base {
        std::weak_ptr<AutoRef> callback;
        std::string callbackName = "unknown";
        Base() = default;
        virtual ~Base() = default;
        virtual void UvWork()
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            // Call back function
            napi_value result = nullptr;
            status = napi_call_function(ref->env_, nullptr, jsCallback, 0, nullptr, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
        virtual void JsCallback()
        {
            UvWork();
            delete this;
        }
    };

    struct Error : public Base {
        std::string errorMsg = "unknown";
        MediaServiceExtErrCodeAPI9 errorCode = MSERR_EXT_API9_UNSUPPORT_FORMAT;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> errorRef = callback.lock();
            CHECK_AND_RETURN_LOG(errorRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(errorRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(errorRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status napiStatus = napi_get_reference_value(errorRef->env_, errorRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr};
            (void)CommonNapi::CreateError(errorRef->env_, errorCode, errorMsg, args[0]);

            // Call back function
            napi_value result = nullptr;
            napiStatus = napi_call_function(errorRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(napiStatus == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct Int : public Base {
        int32_t value = 0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intRef = callback.lock();
            CHECK_AND_RETURN_LOG(intRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(intRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(intRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(intRef->env_, intRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr}; // callback: (int)
            (void)napi_create_int32(intRef->env_, value, &args[0]);

            napi_value result = nullptr;
            status = napi_call_function(intRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct String : public Base {
        std::string value;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stringRef = callback.lock();
            CHECK_AND_RETURN_LOG(stringRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(stringRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(stringRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(stringRef->env_, stringRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value jsValue = nullptr;
            status = napi_create_string_utf8(stringRef->env_, value.c_str(), NAPI_AUTO_LENGTH, &jsValue);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_create_string_utf8", callbackName.c_str());

            napi_value args[1] = {jsValue}; // callback: (string)

            napi_value result = nullptr;
            status = napi_call_function(stringRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct IntVec : public Base {
        std::vector<int32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intVecRef = callback.lock();
            CHECK_AND_RETURN_LOG(intVecRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(intVecRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(intVecRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(intVecRef->env_, intVecRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[2] = {nullptr}; // callback: (int, int)
            (void)napi_create_int32(intVecRef->env_, valueVec[0], &args[0]);
            (void)napi_create_int32(intVecRef->env_, valueVec[1], &args[1]);

            const int32_t argCount = static_cast<int32_t>(valueVec.size());
            napi_value result = nullptr;
            status = napi_call_function(intVecRef->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct IntArray : public Base {
        std::vector<int32_t> valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> intArrayRef = callback.lock();
            CHECK_AND_RETURN_LOG(intArrayRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(intArrayRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(intArrayRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(intArrayRef->env_, intArrayRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value array = nullptr;
            (void)napi_create_array_with_length(intArrayRef->env_, valueVec.size(), &array);

            for (uint32_t i = 0; i < valueVec.size(); i++) {
                napi_value number = nullptr;
                (void)napi_create_int32(intArrayRef->env_, valueVec.at(i), &number);
                (void)napi_set_element(intArrayRef->env_, array, i, number);
            }

            napi_value result = nullptr;
            napi_value args[1] = {array};
            status = napi_call_function(intArrayRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct Double : public Base {
        double value = 0.0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> doubleRef = callback.lock();
            CHECK_AND_RETURN_LOG(doubleRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(doubleRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(doubleRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(doubleRef->env_, doubleRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr};
            (void)napi_create_double(doubleRef->env_, value, &args[0]);

            napi_value result = nullptr;
            status = napi_call_function(doubleRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct FloatArray : public Base {
        std::vector<float>valueVec;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> floatArrayRef = callback.lock();
            CHECK_AND_RETURN_LOG(floatArrayRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(floatArrayRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(floatArrayRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(floatArrayRef->env_, floatArrayRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value array = nullptr;
            (void)napi_create_array_with_length(floatArrayRef->env_, valueVec.size(), &array);

            for (uint32_t i = 0; i < valueVec.size(); i++) {
                napi_value number = nullptr;
                (void)napi_create_double(floatArrayRef->env_, valueVec.at(i), &number);
                (void)napi_set_element(floatArrayRef->env_, array, i, number);
            }

            napi_value result = nullptr;
            napi_value args[1] = {array};
            status = napi_call_function(floatArrayRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct Bool : public Base {
        bool value = false;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> boolRef = callback.lock();
            CHECK_AND_RETURN_LOG(boolRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(boolRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(boolRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(boolRef->env_, boolRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr}; // callback: (boolean)
            (void)napi_get_boolean(boolRef->env_, value, &args[0]);

            napi_value result = nullptr;
            status = napi_call_function(boolRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

struct MetricsEvent : public Base {
        std::vector<int64_t> valueVec;
        std::vector<std::string> stringVec;

        void FillLoadingRateChangeDetails(napi_env env, napi_value metric)
        {
            std::map<std::string, int64_t> detailMap = {
                {std::string("bitrate_before"), valueVec[ARGS_THREE]},
                {std::string("bitrate_after"), valueVec[ARGS_FOUR]},
            };
            (void)CommonNapi::SetPropertyMap(env, metric, "details", detailMap);
        }

        void FillLoadingErrorDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (stringVec.size() >= 1) {
                (void)CommonNapi::SetPropertyString(env, details, "request_stage", stringVec[0]);
            }
            (void)CommonNapi::SetPropertyInt64(env, details, "request_timestamp", valueVec[ARGS_THREE]);
            (void)CommonNapi::SetPropertyInt64(env, details, "error_code", valueVec[ARGS_FOUR]);
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillContentChangedDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (valueVec.size() <= ARGS_THREE) {
                napi_value detailsKey = nullptr;
                napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
                napi_set_property(env, metric, detailsKey, details);
                return;
            }
            bool isLocalFd = (valueVec[INDEX_IS_LOCAL_FD] == 1);
            if (stringVec.size() >= ARGS_THREE) {
                if (!isLocalFd) {
                    (void)CommonNapi::SetPropertyString(env, details, "stream_type",
                        stringVec[STRING_INDEX_STREAM_TYPE]);
                }
                (void)CommonNapi::SetPropertyString(env, details, "change_reason",
                    stringVec[STRING_INDEX_CHANGE_REASON]);
                (void)CommonNapi::SetPropertyString(env, details, "change_result",
                    stringVec[STRING_INDEX_CHANGE_RESULT]);
            }
            if (valueVec.size() > INDEX_AUDIO_SAMPLE_RATE_AFTER) {
                (void)CommonNapi::SetPropertyInt64(env, details, "video_width_before",
                    valueVec[INDEX_VIDEO_WIDTH_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "video_height_before",
                    valueVec[INDEX_VIDEO_HEIGHT_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "video_width_after",
                    valueVec[INDEX_VIDEO_WIDTH_AFTER]);
                (void)CommonNapi::SetPropertyInt64(env, details, "video_height_after",
                    valueVec[INDEX_VIDEO_HEIGHT_AFTER]);
                (void)CommonNapi::SetPropertyInt64(env, details, "video_framerate_before",
                    valueVec[INDEX_VIDEO_FRAMERATE_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "video_framerate_after",
                    valueVec[INDEX_VIDEO_FRAMERATE_AFTER]);
                (void)CommonNapi::SetPropertyInt64(env, details, "audio_channels_before",
                    valueVec[INDEX_AUDIO_CHANNELS_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "audio_channels_after",
                    valueVec[INDEX_AUDIO_CHANNELS_AFTER]);
                (void)CommonNapi::SetPropertyInt64(env, details, "audio_sample_rate_before",
                    valueVec[INDEX_AUDIO_SAMPLE_RATE_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "audio_sample_rate_after",
                    valueVec[INDEX_AUDIO_SAMPLE_RATE_AFTER]);
            }
            if (!isLocalFd && valueVec.size() > INDEX_BITRATE_AFTER) {
                (void)CommonNapi::SetPropertyInt64(env, details, "stream_id_before",
                    valueVec[INDEX_STREAM_ID_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "stream_id_after",
                    valueVec[INDEX_STREAM_ID_AFTER]);
                (void)CommonNapi::SetPropertyInt64(env, details, "bitrate_before",
                    valueVec[INDEX_BITRATE_BEFORE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "bitrate_after",
                    valueVec[INDEX_BITRATE_AFTER]);
            }
            FillContentChangedStringDetails(env, details, isLocalFd);
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillContentChangedStringDetails(napi_env env, napi_value details, bool isLocalFd)
        {
            if (stringVec.size() <= STRING_INDEX_VIDEO_TYPE_AFTER) {
                return;
            }
            (void)CommonNapi::SetPropertyString(env, details, "audio_lang_before",
                stringVec[STRING_INDEX_AUDIO_LANG_BEFORE]);
            (void)CommonNapi::SetPropertyString(env, details, "audio_lang_after",
                stringVec[STRING_INDEX_AUDIO_LANG_AFTER]);
            (void)CommonNapi::SetPropertyString(env, details, "subtitle_lang_before",
                stringVec[STRING_INDEX_SUBTITLE_LANG_BEFORE]);
            (void)CommonNapi::SetPropertyString(env, details, "subtitle_lang_after",
                stringVec[STRING_INDEX_SUBTITLE_LANG_AFTER]);
            (void)CommonNapi::SetPropertyString(env, details, "audio_mime_type_before",
                stringVec[STRING_INDEX_AUDIO_MIME_TYPE_BEFORE]);
            (void)CommonNapi::SetPropertyString(env, details, "audio_mime_type_after",
                stringVec[STRING_INDEX_AUDIO_MIME_TYPE_AFTER]);
            (void)CommonNapi::SetPropertyString(env, details, "video_mime_type_before",
                stringVec[STRING_INDEX_VIDEO_MIME_TYPE_BEFORE]);
            (void)CommonNapi::SetPropertyString(env, details, "video_mime_type_after",
                stringVec[STRING_INDEX_VIDEO_MIME_TYPE_AFTER]);
            (void)CommonNapi::SetPropertyString(env, details, "video_type_before",
                stringVec[STRING_INDEX_VIDEO_TYPE_BEFORE]);
            (void)CommonNapi::SetPropertyString(env, details, "video_type_after",
                stringVec[STRING_INDEX_VIDEO_TYPE_AFTER]);
            
            if (!isLocalFd && stringVec.size() > STRING_INDEX_ORIGIN_CODECS_AFTER) {
                (void)CommonNapi::SetPropertyString(env, details, "codecs_before",
                    stringVec[STRING_INDEX_CODECS_BEFORE]);
                (void)CommonNapi::SetPropertyString(env, details, "codecs_after",
                    stringVec[STRING_INDEX_CODECS_AFTER]);
                (void)CommonNapi::SetPropertyString(env, details, "origin_codecs_before",
                    stringVec[STRING_INDEX_ORIGIN_CODECS_BEFORE]);
                (void)CommonNapi::SetPropertyString(env, details, "origin_codecs_after",
                    stringVec[STRING_INDEX_ORIGIN_CODECS_AFTER]);
            }
        }

        void FillAudioAbnormalDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (stringVec.size() > ARGS_TWO) {
                (void)CommonNapi::SetPropertyString(env, details, "state_before", stringVec[0]);
                (void)CommonNapi::SetPropertyString(env, details, "state_after", stringVec[1]);
                (void)CommonNapi::SetPropertyString(env, details, "interrupt_hint", stringVec[ARGS_TWO]);
            }
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillCodecAbnormalDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (stringVec.size() >= 1) {
                (void)CommonNapi::SetPropertyString(env, details, "decoder_type", stringVec[0]);
            }
            (void)CommonNapi::SetPropertyInt64(env, details, "error_code", valueVec[ARGS_THREE]);
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillContentDiscontinuityDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (stringVec.size() >= ARGS_TWO) {
                (void)CommonNapi::SetPropertyString(env, details, "stream_type", stringVec[0]);
                (void)CommonNapi::SetPropertyString(env, details, "discontinue_type", stringVec[1]);
            }
            if (stringVec.size() > ARGS_FOUR && stringVec[1] == "PTS") {
                (void)CommonNapi::SetPropertyInt64(env, details, "pts_before", valueVec[ARGS_THREE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "pts_after", valueVec[ARGS_FOUR]);
            } else if (stringVec.size() > ARGS_TEN && stringVec[1] == "AUDIO_PARAM") {
                (void)CommonNapi::SetPropertyInt64(env, details, "sample_rate_before", valueVec[ARGS_FIVE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "sample_rate_after", valueVec[ARGS_SIX]);
                (void)CommonNapi::SetPropertyInt64(env, details, "channels_before", valueVec[ARGS_SEVEN]);
                (void)CommonNapi::SetPropertyInt64(env, details, "channels_after", valueVec[ARGS_EIGHT]);
                (void)CommonNapi::SetPropertyInt64(env, details, "sample_format_before", valueVec[ARGS_NINE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "sample_format_after", valueVec[ARGS_TEN]);
            }
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillLipAsyncDetails(napi_env env, napi_value metric)
        {
            napi_value details = nullptr;
            napi_create_object(env, &details);
            if (stringVec.size() >= 1) {
                (void)CommonNapi::SetPropertyString(env, details, "async_type", stringVec[0]);
            }
            if (valueVec.size() >= ARGS_FOUR) {
                (void)CommonNapi::SetPropertyInt64(env, details, "start_time", valueVec[ARGS_THREE]);
                (void)CommonNapi::SetPropertyInt64(env, details, "end_time", valueVec[ARGS_FOUR]);
            }
            napi_value detailsKey = nullptr;
            napi_create_string_utf8(env, "details", NAPI_AUTO_LENGTH, &detailsKey);
            napi_set_property(env, metric, detailsKey, details);
        }

        void FillStallingDetails(napi_env env, napi_value metric)
        {
            std::map<std::string, int64_t> detailMap = {
                {std::string("media_type"), valueVec[ARGS_FOUR]},
                {std::string("duration"), valueVec[ARGS_THREE]}
            };
            (void)CommonNapi::SetPropertyMap(env, metric, "details", detailMap);
        }

        void FillMetricDetails(napi_env env, napi_value metric)
        {
            if (valueVec[0] == AV_METRICS_EVENT_TYPE_LOADINGRATE_CHANGE) {
                FillLoadingRateChangeDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_LOADING_ERROR) {
                FillLoadingErrorDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_CONTENT_CHANGED) {
                FillContentChangedDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_AUDIO_ABNORMAL) {
                FillAudioAbnormalDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_CODEC_ABNORMAL) {
                FillCodecAbnormalDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY) {
                FillContentDiscontinuityDetails(env, metric);
            } else if (valueVec[0] == AV_METRICS_EVENT_TYPE_LIP_ASYNC) {
                FillLipAsyncDetails(env, metric);
            } else {
                FillStallingDetails(env, metric);
            }
        }

    public:
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stallingRef = callback.lock();
            CHECK_AND_RETURN_LOG(stallingRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());
            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(stallingRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(stallingRef->env_, scope);
            };
            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(stallingRef->env_, stallingRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());
            napi_value array = nullptr;
            (void)napi_create_array_with_length(stallingRef->env_, 1, &array);
            napi_value metric = nullptr;
            napi_create_object(stallingRef->env_, &metric);
            (void)CommonNapi::SetPropertyInt32(stallingRef->env_, metric, "event", valueVec[0]);
            (void)CommonNapi::SetPropertyInt64(stallingRef->env_, metric, "timeStamp", valueVec[1]);
            (void)CommonNapi::SetPropertyInt64(stallingRef->env_, metric, "playbackPosition", valueVec[ARGS_TWO]);
            FillMetricDetails(stallingRef->env_, metric);
            (void)napi_set_element(stallingRef->env_, array, 0, metric);
            napi_value result = nullptr;
            napi_value args[1] = {array};
            status = napi_call_function(stallingRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct SubtitleProperty : public Base {
        std::string text;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> subtitleRef = callback.lock();
            CHECK_AND_RETURN_LOG(subtitleRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(subtitleRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(subtitleRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(subtitleRef->env_, subtitleRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            // callback: (textInfo: TextInfoDescriptor)
            napi_value args[1] = {nullptr};
            napi_create_object(subtitleRef->env_, &args[0]);
            (void)CommonNapi::SetPropertyString(subtitleRef->env_, args[0], "text", text);
            napi_value result = nullptr;
            status = napi_call_function(subtitleRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct ObjectArray : public Base {
        std::multimap<std::string, std::vector<uint8_t>> infoMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> mapRef = callback.lock();
            CHECK_AND_RETURN_LOG(mapRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(mapRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(mapRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(mapRef->env_, mapRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            uint32_t index = 0;
            napi_value napiMap;
            napi_create_array_with_length(mapRef->env_, infoMap.size(), &napiMap);
            for (auto item : infoMap) {
                napi_value jsObject;
                napi_value jsUuid;
                napi_value jsPssh;
                napi_create_object(mapRef->env_, &jsObject);
                napi_create_string_utf8(mapRef->env_, item.first.c_str(), NAPI_AUTO_LENGTH, &jsUuid);
                napi_set_named_property(mapRef->env_, jsObject, "uuid", jsUuid);

                status = napi_create_array_with_length(mapRef->env_, item.second.size(), &jsPssh);
                for (uint32_t i = 0; i < item.second.size(); i++) {
                    napi_value number = nullptr;
                    (void)napi_create_uint32(mapRef->env_, item.second[i], &number);
                    (void)napi_set_element(mapRef->env_, jsPssh, i, number);
                }
                napi_set_named_property(mapRef->env_, jsObject, "pssh", jsPssh);
                napi_set_element(mapRef->env_, napiMap, index, jsObject);
                index++;
            }

            const int32_t argCount = 1;
            napi_value args[argCount] = { napiMap };
            napi_value result = nullptr;
            status = napi_call_function(mapRef->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct PropertyInt : public Base {
        std::map<std::string, int32_t> valueMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> propertyIntRef = callback.lock();
            CHECK_AND_RETURN_LOG(propertyIntRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(propertyIntRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(propertyIntRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(propertyIntRef->env_, propertyIntRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr};
            napi_create_object(propertyIntRef->env_, &args[0]);
            for (auto &it : valueMap) {
                CommonNapi::SetPropertyInt32(propertyIntRef->env_, args[0], it.first, it.second);
            }

            napi_value result = nullptr;
            status = napi_call_function(propertyIntRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct StateChange : public Base {
        std::string state = "";
        int32_t reason = 0;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> stateChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(stateChangeRef != nullptr,
                "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(stateChangeRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr,
                "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(stateChangeRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(stateChangeRef->env_, stateChangeRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            const int32_t argCount = 2;
            // callback: (state: AVPlayerState, reason: StateChangeReason)
            napi_value args[argCount] = {nullptr};
            (void)napi_create_string_utf8(stateChangeRef->env_, state.c_str(), NAPI_AUTO_LENGTH, &args[0]);
            (void)napi_create_int32(stateChangeRef->env_, reason, &args[1]);

            napi_value result = nullptr;
            status = napi_call_function(stateChangeRef->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    static void CompleteCallback(napi_env env, NapiCallback::Base *jsCb)
    {
        CHECK_AND_RETURN_LOG(jsCb != nullptr, "jsCb is nullptr");
        napi_status ret = napi_send_event(env, [jsCb] () {
            CHECK_AND_RETURN_LOG(jsCb != nullptr, "Work thread is nullptr");
            MEDIA_LOGD("JsCallBack %{public}s start", jsCb->callbackName.c_str());
            jsCb->UvWork();
            delete jsCb;
        }, napi_eprio_immediate, "AVPlayer CompleteCallback");
        if (ret != napi_ok) {
            MEDIA_LOGE("Failed to execute libuv work queue, ret = %{public}d", ret);
            delete jsCb;
        }
    }

    struct TrackChange : public Base {
        int32_t number = 0;
        bool isSelect = false;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> trackChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(trackChangeRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(trackChangeRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(trackChangeRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(trackChangeRef->env_, trackChangeRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            const int32_t argCount = 2; // 2 prapm, callback: (index: number, isSelect: boolean)
            napi_value args[argCount] = {nullptr};
            (void)napi_create_int32(trackChangeRef->env_, number, &args[0]);
            (void)napi_get_boolean(trackChangeRef->env_, isSelect, &args[1]);

            napi_value result = nullptr;
            status = napi_call_function(trackChangeRef->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok, "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct SubtitleInfo : public Base {
        struct SubtitleParam {
            std::string text;
            int32_t pts;
            int32_t duration;
        } valueMap;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> subtitleRef = callback.lock();
            CHECK_AND_RETURN_LOG(subtitleRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(subtitleRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(subtitleRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(subtitleRef->env_, subtitleRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value args[1] = {nullptr};
            napi_create_object(subtitleRef->env_, &args[0]);
            CommonNapi::SetPropertyString(subtitleRef->env_, args[0], "text", valueMap.text);
            CommonNapi::SetPropertyInt32(subtitleRef->env_, args[0], "startTime", valueMap.pts);
            CommonNapi::SetPropertyInt32(subtitleRef->env_, args[0], "duration", valueMap.duration);
            napi_value result = nullptr;
            status = napi_call_function(subtitleRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok, "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct DeviceChangeNapi : public Base {
        AudioStandard::AudioDeviceDescriptor deviceInfo =
            AudioStandard::AudioDeviceDescriptor(AudioStandard::AudioDeviceDescriptor::DEVICE_INFO);
        int32_t reason;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> deviceChangeRef = callback.lock();
            CHECK_AND_RETURN_LOG(deviceChangeRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(deviceChangeRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(deviceChangeRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(deviceChangeRef->env_, deviceChangeRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            constexpr size_t argCount = 1;
            napi_value args[argCount] = {};
            napi_create_object(deviceChangeRef->env_, &args[0]);
            napi_value deviceObj = nullptr;
            status = CommonNapi::SetValueDeviceInfo(deviceChangeRef->env_, deviceInfo, deviceObj);
            CHECK_AND_RETURN_LOG(status == napi_ok && deviceObj != nullptr,
                " fail to convert to jsobj");
            napi_set_named_property(deviceChangeRef->env_, args[0], "devices", deviceObj);

            bool res = CommonNapi::SetPropertyInt32(deviceChangeRef->env_, args[0], "changeReason",
                static_cast<const int32_t> (reason));
            CHECK_AND_RETURN_LOG(res && deviceObj != nullptr,
                " fail to convert to jsobj");

            napi_value result = nullptr;
            status = napi_call_function(deviceChangeRef->env_, nullptr, jsCallback, argCount, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok, "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct TrackInfoUpdate : public Base {
        std::vector<Format> trackInfo;
        void UvWork() override
        {
            std::shared_ptr<AutoRef> trackInfoRef = callback.lock();
            CHECK_AND_RETURN_LOG(trackInfoRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(trackInfoRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(trackInfoRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(trackInfoRef->env_, trackInfoRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());

            napi_value array = nullptr;
            (void)napi_create_array_with_length(trackInfoRef->env_, trackInfo.size(), &array);

            for (uint32_t i = 0; i < trackInfo.size(); i++) {
                napi_value trackDescription = nullptr;
                trackDescription = CommonNapi::CreateFormatBuffer(trackInfoRef->env_, trackInfo[i]);
                (void)napi_set_element(trackInfoRef->env_, array, i, trackDescription);
            }

            napi_value result = nullptr;
            napi_value args[1] = {array};
            status = napi_call_function(trackInfoRef->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    struct SeiInfoUpadte : public Base {
        int32_t playbackPosition;
        std::vector<Format> payloadGroup;

        void UvWork() override
        {
            std::shared_ptr<AutoRef> seiInfoRef = callback.lock();
            CHECK_AND_RETURN_LOG(seiInfoRef != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(seiInfoRef->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(seiInfoRef->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(seiInfoRef->env_, seiInfoRef->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());
            
            napi_value position = nullptr;
            status = napi_create_int32(seiInfoRef->env_, playbackPosition, &position);
            CHECK_AND_RETURN_LOG(status == napi_ok, "failed to create js number %{public}d", playbackPosition);

            napi_value array = nullptr;
            status = napi_create_array_with_length(seiInfoRef->env_, payloadGroup.size(), &array);
            CHECK_AND_RETURN_LOG(status == napi_ok, "failed to create js array len %{public}zu", payloadGroup.size());
            for (uint32_t i = 0; i < payloadGroup.size(); i++) {
                napi_value seiPayload = nullptr;
                seiPayload = CommonNapi::CreateFormatBuffer(seiInfoRef->env_, payloadGroup[i]);
                status = napi_set_element(seiInfoRef->env_, array, i, seiPayload);
                CHECK_AND_RETURN_LOG(status == napi_ok, "failed to set sei element %{public}d", i);
            }

            napi_value args[ARGS_TWO] = { array, position };
            napi_value result = nullptr;
            status = napi_call_function(seiInfoRef->env_, nullptr, jsCallback, ARGS_TWO, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok,
                "%{public}s failed to napi_call_function", callbackName.c_str());
        }
    };

    /**
     * timedMetaData: callback(info: { id, classify, start, duration, contents })
     */
    struct TimedMetaDataCb : public Base {
        OHOS::Media::AVTimedMetaData meta = {};
        void UvWork() override
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());
            napi_value obj = nullptr;
            napi_create_object(ref->env_, &obj);
            CommonNapi::SetPropertyString(ref->env_, obj, "id", meta.id);
            CommonNapi::SetPropertyString(ref->env_, obj, "classify", meta.classify);
            CommonNapi::SetPropertyInt64(ref->env_, obj, "start", meta.start);
            CommonNapi::SetPropertyInt64(ref->env_, obj, "duration", meta.duration);
            CommonNapi::SetPropertyMap(ref->env_, obj, "contents", meta.contents);
            napi_value args[1] = { obj };
            napi_value result = nullptr;
            status = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok, "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };

    struct AdsChangeCb : public Base {
        OHOS::Media::AVAdsChangeEvent meta = {};
        void UvWork() override
        {
            std::shared_ptr<AutoRef> ref = callback.lock();
            CHECK_AND_RETURN_LOG(ref != nullptr, "%{public}s AutoRef is nullptr", callbackName.c_str());

            napi_handle_scope scope = nullptr;
            napi_open_handle_scope(ref->env_, &scope);
            CHECK_AND_RETURN_LOG(scope != nullptr, "%{public}s scope is nullptr", callbackName.c_str());
            ON_SCOPE_EXIT(0) {
                napi_close_handle_scope(ref->env_, scope);
            };

            napi_value jsCallback = nullptr;
            napi_status status = napi_get_reference_value(ref->env_, ref->cb_, &jsCallback);
            CHECK_AND_RETURN_LOG(status == napi_ok && jsCallback != nullptr,
                "%{public}s failed to napi_get_reference_value", callbackName.c_str());
            napi_value obj = nullptr;
            napi_create_object(ref->env_, &obj);
            CommonNapi::SetPropertyInt32(ref->env_, obj, "type", meta.type);
            CommonNapi::SetPropertyString(ref->env_, obj, "eventId", meta.eventId);
            CommonNapi::SetPropertyInt64(ref->env_, obj, "startMs", meta.startMs);
            CommonNapi::SetPropertyInt64(ref->env_, obj, "durationMs", meta.durationMs);
            CommonNapi::SetPropertyInt32(ref->env_, obj, "reason", meta.reason);
            napi_value args[1] = { obj };
            napi_value result = nullptr;
            status = napi_call_function(ref->env_, nullptr, jsCallback, 1, args, &result);
            CHECK_AND_RETURN_LOG(status == napi_ok, "%{public}s fail to napi_call_function", callbackName.c_str());
        }
    };
};

AVPlayerCallback::AVPlayerCallback(napi_env env, AVPlayerNotify *listener)
    : env_(env), listener_(listener)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
    InitInfoFuncsPart1();
    InitInfoFuncsPart2();
}

void AVPlayerCallback::InitInfoFuncsPart1()
{
    onInfoFuncs_ = {
        { INFO_TYPE_STATE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnStateChangeCb(extra, infoBody); } },
        { INFO_TYPE_VOLUME_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVolumeChangeCb(extra, infoBody); } },
        { INFO_TYPE_SEEKDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSeekDoneCb(extra, infoBody); } },
        { INFO_TYPE_SPEEDDONE,
            [this](const int32_t extra, const Format &infoBody) { OnSpeedDoneCb(extra, infoBody); } },
        { INFO_TYPE_BITRATEDONE,
            [this](const int32_t extra, const Format &infoBody) { OnBitRateDoneCb(extra, infoBody); } },
        { INFO_TYPE_POSITION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnPositionUpdateCb(extra, infoBody); } },
        { INFO_TYPE_DURATION_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnDurationUpdateCb(extra, infoBody); } },
        { INFO_TYPE_BUFFERING_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnBufferingUpdateCb(extra, infoBody); } },
        { INFO_TYPE_MESSAGE,
            [this](const int32_t extra, const Format &infoBody) { OnMessageCb(extra, infoBody);} },
        { INFO_TYPE_RESOLUTION_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnVideoSizeChangedCb(extra, infoBody); } },
        { INFO_TYPE_INTERRUPT_EVENT,
            [this](const int32_t extra, const Format &infoBody) { OnAudioInterruptCb(extra, infoBody); } },
        { INFO_TYPE_BITRATE_COLLECT,
             [this](const int32_t extra, const Format &infoBody) { OnBitRateCollectedCb(extra, infoBody); } },
        { INFO_TYPE_EOS,
            [this](const int32_t extra, const Format &infoBody) { OnEosCb(extra, infoBody); } },
        { INFO_TYPE_IS_LIVE_STREAM,
            [this](const int32_t extra, const Format &infoBody) { NotifyIsLiveStream(extra, infoBody); } },
        { INFO_TYPE_SUBTITLE_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnSubtitleUpdateCb(extra, infoBody); } },
        { INFO_TYPE_TRACKCHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnTrackChangedCb(extra, infoBody); } },
        { INFO_TYPE_TRACK_INFO_UPDATE,
            [this](const int32_t extra, const Format &infoBody) { OnTrackInfoUpdate(extra, infoBody); } },
        { INFO_TYPE_DRM_INFO_UPDATED,
            [this](const int32_t extra, const Format &infoBody) { OnDrmInfoUpdatedCb(extra, infoBody); } },
        { INFO_TYPE_SET_DECRYPT_CONFIG_DONE,
            [this](const int32_t extra, const Format &infoBody) { OnSetDecryptConfigDoneCb(extra, infoBody); } },
        { INFO_TYPE_SUBTITLE_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSubtitleInfoCb(extra, infoBody); } },
        { INFO_TYPE_AUDIO_DEVICE_CHANGE,
            [this](const int32_t extra, const Format &infoBody) { OnAudioDeviceChangeCb(extra, infoBody); } },
        { INFO_TYPE_MAX_AMPLITUDE_COLLECT,
            [this](const int32_t extra, const Format &infoBody) { OnMaxAmplitudeCollectedCb(extra, infoBody); } },
        { INFO_TYPE_SEI_UPDATE_INFO,
            [this](const int32_t extra, const Format &infoBody) { OnSeiInfoCb(extra, infoBody); } },
    };
}

void AVPlayerCallback::InitInfoFuncsPart2()
{
    onInfoFuncs_[INFO_TYPE_SUPER_RESOLUTION_CHANGED] =
        [this](const int32_t extra, const Format &infoBody) { OnSuperResolutionChangedCb(extra, infoBody); };
    onInfoFuncs_[INFO_TYPE_RATEDONE] =
        [this](const int32_t extra, const Format &infoBody) { OnPlaybackRateDoneCb(extra, infoBody); };
    onInfoFuncs_[INFO_TYPE_METRICS_EVENT] =
        [this](const int32_t extra, const Format &infoBody) { OnMetricsEventCb(extra, infoBody); };
    onInfoFuncs_[INFO_TYPE_PLAYBACK_CONTENT_CHANGE] =
        [this](const int32_t extra, const Format &infoBody) { OnPlaybackContentChangeCb(extra, infoBody); };
    onInfoFuncs_[INFO_TYPE_TIMED_META_DATA] =
        [this](const int32_t extra, const Format &infoBody) { OnTimedMetaDataCb(extra, infoBody); };
    onInfoFuncs_[INFO_TYPE_ADS_CHANGE] =
        [this](const int32_t extra, const Format &infoBody) { OnAdsChangeCb(extra, infoBody); };
}

void AVPlayerCallback::OnAudioDeviceChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE) == refMap_.end()) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find audio AudioDeviceChange callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::DeviceChangeNapi *cb = new(std::nothrow) NapiCallback::DeviceChangeNapi();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new DeviceChangeNapi");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_AUDIO_DEVICE_CHANGE;

    uint8_t *parcelBuffer = nullptr;
    size_t parcelSize;
    infoBody.GetBuffer(PlayerKeys::AUDIO_DEVICE_CHANGE, &parcelBuffer, parcelSize);
    Parcel parcel;
    parcel.WriteBuffer(parcelBuffer, parcelSize);
    AudioStandard::AudioDeviceDescriptor deviceInfo(AudioStandard::AudioDeviceDescriptor::DEVICE_INFO);
    deviceInfo.UnmarshallingSelf(parcel);

    int32_t reason;
    infoBody.GetIntValue(PlayerKeys::AUDIO_DEVICE_CHANGE_REASON, reason);

    cb->deviceInfo = deviceInfo;
    cb->reason = reason;

    NapiCallback::CompleteCallback(env_, cb);
}

AVPlayerCallback::~AVPlayerCallback()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

void AVPlayerCallback::OnError(int32_t errorCode, const std::string &errorMsg)
{
    MediaServiceExtErrCodeAPI9 errorCodeApi9 = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(errorCode));
    if (errorCodeApi9 == MSERR_EXT_API9_NO_PERMISSION ||
        errorCodeApi9 == MSERR_EXT_API9_NO_MEMORY ||
        errorCodeApi9 == MSERR_EXT_API9_TIMEOUT ||
        errorCodeApi9 == MSERR_EXT_API9_SERVICE_DIED ||
        errorCodeApi9 == MSERR_EXT_API9_UNSUPPORT_FORMAT) {
        Format infoBody;
        AVPlayerCallback::OnInfo(INFO_TYPE_STATE_CHANGE, PLAYER_STATE_ERROR, infoBody);
    }
    AVPlayerCallback::OnErrorCb(errorCodeApi9, errorMsg);
}

void AVPlayerCallback::OnErrorCb(MediaServiceExtErrCodeAPI9 errorCode, const std::string &errorMsg)
{
    std::string message = MSExtAVErrorToString(errorCode) + errorMsg;
    MEDIA_LOGE("OnErrorCb:errorCode %{public}d, errorMsg %{public}s", errorCode, message.c_str());
    std::lock_guard<std::mutex> lock(mutex_);
    if (refMap_.find(AVPlayerEvent::EVENT_ERROR) == refMap_.end()) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find error callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::Error *cb = new(std::nothrow) NapiCallback::Error();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Error");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_ERROR);
    cb->callbackName = AVPlayerEvent::EVENT_ERROR;
    cb->errorCode = errorCode;
    cb->errorMsg = message;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnInfo(PlayerOnInfoType type, int32_t extra, const Format &infoBody)
{
    if (type == INFO_TYPE_STATE_CHANGE && extra == static_cast<int32_t>(PlayerStates::PLAYER_INITIALIZED)) {
        static constexpr int32_t waitForSetStateChangeCbUs = 3000;
        usleep(waitForSetStateChangeCbUs);
    }
    std::lock_guard<std::mutex> lock(mutex_);
    MEDIA_LOGD("OnInfo is called, PlayerOnInfoType: %{public}d", type);
    if (onInfoFuncs_.count(type) > 0) {
        onInfoFuncs_[type](extra, infoBody);
    } else {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " OnInfo: no member func supporting, %{public}d",
            FAKE_POINTER(this), type);
    }
}

void AVPlayerCallback::NotifyIsLiveStream(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t isFlvLive = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_IS_FLV_LIVE, isFlvLive);
    if (listener_ != nullptr) {
        listener_->NotifyIsLiveStream();
        listener_->NotifyIsFlvLive(isFlvLive);
    }
}

bool AVPlayerCallback::IsValidState(PlayerStates state, std::string &stateStr)
{
    switch (state) {
        case PlayerStates::PLAYER_IDLE:
            stateStr = AVPlayerState::STATE_IDLE;
            break;
        case PlayerStates::PLAYER_INITIALIZED:
            stateStr = AVPlayerState::STATE_INITIALIZED;
            break;
        case PlayerStates::PLAYER_PREPARED:
            stateStr = AVPlayerState::STATE_PREPARED;
            break;
        case PlayerStates::PLAYER_STARTED:
            stateStr = AVPlayerState::STATE_PLAYING;
            break;
        case PlayerStates::PLAYER_PAUSED:
            stateStr = AVPlayerState::STATE_PAUSED;
            break;
        case PlayerStates::PLAYER_STOPPED:
            stateStr = AVPlayerState::STATE_STOPPED;
            break;
        case PlayerStates::PLAYER_PLAYBACK_COMPLETE:
            stateStr = AVPlayerState::STATE_COMPLETED;
            break;
        case PlayerStates::PLAYER_RELEASED:
            stateStr = AVPlayerState::STATE_RELEASED;
            break;
        case PlayerStates::PLAYER_STATE_ERROR:
            stateStr = AVPlayerState::STATE_ERROR;
            break;
        default:
            return false;
    }
    return true;
}

void AVPlayerCallback::OnStateChangeCb(const int32_t extra, const Format &infoBody)
{
    PlayerStates state = static_cast<PlayerStates>(extra);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instance OnStateChanged is called, current state: %{public}d",
        FAKE_POINTER(this), state);

    if (listener_ != nullptr) {
        listener_->NotifyState(state);
    }

    if (state_ != state) {
        state_ = state;
        std::string stateStr;
        if (IsValidState(state, stateStr)) {
            if (refMap_.find(AVPlayerEvent::EVENT_STATE_CHANGE) == refMap_.end()) {
                MEDIA_LOGW("can not find state change callback!");
                return;
            }
            NapiCallback::StateChange *cb = new(std::nothrow) NapiCallback::StateChange();
            CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new StateChange");

            int32_t reason = StateChangeReason::USER;
            if (infoBody.ContainKey(PlayerKeys::PLAYER_STATE_CHANGED_REASON)) {
                (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STATE_CHANGED_REASON, reason);
            }
            cb->callback = refMap_.at(AVPlayerEvent::EVENT_STATE_CHANGE);
            cb->callbackName = AVPlayerEvent::EVENT_STATE_CHANGE;
            cb->state = stateStr;
            cb->reason = reason;
            NapiCallback::CompleteCallback(env_, cb);
        }
    }
}

void AVPlayerCallback::OnVolumeChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    float volumeLevel = 0.0;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_VOLUME_LEVEL, volumeLevel);

    isSetVolume_ = false;
    MEDIA_LOGD("OnVolumeChangeCb in volume=%{public}f", volumeLevel);
    if (refMap_.find(AVPlayerEvent::EVENT_VOLUME_CHANGE) == refMap_.end()) {
        MEDIA_LOGD("can not find vol change callback!");
        return;
    }

    NapiCallback::Double *cb = new(std::nothrow) NapiCallback::Double();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Double");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_VOLUME_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_VOLUME_CHANGE;
    cb->value = static_cast<double>(volumeLevel);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSeekDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t currentPositon = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnSeekDone is called, currentPositon: %{public}d",
        FAKE_POINTER(this), currentPositon);
    if (refMap_.find(AVPlayerEvent::EVENT_SEEK_DONE) == refMap_.end()) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find seekdone callback!", FAKE_POINTER(this));
        return;
    }
    NapiCallback::Int *cb = new(std::nothrow) NapiCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SEEK_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SEEK_DONE;
    cb->value = currentPositon;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSpeedDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t speedMode = extra;
    MEDIA_LOGI("OnSpeedDoneCb is called, speedMode: %{public}d", speedMode);
    if (refMap_.find(AVPlayerEvent::EVENT_SPEED_DONE) == refMap_.end()) {
        MEDIA_LOGW("can not find speeddone callback!");
        return;
    }

    NapiCallback::Int *cb = new(std::nothrow) NapiCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SPEED_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SPEED_DONE;
    cb->value = speedMode;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnPlaybackRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    float speedRate = 0.0f;
    (void)infoBody.GetFloatValue(PlayerKeys::PLAYER_PLAYBACK_RATE, speedRate);
    MEDIA_LOGI("OnPlaybackRateDoneCb is called, speedRate: %{public}f", speedRate);
    if (refMap_.find(AVPlayerEvent::EVENT_RATE_DONE) == refMap_.end()) {
        MEDIA_LOGW("can not find ratedone callback!");
        return;
    }

    NapiCallback::Double *cb = new(std::nothrow) NapiCallback::Double();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new float");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_RATE_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_RATE_DONE;
    cb->value = static_cast<double>(speedRate);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnBitRateDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t bitRate = extra;
    MEDIA_LOGI("OnBitRateDoneCb is called, bitRate: %{public}d", bitRate);
    if (refMap_.find(AVPlayerEvent::EVENT_BITRATE_DONE) == refMap_.end()) {
        MEDIA_LOGW("can not find bitrate callback!");
        return;
    }

    NapiCallback::Int *cb = new(std::nothrow) NapiCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_BITRATE_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_BITRATE_DONE;
    cb->value = bitRate;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnPositionUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t position = extra;
    MEDIA_LOGD("OnPositionUpdateCb is called, position: %{public}d", position);

    if (listener_ != nullptr) {
        listener_->NotifyPosition(position);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_TIME_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("can not find timeupdate callback!");
        return;
    }
    NapiCallback::Int *cb = new(std::nothrow) NapiCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TIME_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_TIME_UPDATE;
    cb->value = position;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnDurationUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t duration = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnDurationUpdateCb is called, duration: %{public}d",
        FAKE_POINTER(this), duration);

    if (listener_ != nullptr) {
        listener_->NotifyDuration(duration);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_DURATION_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find duration update callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::Int *cb = new(std::nothrow) NapiCallback::Int();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Int");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_DURATION_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_DURATION_UPDATE;
    cb->value = duration;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSubtitleUpdateCb(const int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_SUBTITLE_TEXT_UPDATE) == refMap_.end()) {
        MEDIA_LOGW("can not find subtitle update callback!");
        return;
    }
    NapiCallback::SubtitleProperty *cb = new(std::nothrow) NapiCallback::SubtitleProperty();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new SubtitleProperty");
    if (infoBody.ContainKey(PlayerKeys::SUBTITLE_TEXT)) {
        (void)infoBody.GetStringValue(PlayerKeys::SUBTITLE_TEXT, cb->text);
    }
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SUBTITLE_TEXT_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_SUBTITLE_TEXT_UPDATE;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnBufferingUpdateCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_BUFFERING_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("can not find buffering update callback!");
        return;
    }

    int32_t val = 0;
    int32_t bufferingType = -1;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_START))) {
        bufferingType = BUFFERING_START;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_START), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_END))) {
        bufferingType = BUFFERING_END;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_END), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT))) {
        bufferingType = BUFFERING_PERCENT;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_BUFFERING_PERCENT), val);
    } else if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_CACHED_DURATION))) {
        bufferingType = CACHED_DURATION;
        (void)infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_CACHED_DURATION), val);
    } else {
        return;
    }

    MEDIA_LOGD("OnBufferingUpdateCb is called, buffering type: %{public}d value: %{public}d", bufferingType, val);
    NapiCallback::IntVec *cb = new(std::nothrow) NapiCallback::IntVec();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntVec");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_BUFFERING_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_BUFFERING_UPDATE;
    cb->valueVec.push_back(bufferingType);
    cb->valueVec.push_back(val);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnMessageCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    MEDIA_LOGI("OnMessageCb is called, extra: %{public}d", extra);
    if (extra == PlayerMessageType::PLAYER_INFO_VIDEO_RENDERING_START) {
        AVPlayerCallback::OnStartRenderFrameCb();
    }
}

void AVPlayerCallback::OnPlaybackContentChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_PLAYBACK_CONTENT_CHANGE) == refMap_.end()) {
        return;
    }
    std::string changeId;
    if (infoBody.ContainKey(PlayerKeys::PLAYER_LIST_MEDIA_SOURCE_CHANGE_ID)) {
        (void)infoBody.GetStringValue(PlayerKeys::PLAYER_LIST_MEDIA_SOURCE_CHANGE_ID, changeId);
    }
    CHECK_AND_RETURN_LOG(!changeId.empty(), "changeId is empty");

    NapiCallback::String *cb = new(std::nothrow) NapiCallback::String();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new String callback");
    cb->value = changeId;
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_PLAYBACK_CONTENT_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_PLAYBACK_CONTENT_CHANGE;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnStartRenderFrameCb() const
{
    MEDIA_LOGI("OnStartRenderFrameCb is called");
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_START_RENDER_FRAME) == refMap_.end()) {
        MEDIA_LOGW("can not find start render callback!");
        return;
    }

    NapiCallback::Base *cb = new(std::nothrow) NapiCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_START_RENDER_FRAME);
    cb->callbackName = AVPlayerEvent::EVENT_START_RENDER_FRAME;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnVideoSizeChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t width = 0;
    int32_t height = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_WIDTH, width);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_HEIGHT, height);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnVideoSizeChangedCb is called, width = %{public}d, height = %{public}d",
        FAKE_POINTER(this), width, height);

    if (listener_ != nullptr) {
        listener_->NotifyVideoSize(width, height);
    }

    if (refMap_.find(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE) == refMap_.end()) {
        MEDIA_LOGW("can not find video size changed callback!");
        return;
    }
    NapiCallback::IntVec *cb = new(std::nothrow) NapiCallback::IntVec();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntVec");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_VIDEO_SIZE_CHANGE;
    cb->valueVec.push_back(width);
    cb->valueVec.push_back(height);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnAudioInterruptCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AUDIO_INTERRUPT) == refMap_.end()) {
        MEDIA_LOGW("can not find audio interrupt callback!");
        return;
    }

    NapiCallback::PropertyInt *cb = new(std::nothrow) NapiCallback::PropertyInt();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new PropertyInt");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AUDIO_INTERRUPT);
    cb->callbackName = AVPlayerEvent::EVENT_AUDIO_INTERRUPT;
    int32_t eventType = 0;
    int32_t forceType = 0;
    int32_t hintType = 0;
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, eventType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, forceType);
    (void)infoBody.GetIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, hintType);
    MEDIA_LOGI("OnAudioInterruptCb is called, eventType = %{public}d, forceType = %{public}d, hintType = %{public}d",
        eventType, forceType, hintType);
    // ohos.multimedia.audio.d.ts interface InterruptEvent
    cb->valueMap["eventType"] = eventType;
    cb->valueMap["forceType"] = forceType;
    cb->valueMap["hintType"] = hintType;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnBitRateCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AVAILABLE_BITRATES) == refMap_.end()) {
        MEDIA_LOGW("can not find bitrate collected callback!");
        return;
    }

    std::vector<int32_t> bitrateVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES))) {
        uint8_t *addr = nullptr;
        size_t size  = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_AVAILABLE_BITRATES), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "bitrate addr is nullptr");

        MEDIA_LOGI("bitrate size = %{public}zu", size / sizeof(uint32_t));
        while (size > 0) {
            if (size < sizeof(uint32_t)) {
                break;
            }

            uint32_t bitrate = *(static_cast<uint32_t *>(static_cast<void *>(addr)));
            MEDIA_LOGI("bitrate = %{public}u", bitrate);
            addr += sizeof(uint32_t);
            size -= sizeof(uint32_t);
            bitrateVec.push_back(static_cast<int32_t>(bitrate));
        }
    }

    NapiCallback::IntArray *cb = new(std::nothrow) NapiCallback::IntArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AVAILABLE_BITRATES);
    cb->callbackName = AVPlayerEvent::EVENT_AVAILABLE_BITRATES;
    cb->valueVec = bitrateVec;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnMaxAmplitudeCollectedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE) == refMap_.end()) {
        MEDIA_LOGD("can not find max amplitude collected callback!");
        return;
    }

    std::vector<float> MaxAmplitudeVec;
    if (infoBody.ContainKey(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE))) {
        uint8_t *addr = nullptr;
        size_t size  = 0;
        infoBody.GetBuffer(std::string(PlayerKeys::AUDIO_MAX_AMPLITUDE), &addr, size);
        CHECK_AND_RETURN_LOG(addr != nullptr, "max amplitude addr is nullptr");

        MEDIA_LOGD("max amplitude size = %{public}zu", size / sizeof(float));
        while (size > 0) {
            if (size < sizeof(float)) {
                break;
            }

            float maxAmplitude = *(static_cast<float *>(static_cast<void *>(addr)));
            MEDIA_LOGD("maxAmplitude = %{public}f", maxAmplitude);
            addr += sizeof(float);
            size -= sizeof(float);
            MaxAmplitudeVec.push_back(static_cast<float>(maxAmplitude));
        }
    }

    NapiCallback::FloatArray *cb = new(std::nothrow) NapiCallback::FloatArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_AMPLITUDE_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_AMPLITUDE_UPDATE;
    cb->valueVec = MaxAmplitudeVec;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSeiInfoCb(const int32_t extra, const Format &infoBody)
{
    CHECK_AND_RETURN_LOG(
        refMap_.find(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO) != refMap_.end(), "can not find on sei message callback!");

    (void)extra;
    int32_t playbackPosition = 0;
    bool res = infoBody.GetIntValue(Tag::AV_PLAYER_SEI_PLAYBACK_POSITION, playbackPosition);
    CHECK_AND_RETURN_LOG(res, "get playback position failed");

    std::vector<Format> formatVec;
    res = infoBody.GetFormatVector(Tag::AV_PLAYER_SEI_PLAYBACK_GROUP, formatVec);
    CHECK_AND_RETURN_LOG(res, "get sei payload group failed");

    NapiCallback::SeiInfoUpadte *cb = new(std::nothrow) NapiCallback::SeiInfoUpadte();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new IntArray");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SEI_MESSAGE_INFO);
    cb->callbackName = AVPlayerEvent::EVENT_SEI_MESSAGE_INFO;
    cb->playbackPosition = playbackPosition;
    cb->payloadGroup = formatVec;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSuperResolutionChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t enabled = 0;
    (void)infoBody.GetIntValue(PlayerKeys::SUPER_RESOLUTION_ENABLED, enabled);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnSuperResolutionChangedCb is called, enabled = %{public}d",
        FAKE_POINTER(this), enabled);

    if (refMap_.find(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED) == refMap_.end()) {
        MEDIA_LOGW("can not find super resolution changed callback!");
        return;
    }
    NapiCallback::Bool *cb = new(std::nothrow) NapiCallback::Bool();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Bool");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED);
    cb->callbackName = AVPlayerEvent::EVENT_SUPER_RESOLUTION_CHANGED;
    cb->value = enabled ? true : false;
    NapiCallback::CompleteCallback(env_, cb);
}

struct AVPlayerCallback::ContentChangedData {
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string streamType;
    std::string changeReason;
    std::string changeResult;
    bool isLocalFd = false;
    int32_t streamIdBefore = 0;
    int32_t streamIdAfter = 0;
    int64_t bitrateBefore = 0;
    int64_t bitrateAfter = 0;
    int32_t videoWidthBefore = 0;
    int32_t videoHeightBefore = 0;
    int32_t videoWidthAfter = 0;
    int32_t videoHeightAfter = 0;
    int32_t videoFrameRateBefore = 0;
    int32_t videoFrameRateAfter = 0;
    int32_t audioChannelsBefore = 0;
    int32_t audioChannelsAfter = 0;
    int32_t audioSampleRateBefore = 0;
    int32_t audioSampleRateAfter = 0;
    int32_t videoTypeBefore = 0;
    int32_t videoTypeAfter = 0;
    std::string audioLangBefore;
    std::string audioLangAfter;
    std::string subtitleLangBefore;
    std::string subtitleLangAfter;
    std::string audioMimeTypeBefore;
    std::string audioMimeTypeAfter;
    std::string videoMimeTypeBefore;
    std::string videoMimeTypeAfter;
    std::string codecsBefore;
    std::string codecsAfter;
    std::string originCodecsBefore;
    std::string originCodecsAfter;
};

void AVPlayerCallback::FillLoadingRateChangeEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    int64_t bitrateBefore = 0;
    int64_t bitrateAfter = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_LOADING_BITRATE_BEFORE, bitrateBefore);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_LOADING_BITRATE_AFTER, bitrateAfter);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb LOADING_BITRATE, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", bitrateBefore = %{public}" PRId64
        ", bitrateAfter = %{public}" PRId64, FAKE_POINTER(this), timestamp, playbackPosition,
        bitrateBefore, bitrateAfter);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_LOADINGRATE_CHANGE);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->valueVec.push_back(bitrateBefore);
    cb->valueVec.push_back(bitrateAfter);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillLoadingErrorEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string requestStage;
    int64_t requestTimestamp = 0;
    int64_t errorCode = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_REQUEST_STAGE, requestStage);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_REQUEST_TIMESTAMP, requestTimestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_ERROR_CODE, errorCode);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb LOADING_ERROR, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", requestStage = %{public}s"
        ", requestTimestamp = %{public}" PRId64 ", errorCode = %{public}" PRId64,
        FAKE_POINTER(this), timestamp, playbackPosition, requestStage.c_str(), requestTimestamp, errorCode);

    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_LOADING_ERROR);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->stringVec.push_back(requestStage);
    cb->valueVec.push_back(requestTimestamp);
    cb->valueVec.push_back(errorCode);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::ExtractContentChangedData(const Format &infoBody, ContentChangedData &data)
{
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, data.timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, data.playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_MEDIA_STREAM_TYPE, data.streamType);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_CHANGE_REASON, data.changeReason);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_CHANGE_RESULT, data.changeResult);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STREAM_ID_BEFORE, data.streamIdBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STREAM_ID_AFTER, data.streamIdAfter);
    int32_t isLocalFd = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_IS_LOCAL_FD, isLocalFd);
    data.isLocalFd = (isLocalFd == 1);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_BITRATE_BEFORE, data.bitrateBefore);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_BITRATE_AFTER, data.bitrateAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_WIDTH_BEFORE, data.videoWidthBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_HEIGHT_BEFORE, data.videoHeightBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_WIDTH_AFTER, data.videoWidthAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_HEIGHT_AFTER, data.videoHeightAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_FRAMERATE_BEFORE, data.videoFrameRateBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_FRAMERATE_AFTER, data.videoFrameRateAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_AUDIO_CHANNELS_BEFORE, data.audioChannelsBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_AUDIO_CHANNELS_AFTER, data.audioChannelsAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_AUDIO_SAMPLE_RATE_BEFORE, data.audioSampleRateBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_AUDIO_SAMPLE_RATE_AFTER, data.audioSampleRateAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_TYPE_BEFORE, data.videoTypeBefore);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_VIDEO_TYPE_AFTER, data.videoTypeAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_AUDIO_LANG_BEFORE), data.audioLangBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_AUDIO_LANG_AFTER), data.audioLangAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_SUBTITLE_LANG_BEFORE), data.subtitleLangBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_SUBTITLE_LANG_AFTER), data.subtitleLangAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_AUDIO_MIME_TYPE_BEFORE), data.audioMimeTypeBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_AUDIO_MIME_TYPE_AFTER), data.audioMimeTypeAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_VIDEO_MIME_TYPE_BEFORE), data.videoMimeTypeBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_VIDEO_MIME_TYPE_AFTER), data.videoMimeTypeAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_CODECS_BEFORE), data.codecsBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_CODECS_AFTER), data.codecsAfter);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_ORIGIN_CODECS_BEFORE), data.originCodecsBefore);
    (void)infoBody.GetStringValue(std::string(PlayerKeys::PLAYER_ORIGIN_CODECS_AFTER), data.originCodecsAfter);
}

void AVPlayerCallback::PushContentChangedValuesToCb(const ContentChangedData &data, std::vector<int64_t>& valueVec)
{
    bool isLocalFd = data.isLocalFd;
    
    valueVec.push_back(data.timestamp);
    valueVec.push_back(data.playbackPosition);
    valueVec.push_back(isLocalFd ? 1 : 0);
    valueVec.push_back(static_cast<int64_t>(data.videoWidthBefore));
    valueVec.push_back(static_cast<int64_t>(data.videoHeightBefore));
    valueVec.push_back(static_cast<int64_t>(data.videoWidthAfter));
    valueVec.push_back(static_cast<int64_t>(data.videoHeightAfter));
    valueVec.push_back(static_cast<int64_t>(data.videoFrameRateBefore));
    valueVec.push_back(static_cast<int64_t>(data.videoFrameRateAfter));
    valueVec.push_back(static_cast<int64_t>(data.audioChannelsBefore));
    valueVec.push_back(static_cast<int64_t>(data.audioChannelsAfter));
    valueVec.push_back(static_cast<int64_t>(data.audioSampleRateBefore));
    valueVec.push_back(static_cast<int64_t>(data.audioSampleRateAfter));
    if (isLocalFd) {
        return;
    }
    valueVec.push_back(static_cast<int64_t>(data.streamIdBefore));
    valueVec.push_back(static_cast<int64_t>(data.streamIdAfter));
    valueVec.push_back(data.bitrateBefore);
    valueVec.push_back(data.bitrateAfter);
}

void AVPlayerCallback::PushContentChangedStringsToCb(const ContentChangedData &data,
    std::vector<std::string>& stringVec)
{
    bool isLocalFd = data.isLocalFd;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb MEDIA_CHANGED, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", streamType = %{public}s"
        ", changeReason = %{public}s, changeResult = %{public}s",
        FAKE_POINTER(this), data.timestamp, data.playbackPosition,
        data.streamType.c_str(), data.changeReason.c_str(), data.changeResult.c_str());
    if (!isLocalFd) {
        stringVec.push_back(data.streamType);
    } else {
        stringVec.push_back("");
    }
    stringVec.push_back(data.changeReason);
    stringVec.push_back(data.changeResult);
    std::string videoTypeBeforeStr = GetVideoTypeStr(data.videoTypeBefore);
    std::string videoTypeAfterStr = GetVideoTypeStr(data.videoTypeAfter);
    stringVec.push_back(data.audioLangBefore);
    stringVec.push_back(data.audioLangAfter);
    stringVec.push_back(data.subtitleLangBefore);
    stringVec.push_back(data.subtitleLangAfter);
    stringVec.push_back(data.audioMimeTypeBefore);
    stringVec.push_back(data.audioMimeTypeAfter);
    stringVec.push_back(data.videoMimeTypeBefore);
    stringVec.push_back(data.videoMimeTypeAfter);
    stringVec.push_back(videoTypeBeforeStr);
    stringVec.push_back(videoTypeAfterStr);
    if (!isLocalFd) {
        stringVec.push_back(data.codecsBefore);
        stringVec.push_back(data.codecsAfter);
        stringVec.push_back(data.originCodecsBefore);
        stringVec.push_back(data.originCodecsAfter);
    }
}

void AVPlayerCallback::FillContentChangedEvent(const Format &infoBody)
{
    ContentChangedData data;
    ExtractContentChangedData(infoBody, data);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_CONTENT_CHANGED);
    PushContentChangedValuesToCb(data, cb->valueVec);
    PushContentChangedStringsToCb(data, cb->stringVec);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillAudioAbnormalEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string stateBefore;
    std::string stateAfter;
    int32_t interruptHint = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_AUDIO_STATE_BEFORE, stateBefore);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_AUDIO_STATE_AFTER, stateAfter);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_AUDIO_INTERRUPT_HINT, interruptHint);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb AUDIO_STATUS, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", stateBefore = %{public}s"
        ", stateAfter = %{public}s, interruptHint = %{public}d",
        FAKE_POINTER(this), timestamp, playbackPosition, stateBefore.c_str(), stateAfter.c_str(), interruptHint);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_AUDIO_ABNORMAL);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->stringVec.push_back(stateBefore);
    cb->stringVec.push_back(stateAfter);
    std::string interruptHintStr = GetInterruptHintStr(interruptHint);
    cb->stringVec.push_back(interruptHintStr);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillCodecAbnormalEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string decoderType;
    int64_t errorCode = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_DECODER_TYPE, decoderType);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_CODEC_ERROR_CODE, errorCode);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb CODEC_ABNORMAL, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", decoderType = %{public}s, errorCode = %{public}" PRId64,
        FAKE_POINTER(this), timestamp, playbackPosition, decoderType.c_str(), errorCode);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_CODEC_ABNORMAL);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->stringVec.push_back(decoderType);
    cb->valueVec.push_back(errorCode);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillContentDiscontinuityEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string streamType;
    std::string discontinueType;
    int64_t ptsBefore = 0;
    int64_t ptsAfter = 0;
    int32_t sampleRateBefore = 0;
    int32_t sampleRateAfter = 0;
    int32_t channelsBefore = 0;
    int32_t channelsAfter = 0;
    int32_t sampleFormatBefore = 0;
    int32_t sampleFormatAfter = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_MEDIA_STREAM_TYPE, streamType);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_DISCONTINUE_TYPE, discontinueType);
    if (discontinueType == "PTS") {
        (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PTS_BEFORE, ptsBefore);
        (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PTS_AFTER, ptsAfter);
    } else if (discontinueType == "AUDIO_PARAM") {
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_SAMPLE_RATE_BEFORE, sampleRateBefore);
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_SAMPLE_RATE_AFTER, sampleRateAfter);
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_CHANNELS_BEFORE, channelsBefore);
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_CHANNELS_AFTER, channelsAfter);
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_SAMPLE_FORMAT_BEFORE, sampleFormatBefore);
        (void)infoBody.GetIntValue(PlayerKeys::PLAYER_SAMPLE_FORMAT_AFTER, sampleFormatAfter);
    }
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb CONTENT_DISCONTINUITY, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", streamType = %{public}s, discontinueType = %{public}s",
        FAKE_POINTER(this), timestamp, playbackPosition, streamType.c_str(), discontinueType.c_str());
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->stringVec.push_back(streamType);
    cb->stringVec.push_back(discontinueType);
    cb->valueVec.push_back(ptsBefore);
    cb->valueVec.push_back(ptsAfter);
    cb->valueVec.push_back(static_cast<int64_t>(sampleRateBefore));
    cb->valueVec.push_back(static_cast<int64_t>(sampleRateAfter));
    cb->valueVec.push_back(static_cast<int64_t>(channelsBefore));
    cb->valueVec.push_back(static_cast<int64_t>(channelsAfter));
    cb->valueVec.push_back(static_cast<int64_t>(sampleFormatBefore));
    cb->valueVec.push_back(static_cast<int64_t>(sampleFormatAfter));
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillLipAsyncEvent(const Format &infoBody)
{
    int64_t timestamp = 0;
    int64_t playbackPosition = 0;
    std::string asyncType;
    int64_t startTime = 0;
    int64_t endTime = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_TIMESTAMP, timestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_PLAYBACK_POSITION, playbackPosition);
    (void)infoBody.GetStringValue(PlayerKeys::PLAYER_ASYNC_TYPE, asyncType);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_START_TIME, startTime);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_END_TIME, endTime);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb LIP_ASYNC, timestamp = %{public}" PRId64
        ", playbackPosition = %{public}" PRId64 ", asyncType = %{public}s, startTime = %{public}" PRId64
        ", endTime = %{public}" PRId64,
        FAKE_POINTER(this), timestamp, playbackPosition, asyncType.c_str(), startTime, endTime);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_LIP_ASYNC);
    cb->valueVec.push_back(timestamp);
    cb->valueVec.push_back(playbackPosition);
    cb->stringVec.push_back(asyncType);
    cb->valueVec.push_back(startTime);
    cb->valueVec.push_back(endTime);
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::FillStallingEvent(const Format &infoBody)
{
    int64_t stallingTimestamp = 0;
    int64_t stallingTimeline = 0;
    int64_t stallingDuration = 0;
    int32_t stallingMediaType = 0;
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_TIMESTAMP, stallingTimestamp);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_TIMELINE, stallingTimeline);
    (void)infoBody.GetLongValue(PlayerKeys::PLAYER_STALLING_DURATION, stallingDuration);
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_STALLING_MEDIA_TYPE, stallingMediaType);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnMetricsEventCb STALLING, timestamp = %{public}" PRId64
        ", timeline = %{public}" PRId64 ", duration = %{public}" PRId64 ", mediaType = %{public}" PRId32,
        FAKE_POINTER(this), stallingTimestamp, stallingTimeline, stallingDuration, stallingMediaType);
    NapiCallback::MetricsEvent *cb = new(std::nothrow) NapiCallback::MetricsEvent();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new MetricsEvent");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_METRICS);
    cb->callbackName = AVPlayerEvent::EVENT_METRICS;
    cb->valueVec.push_back(AV_METRICS_EVENT_TYPE_STALLING);
    cb->valueVec.push_back(stallingTimestamp);
    cb->valueVec.push_back(stallingTimeline);
    cb->valueVec.push_back(stallingDuration);
    cb->valueVec.push_back(static_cast<int64_t>(stallingMediaType));
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnMetricsEventCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");

    if (refMap_.find(AVPlayerEvent::EVENT_METRICS) == refMap_.end()) {
        MEDIA_LOGW("can not find metrics event callback!");
        return;
    }

    int32_t metricsEventType = 0;
    (void)infoBody.GetIntValue(PlayerKeys::PLAYER_METRICS_EVENT_TYPE, metricsEventType);

    if (metricsEventType == AV_METRICS_EVENT_TYPE_LOADINGRATE_CHANGE) {
        FillLoadingRateChangeEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_LOADING_ERROR) {
        FillLoadingErrorEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_CONTENT_CHANGED) {
        FillContentChangedEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_AUDIO_ABNORMAL) {
        FillAudioAbnormalEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_CODEC_ABNORMAL) {
        FillCodecAbnormalEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_CONTENT_DISCONTINUITY) {
        FillContentDiscontinuityEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_LIP_ASYNC) {
        FillLipAsyncEvent(infoBody);
    } else if (metricsEventType == AV_METRICS_EVENT_TYPE_STALLING) {
        FillStallingEvent(infoBody);
    } else {
        return;
    }
}

void AVPlayerCallback::OnTimedMetaDataCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_TIMED_META_DATA) == refMap_.end()) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find timedMetaData callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::TimedMetaDataCb *cb = new(std::nothrow) NapiCallback::TimedMetaDataCb();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new TimedMetaDataCb");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TIMED_META_DATA);
    cb->callbackName = AVPlayerEvent::EVENT_TIMED_META_DATA;

    std::string id;
    std::string classify;
    int64_t start = 0;
    int64_t duration = 0;

    (void)infoBody.GetStringValue(std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_ID), id);
    (void)infoBody.GetStringValue(std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_CLASSIFY), classify);
    (void)infoBody.GetLongValue(std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_START), start);
    (void)infoBody.GetLongValue(std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_DURATION), duration);

    cb->meta.id = id;
    cb->meta.classify = classify;
    cb->meta.start = start;
    cb->meta.duration = duration;

    // Extract contents: all keys in infoBody except fixed keys are dynamic contents
    static const std::set<std::string> fixedKeys = {
        std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_ID),
        std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_CLASSIFY),
        std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_START),
        std::string(PlaybackTimedMetaData::PLAYER_TIMED_META_DURATION)
    };
    std::vector<std::string> allKeys;
    infoBody.GetKeys(allKeys);
    for (const auto &key : allKeys) {
        if (fixedKeys.find(key) == fixedKeys.end()) {
            std::string val;
            (void)infoBody.GetStringValue(key, val);
            cb->meta.contents[key] = val;
        }
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnTimedMetaDataCb id=%{public}s classify=%{public}s",
        FAKE_POINTER(this), id.c_str(), classify.c_str());
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnAdsChangeCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    if (refMap_.find(AVPlayerEvent::EVENT_ADS_CHANGE) == refMap_.end()) {
        MEDIA_LOGD("0x%{public}06" PRIXPTR " can not find adsChange callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::AdsChangeCb *cb = new(std::nothrow) NapiCallback::AdsChangeCb();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new AdsChangeCb");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_ADS_CHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_ADS_CHANGE;

    (void)infoBody.GetIntValue(std::string(PlaybackAds::PLAYER_ADS_TYPE), cb->meta.type);
    (void)infoBody.GetStringValue(std::string(PlaybackAds::PLAYER_ADS_EVENT_ID), cb->meta.eventId);
    (void)infoBody.GetLongValue(std::string(PlaybackAds::PLAYER_ADS_START_MS), cb->meta.startMs);
    (void)infoBody.GetLongValue(std::string(PlaybackAds::PLAYER_ADS_DURATION_MS),
        cb->meta.durationMs);
    (void)infoBody.GetIntValue(std::string(PlaybackAds::PLAYER_ADS_REASON), cb->meta.reason);

    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnAdsChangeCb type=%{public}d eventId=%{public}s",
        FAKE_POINTER(this), cb->meta.type, cb->meta.eventId.c_str());
    NapiCallback::CompleteCallback(env_, cb);
}

int32_t AVPlayerCallback::SetDrmInfoData(const uint8_t *drmInfoAddr, int32_t infoCount,
    std::multimap<std::string, std::vector<uint8_t>> &drmInfoMap)
{
    DrmInfoItem *drmInfos = reinterpret_cast<DrmInfoItem*>(const_cast<uint8_t *>(drmInfoAddr));
    CHECK_AND_RETURN_RET_LOG(drmInfos != nullptr, MSERR_INVALID_VAL, "cast drmInfos nullptr");
    for (int32_t i = 0; i < infoCount; i++) {
        DrmInfoItem temp = drmInfos[i];
        std::stringstream ssConverter;
        std::string uuid;
        for (uint32_t index = 0; index < DrmConstant::DRM_MAX_M3U8_DRM_UUID_LEN; index++) {
            int32_t singleUuid = static_cast<int32_t>(temp.uuid[index]);
            ssConverter << std::hex << std::setfill('0') << std::setw(2) << singleUuid; // 2:w
            uuid = ssConverter.str();
        }
        if (temp.psshLen <= 0 || temp.psshLen > DrmConstant::DRM_MAX_M3U8_DRM_PSSH_LEN) {
            MEDIA_LOGW("drmInfoItem psshLen is invalid");
            continue;
        }
        std::vector<uint8_t> pssh(temp.pssh, temp.pssh + temp.psshLen);
        drmInfoMap.insert({ uuid, pssh });
    }

    if (listener_ != nullptr) {
        listener_->NotifyDrmInfoUpdated(drmInfoMap);
    }
    return MSERR_OK;
}

void AVPlayerCallback::OnDrmInfoUpdatedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    MEDIA_LOGI("AVPlayerCallback OnDrmInfoUpdatedCb is called");
    if (refMap_.find(AVPlayerEvent::EVENT_DRM_INFO_UPDATE) == refMap_.end()) {
        MEDIA_LOGW("can not find drm info updated callback!");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_addr key");
        return;
    }
    if (!infoBody.ContainKey(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT))) {
        MEDIA_LOGW("there's no drminfo-update drm_info_count key");
        return;
    }

    uint8_t *drmInfoAddr = nullptr;
    size_t size  = 0;
    int32_t infoCount = 0;
    infoBody.GetBuffer(std::string(PlayerKeys::PLAYER_DRM_INFO_ADDR), &drmInfoAddr, size);
    CHECK_AND_RETURN_LOG(drmInfoAddr != nullptr && size > 0, "get drminfo buffer failed");
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_DRM_INFO_COUNT), infoCount);
    CHECK_AND_RETURN_LOG(infoCount > 0, "get drminfo count is illegal");

    std::multimap<std::string, std::vector<uint8_t>> drmInfoMap;
    int32_t ret = SetDrmInfoData(drmInfoAddr, infoCount, drmInfoMap);
    CHECK_AND_RETURN_LOG(ret == MSERR_OK, "SetDrmInfoData err");
    NapiCallback::ObjectArray *cb = new(std::nothrow) NapiCallback::ObjectArray();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new ObjectArray");
    cb->callback = refMap_.at(AVPlayerEvent::EVENT_DRM_INFO_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_DRM_INFO_UPDATE;
    cb->infoMap = drmInfoMap;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSetDecryptConfigDoneCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    MEDIA_LOGI("AVPlayerCallback OnSetDecryptConfigDoneCb is called");
    if (refMap_.find(AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE) == refMap_.end()) {
        MEDIA_LOGW("can not find SetDecryptConfig Done callback!");
        return;
    }

    NapiCallback::Base *cb = new(std::nothrow) NapiCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE);
    cb->callbackName = AVPlayerEvent::EVENT_SET_DECRYPT_CONFIG_DONE;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnSubtitleInfoCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    int32_t pts = -1;
    int32_t duration = -1;
    std::string text;
    infoBody.GetStringValue(PlayerKeys::SUBTITLE_TEXT, text);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_PTS), pts);
    infoBody.GetIntValue(std::string(PlayerKeys::SUBTITLE_DURATION), duration);
    MEDIA_LOGI("OnSubtitleInfoCb pts %{public}d, duration = %{public}d", pts, duration);

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_SUBTITLE_UPDATE) != refMap_.end(),
        "can not find Subtitle callback!");

    NapiCallback::SubtitleInfo *cb = new(std::nothrow) NapiCallback::SubtitleInfo();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Subtitle");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_SUBTITLE_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_SUBTITLE_UPDATE;
    cb->valueMap.text = text;
    cb->valueMap.pts = pts;
    cb->valueMap.duration = duration;

    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnEosCb(const int32_t extra, const Format &infoBody)
{
    (void)infoBody;
    CHECK_AND_RETURN_LOG(isloaded_.load(), "current source is unready");
    int32_t isLooping = extra;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OnEndOfStream is called, isloop: %{public}d", FAKE_POINTER(this), isLooping);
    if (refMap_.find(AVPlayerEvent::EVENT_END_OF_STREAM) == refMap_.end()) {
        MEDIA_LOGW("0x%{public}06" PRIXPTR " can not find EndOfStream callback!", FAKE_POINTER(this));
        return;
    }

    NapiCallback::Base *cb = new(std::nothrow) NapiCallback::Base();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new Base");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_END_OF_STREAM);
    cb->callbackName = AVPlayerEvent::EVENT_END_OF_STREAM;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnTrackChangedCb(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    int32_t index = -1;
    int32_t isSelect = -1;
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_TRACK_INDEX), index);
    infoBody.GetIntValue(std::string(PlayerKeys::PLAYER_IS_SELECT), isSelect);
    MEDIA_LOGI("OnTrackChangedCb index %{public}d, isSelect = %{public}d", index, isSelect);

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_TRACKCHANGE) != refMap_.end(),
        "can not find trackChange callback!");

    NapiCallback::TrackChange *cb = new(std::nothrow) NapiCallback::TrackChange();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new TrackChange");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TRACKCHANGE);
    cb->callbackName = AVPlayerEvent::EVENT_TRACKCHANGE;
    cb->number = index;
    cb->isSelect = isSelect ? true : false;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::OnTrackInfoUpdate(const int32_t extra, const Format &infoBody)
{
    (void)extra;
    std::vector<Format> trackInfo;
    (void)infoBody.GetFormatVector(std::string(PlayerKeys::PLAYER_TRACK_INFO), trackInfo);
    MEDIA_LOGI("OnTrackInfoUpdate callback");

    CHECK_AND_RETURN_LOG(refMap_.find(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE) != refMap_.end(),
        "can not find trackInfoUpdate callback!");

    NapiCallback::TrackInfoUpdate *cb = new(std::nothrow) NapiCallback::TrackInfoUpdate();
    CHECK_AND_RETURN_LOG(cb != nullptr, "failed to new TrackInfoUpdate");

    cb->callback = refMap_.at(AVPlayerEvent::EVENT_TRACK_INFO_UPDATE);
    cb->callbackName = AVPlayerEvent::EVENT_TRACK_INFO_UPDATE;
    cb->trackInfo = trackInfo;
    NapiCallback::CompleteCallback(env_, cb);
}

void AVPlayerCallback::SaveCallbackReference(const std::string &name, std::weak_ptr<AutoRef> ref)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_[name] = ref;
}

void AVPlayerCallback::ClearCallbackReference()
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.clear();
}

void AVPlayerCallback::ClearCallbackReference(const std::string &name)
{
    std::lock_guard<std::mutex> lock(mutex_);
    refMap_.erase(name);
}

void AVPlayerCallback::Start()
{
    isloaded_ = true;
}

void AVPlayerCallback::Pause()
{
    isloaded_ = false;
}

void AVPlayerCallback::Release()
{
    std::lock_guard<std::mutex> lock(mutex_);

    Format infoBody;
    AVPlayerCallback::OnStateChangeCb(PlayerStates::PLAYER_RELEASED, infoBody);
    listener_ = nullptr;
}
} // namespace Media
} // namespace OHOS