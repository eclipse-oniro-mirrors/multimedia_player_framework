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

#include "audio_haptic_common_taihe.h"

namespace {
const std::string NAPI_ERR_INPUT_INVALID_INFO = "input parameter check failed";
const std::string NAPI_ERR_OPERATE_NOT_ALLOWED_INFO = "operate not allowed";
const std::string NAPI_ERR_IO_ERROR_INFO = "input or output error";
const std::string NAPI_ERR_SERVICE_DIED_INFO = "service died";
const std::string NAPI_ERR_UNSUPPORTED_FORMAT_INFO = "unsupport format";
}

namespace ANI::Media {

AudioHapticCommonTaihe::AudioHapticCommonTaihe()
{
}

AudioHapticCommonTaihe::~AudioHapticCommonTaihe()
{
}

std::string AudioHapticCommonTaihe::GetMessageByCode(int32_t &code)
{
    std::string errMessage;
    switch (code) {
        case NAPI_ERR_INPUT_INVALID:
            errMessage = NAPI_ERR_INPUT_INVALID_INFO;
            break;
        case NAPI_ERR_OPERATE_NOT_ALLOWED:
            errMessage = NAPI_ERR_OPERATE_NOT_ALLOWED_INFO;
            break;
        case NAPI_ERR_IO_ERROR:
            errMessage = NAPI_ERR_IO_ERROR_INFO;
            break;
        case NAPI_ERR_SERVICE_DIED:
            errMessage = NAPI_ERR_SERVICE_DIED_INFO;
            break;
        case NAPI_ERR_UNSUPPORTED_FORMAT:
            errMessage = NAPI_ERR_UNSUPPORTED_FORMAT_INFO;
            break;
        default:
            errMessage = NAPI_ERR_OPERATE_NOT_ALLOWED_INFO;
            code = NAPI_ERR_OPERATE_NOT_ALLOWED;
            break;
    }
    return errMessage;
}
} // namespace ANI::Media