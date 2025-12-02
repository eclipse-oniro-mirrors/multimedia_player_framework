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

#ifndef RINGTONE_COMMON_TAIHE_H
#define RINGTONE_COMMON_TAIHE_H

#include <string>

#include "audio_info.h"
#include "ringtonePlayer.proj.hpp"
#include "ringtonePlayer.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"
#include "meta/format.h"

namespace ANI::Media {

const int32_t  TAIHE_ERR_NO_PERMISSION = 201;
const int32_t  TAIHE_ERR_PERMISSION_DENIED = 202;
const int32_t  TAIHE_ERR_INPUT_INVALID = 401;
const int32_t  TAIHE_ERR_URI_ERROR = 20700001;
const int32_t  TAIHE_ERR_OPERATE_NOT_ALLOWED = 5400102;
const int32_t  TAIHE_ERR_IO_ERROR = 5400103;
const int32_t  TAIHE_ERR_INVALID_PARAM = 6800101;
const int32_t  TAIHE_ERR_NO_MEMORY = 6800102;
const int32_t  TAIHE_ERR_UNSUPPORTED = 6800104;
const int32_t  TAIHE_ERR_SYSTEM = 6800301;
const int32_t  TAIHE_ERR_PARAM_CHECK_ERROR = 20700002;
const int32_t  TAIHE_ERR_UNSUPPORTED_OPERATION = 20700003;

const std::string TAIHE_ERR_NO_PERMISSION_INFO = "Permission denied";
const std::string TAIHE_ERR_PERMISSION_DENIED_INFO = "Caller is not a system application";
const std::string TAIHE_ERR_INPUT_INVALID_INFO = "input parameter type or number mismatch";
const std::string TAIHE_ERR_URI_ERROR_INFO = "Tone type mismatch";
const std::string TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO = "Operation is not allowed";
const std::string TAIHE_ERR_IO_ERROR_INFO = "I/O error";
const std::string TAIHE_ERR_INVALID_PARAM_INFO = "invalid parameter";
const std::string TAIHE_ERR_NO_MEMORY_INFO = "allocate memory failed";
const std::string TAIHE_ERR_SYSTEM_INFO = "system error";
const std::string TAIHE_ERR_PARAM_CHECK_ERROR_INFO = "Parameter check error";
const std::string TAIHE_ERR_UNSUPPORTED_OPERATION_INFO = "Unsupported operation";
const std::string TAIHE_ERR_URILIST_OVER_LIMIT_INFO = "Parameter is invalid, e.g. the length of uriList is too long";

class RingtoneCommonTaihe {
public:
    RingtoneCommonTaihe() = delete;
    ~RingtoneCommonTaihe() = delete;
    static void ThrowError(int32_t code, const std::string &errMessage);
    static std::string GetMessageByCode(int32_t &code);
};
} // namespace ANI::Media
#endif // RINGTONE_COMMON_TAIHE_H