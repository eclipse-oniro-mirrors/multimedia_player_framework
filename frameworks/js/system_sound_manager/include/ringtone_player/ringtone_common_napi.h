/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef RINGTONE_COMMON_NAPI_H
#define RINGTONE_COMMON_NAPI_H

#include <string>

#include "meta/format.h"

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace Media {
const int32_t  NAPI_ERR_NO_PERMISSION = 201;
const int32_t  NAPI_ERR_PERMISSION_DENIED = 202;
const int32_t  NAPI_ERR_INPUT_INVALID = 401;
const int32_t  NAPI_ERR_URI_ERROR = 20700001;
const int32_t  NAPI_ERR_OPERATE_NOT_ALLOWED = 5400102;
const int32_t  NAPI_ERR_IO_ERROR = 5400103;
const int32_t  NAPI_ERR_INVALID_PARAM = 6800101;
const int32_t  NAPI_ERR_NO_MEMORY = 6800102;
const int32_t  NAPI_ERR_UNSUPPORTED = 6800104;
const int32_t  NAPI_ERR_SYSTEM = 6800301;
const int32_t  NAPI_ERR_PARAM_CHECK_ERROR = 20700002;
const int32_t  NAPI_ERR_UNSUPPORTED_OPERATION = 20700003;

const std::string NAPI_ERR_NO_PERMISSION_INFO = "Permission denied";
const std::string NAPI_ERR_PERMISSION_DENIED_INFO = "Caller is not a system application";
const std::string NAPI_ERR_INPUT_INVALID_INFO = "input parameter type or number mismatch";
const std::string NAPI_ERR_URI_ERROR_INFO = "Tone type mismatch";
const std::string NAPI_ERR_OPERATE_NOT_ALLOWED_INFO = "Operation is not allowed";
const std::string NAPI_ERR_IO_ERROR_INFO = "I/O error";
const std::string NAPI_ERR_INVALID_PARAM_INFO = "invalid parameter";
const std::string NAPI_ERR_NO_MEMORY_INFO = "allocate memory failed";
const std::string NAPI_ERR_SYSTEM_INFO = "system error";
const std::string NAPI_ERR_PARAM_CHECK_ERROR_INFO = "Parameter check error";
const std::string NAPI_ERR_UNSUPPORTED_OPERATION_INFO = "Unsupported operation";
const std::string NAPI_ERR_DATA_TOO_LARGE_INFO = "File size over limit. For video, the upper limit is 1GB";
const std::string NAPI_ERR_TOO_MANY_FILES_INFO = "File count over limit. For video, the upper limit is 20";
const std::string NAPI_ERR_INSUFFICIENT_ROM_INFO = "Rom is insufficient";
const std::string NAPI_ERR_URILIST_OVER_LIMIT_INFO = "Parameter is invalid, e.g. the length of uriList is too long";

class RingtoneCommonNapi {
public:
    RingtoneCommonNapi() = delete;
    ~RingtoneCommonNapi() = delete;
    static std::string GetStringArgument(napi_env env, napi_value value);
    static void ThrowError(napi_env env, int32_t code, const std::string &errMessage);
    static std::string GetMessageByCode(int32_t &code);
};
} // namespace Media
} // namespace OHOS
#endif // RINGTONE_COMMON_NAPI_H