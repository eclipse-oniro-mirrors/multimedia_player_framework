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

#ifndef AUDIO_HAPTIC_COMMON_TAIHE_H
#define AUDIO_HAPTIC_COMMON_TAIHE_H

#include "ohos.multimedia.audioHaptic.audioHaptic.proj.hpp"
#include "ohos.multimedia.audioHaptic.audioHaptic.impl.hpp"
#include "taihe/runtime.hpp"

#include "audio_info.h"

namespace ANI::Media {
const int32_t TAIHE_ERR_INPUT_INVALID = 401;
const int32_t TAIHE_ERR_OPERATE_NOT_ALLOWED = 5400102;
const int32_t TAIHE_ERR_IO_ERROR = 5400103;
const int32_t TAIHE_ERR_SERVICE_DIED = 5400105;
const int32_t TAIHE_ERR_UNSUPPORTED_FORMAT = 5400106;
const int32_t TAIHE_ERR_PARAM_OUT_OF_RANGE = 5400108;
const int32_t TAIHE_ERR_PERMISSION_DENIED = 202;
const int32_t TAIHE_ERR_NOT_SUPPORTED = 801;

const std::string TAIHE_ERR_INPUT_INVALID_INFO = "input parameter check failed";
const std::string TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO = "operate not allowed";
const std::string TAIHE_ERR_IO_ERROR_INFO = "input or output error";
const std::string TAIHE_ERR_SERVICE_DIED_INFO = "service died";
const std::string TAIHE_ERR_UNSUPPORTED_FORMAT_INFO = "unsupport format";
const std::string TAIHE_ERR_PARAM_OUT_OF_RANGE_INFO = "Parameter out of range";
const std::string TAIHE_ERR_NOT_SUPPORTED_INFO = "Function is not supported in current device";
const std::string TAIHE_ERR_PERMISSION_DENIED_INFO = "Caller is not a system application";

class AudioHapticCommonTaihe {
public:
    AudioHapticCommonTaihe();
    ~AudioHapticCommonTaihe();

    static std::string GetMessageByCode(int32_t &code);
    static bool VerifySelfSystemPermission();
};

} // namespace ANI::Media

#endif // AUDIO_HAPTIC_COMMON_TAIHE_H