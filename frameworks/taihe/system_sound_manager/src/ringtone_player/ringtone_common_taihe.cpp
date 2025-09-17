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

#include <climits>
#include "ringtone_common_taihe.h"
#include "system_sound_log.h"

namespace ANI::Media {
void RingtoneCommonTaihe::ThrowError(int32_t code, const std::string &errMessage)
{
    std::string messageValue;
    if (code == TAIHE_ERR_INVALID_PARAM || code == TAIHE_ERR_INPUT_INVALID) {
        messageValue = errMessage.c_str();
    } else {
        messageValue = RingtoneCommonTaihe::GetMessageByCode(code);
    }
    taihe::set_business_error(code, messageValue.c_str());
}

std::string RingtoneCommonTaihe::GetMessageByCode(int32_t &code)
{
    std::string errMessage;
    switch (code) {
        case TAIHE_ERR_INVALID_PARAM:
            errMessage = TAIHE_ERR_INVALID_PARAM_INFO;
            break;
        case TAIHE_ERR_NO_MEMORY:
            errMessage = TAIHE_ERR_NO_MEMORY_INFO;
            break;
        case TAIHE_ERR_SYSTEM:
            errMessage = TAIHE_ERR_SYSTEM_INFO;
            break;
        case TAIHE_ERR_INPUT_INVALID:
            errMessage = TAIHE_ERR_INPUT_INVALID_INFO;
            break;
        default:
            errMessage = TAIHE_ERR_SYSTEM_INFO;
            code = TAIHE_ERR_SYSTEM;
            break;
    }
    return errMessage;
}
} // namespace ANI::Media