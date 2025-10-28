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

#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace ANI::Media {

AudioHapticCommonTaihe::AudioHapticCommonTaihe()
{
}

AudioHapticCommonTaihe::~AudioHapticCommonTaihe()
{
}

bool AudioHapticCommonTaihe::VerifySelfSystemPermission()
{
    OHOS::Security::AccessToken::FullTokenID selfTokenID = OHOS::IPCSkeleton::GetSelfTokenID();
    return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfTokenID);
}

std::string AudioHapticCommonTaihe::GetMessageByCode(int32_t &code)
{
    std::string errMessage;
    switch (code) {
        case TAIHE_ERR_INPUT_INVALID:
            errMessage = TAIHE_ERR_INPUT_INVALID_INFO;
            break;
        case TAIHE_ERR_OPERATE_NOT_ALLOWED:
            errMessage = TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO;
            break;
        case TAIHE_ERR_IO_ERROR:
            errMessage = TAIHE_ERR_IO_ERROR_INFO;
            break;
        case TAIHE_ERR_SERVICE_DIED:
            errMessage = TAIHE_ERR_SERVICE_DIED_INFO;
            break;
        case TAIHE_ERR_UNSUPPORTED_FORMAT:
            errMessage = TAIHE_ERR_UNSUPPORTED_FORMAT_INFO;
            break;
        case TAIHE_ERR_PARAM_OUT_OF_RANGE:
            errMessage = TAIHE_ERR_PARAM_OUT_OF_RANGE_INFO;
            break;
        case TAIHE_ERR_NOT_SUPPORTED:
            errMessage = TAIHE_ERR_NOT_SUPPORTED_INFO;
            break;
        case TAIHE_ERR_PERMISSION_DENIED:
            errMessage = TAIHE_ERR_PERMISSION_DENIED_INFO;
            break;
        default:
            errMessage = TAIHE_ERR_OPERATE_NOT_ALLOWED_INFO;
            code = TAIHE_ERR_OPERATE_NOT_ALLOWED;
            break;
    }
    return errMessage;
}
} // namespace ANI::Media