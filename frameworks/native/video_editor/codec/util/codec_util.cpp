/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "codec/util/codec_util.h"

namespace OHOS {
namespace Media {

const char* CodecUtil::GetCodecErrorStr(OH_AVErrCode errorCode)
{
    switch (errorCode) {
        case AV_ERR_OK:
            return "AV_ERR_OK";
        case AV_ERR_NO_MEMORY:
            return "AV_ERR_NO_MEMORY";
        case AV_ERR_OPERATE_NOT_PERMIT:
            return "AV_ERR_OPERATE_NOT_PERMIT";
        case AV_ERR_INVALID_VAL:
            return "AV_ERR_INVALID_VAL";
        case AV_ERR_IO:
            return "AV_ERR_IO";
        case AV_ERR_TIMEOUT:
            return "AV_ERR_TIMEOUT";
        case AV_ERR_UNKNOWN:
            return "AV_ERR_UNKNOWN";
        case AV_ERR_SERVICE_DIED:
            return "AV_ERR_SERVICE_DIED";
        case AV_ERR_INVALID_STATE:
            return "AV_ERR_INVALID_STATE";
        case AV_ERR_UNSUPPORT:
            return "AV_ERR_UNSUPPORT";
        default:
            break;
    }
    return "?";
}
} // namespace Media
} // namespace OHOS
