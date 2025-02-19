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

#include "js_common_utils.h"
#include <cmath>
#include <media_errors.h>
#include <sstream>
#include <climits>
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "JsCommonUtils"};
    constexpr int32_t DECIMAL = 10;
} //namespace

bool __attribute__((visibility("default"))) StrToULL(const std::string &str, uint64_t &value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front())), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    unsigned long long result = strtoull(valStr.c_str(), &end, DECIMAL);
    // end will not be nullptr here
    CHECK_AND_RETURN_RET_LOG(result <= ULLONG_MAX, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != valStr.c_str() && end[0] == '\0' && errno != ERANGE, false,
        "call StrToULL func false,  input str is: %{public}s!", valStr.c_str());
    value = result;
    return true;
}
} // namespace Media
} // namespace OHOS