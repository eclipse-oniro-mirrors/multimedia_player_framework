/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "limitIdGenerator.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_SCREENCAPTURE, "ScreenCaptureServer"};
}

UniqueIDGenerator::UniqueIDGenerator(int32_t limit)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances create", FAKE_POINTER(this));
    limit_ = limit;
    std::unique_lock<std::mutex> lock(queueMtx);
    for (int32_t i = 1; i <= limit_; i++) {
        availableIDs.push(i);
    }
}

UniqueIDGenerator::~UniqueIDGenerator()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "Instances destroy", FAKE_POINTER(this));
}

int32_t UniqueIDGenerator::GetNewID()
{
    std::unique_lock<std::mutex> lock(queueMtx);
    if (availableIDs.empty()) {
        return -1;
    }
    int32_t id = availableIDs.front();
    availableIDs.pop();
    return id;
}

int32_t UniqueIDGenerator::ReturnID(int32_t id)
{
    std::unique_lock<std::mutex> lock(queueMtx);
    if (id < 1 || id > limit_) {
        return -1;
    }
    availableIDs.push(id);
    return id;
}
} // namespace Media
} // namespace OHOS