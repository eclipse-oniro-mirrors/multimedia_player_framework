/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_UT_COMMON_DATA_H
#define OH_VEF_UT_COMMON_DATA_H

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "video_editor_impl.h"

namespace OHOS {
namespace Media {

constexpr const char* WATER_MARK_DESC =
    "{\"imageEffect\":{\"filters\":[{\"name\":\"InplaceSticker\",\"values\":"
    "{\"RESOURCE_DIRECTORY\":\"/sys_prod/resource/camera\"}}],\"name\":\"brandWaterMark\"}}";

class CompositionCallbackTesterImpl : public CompositionCallback {
public:
    CompositionCallbackTesterImpl() = default;
    virtual ~CompositionCallbackTesterImpl() = default;
    void onResult(VEFResult result, VEFError errorCode) override
    {
        result_ = result;
    }
    void onProgress(uint32_t progress) override
    {
        progress_ = progress;
    }
private:
    VEFResult result_ = VEFResult::UNKNOWN;
    uint32_t progress_ = 0;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_UT_COMMON_DATA_H