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

#ifndef OH_VEF_COMPOSITE_ENGINE_H
#define OH_VEF_COMPOSITE_ENGINE_H

#include <memory>
#include "video_editor.h"
#include "data_center/data_center.h"

namespace OHOS {
namespace Media {

using OnCompositeResultFunc = std::function<void(VEFResult result)>;
class ICompositeEngine {
public:
    static std::shared_ptr<ICompositeEngine> CreateCompositeEngine(const std::shared_ptr<IDataCenter>& dc);
    virtual uint64_t GetId() const = 0;
    virtual VEFError StartComposite(const std::shared_ptr<CompositionOptions>& options,
                                    const OnCompositeResultFunc& func) = 0;
    virtual VEFError StopComposite() = 0;
};

} // namespace Media
} // namespace OHOS

#endif // OH_VEF_COMPOSITE_ENGINE_H
