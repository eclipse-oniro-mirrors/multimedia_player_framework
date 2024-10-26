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

#ifndef OH_VEF_GRAPHICS_RENDER_OBJECT_H
#define OH_VEF_GRAPHICS_RENDER_OBJECT_H

#include <memory>
#include <string>
#include "ffrt.h"
#include "media_log.h"

namespace OHOS {
namespace Media {
class RenderObject {
public:
    explicit RenderObject() : isReady_(false) {}
    virtual ~RenderObject() = default;

    virtual bool Init() = 0;
    virtual bool Release() = 0;

    bool IsReady()
    {
        return isReady_;
    }

    void SetReady(bool flag)
    {
        isReady_ = flag;
    }

    void SetTag(const std::string& tag)
    {
        tag_ = tag;
    }

    std::string GetTag()
    {
        return tag_;
    }

protected:
    ffrt::mutex m_renderLock;

private:
    bool isReady_;
    std::string tag_;
};

using RenderObjectPtr = std::shared_ptr<RenderObject>;

auto TO_RENDER_OBJECT = [](auto obj) -> std::shared_ptr<RenderObject> {
    return std::dynamic_pointer_cast<RenderObject>(obj);
};
}
}

#endif