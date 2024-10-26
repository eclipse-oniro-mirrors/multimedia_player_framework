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

#ifndef OH_VEF_RENDER_QUEUE_INTERFACE_H
#define OH_VEF_RENDER_QUEUE_INTERFACE_H

#include <functional>

namespace OHOS {
namespace Media {
template <typename T> class RenderQueueItf {
public:
    typedef T DataType;

    virtual ~RenderQueueItf() = default;
    virtual size_t GetSize() = 0;
    virtual bool Push(const T& data) = 0;
    virtual bool Pop(T& data) = 0;
    virtual bool PopWithCallBack(T& data, std::function<void(T&)>&) = 0;
    virtual T Find(const T& data) = 0;
    virtual bool Front(T& data) = 0;
    virtual bool Back(T& data) = 0;
    virtual void RemoveAll() = 0;
    virtual void Remove(const std::function<bool(T&)>& checkFunc) = 0;
};
}
}

#endif