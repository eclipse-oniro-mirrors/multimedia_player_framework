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

#ifndef OH_VEF_RENDER_QUEUE_H
#define OH_VEF_RENDER_QUEUE_H

#include <list>
#include "render/graphics/base/queue/RenderQueueItf.h"

namespace OHOS {
namespace Media {
template <typename T> class RenderFifoQueue : public RenderQueueItf<T> {
public:
    typedef std::list<T> list_t;

    ~RenderFifoQueue() = default;

    size_t GetSize() override
    {
        return list_.size();
    }

    bool Push(const T& data) override
    {
        list_.emplace_back(data);
        return true;
    }

    bool Pop(T& result) override
    {
        if (list_.size() == 0) {
            return false;
        }
        result = list_.front();
        list_.pop_front();
        return true;
    }

    bool PopWithCallBack(T& result, std::function<void(T&)>& callback) override
    {
        if (list_.size() == 0) {
            return false;
        }
        result = list_.front();
        list_.pop_front();
        callback(result);
        return true;
    }

    T Find(const T& result) override
    {
        for (typename list_t::iterator it = list_.begin(); it != list_.end(); ++it) {
            if (GetTag(*it) == GetTag(result)) {
                return *it;
            }
        }
        return nullptr;
    }

    bool Front(T& result) override
    {
        if (list_.size() == 0) {
            return false;
        }
        result = list_.front();
        return true;
    }

    bool Back(T& result) override
    {
        if (list_.size() == 0) {
            return false;
        }
        result = list_.back();
        return true;
    }

    void RemoveAll() override
    {
        list_.clear();
    }

    void Remove(const std::function<bool(T&)>& checkFunc) override
    {
        list_.remove_if(checkFunc);
    }

private:
    list_t list_;
};
}
}

#endif