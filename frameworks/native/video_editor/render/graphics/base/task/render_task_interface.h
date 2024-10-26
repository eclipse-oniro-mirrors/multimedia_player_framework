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

#ifndef OH_VEF_RENDER_TASK_INTERFACE_H
#define OH_VEF_RENDER_TASK_INTERFACE_H

#include <memory>
#include <future>

namespace OHOS {
namespace Media {
template <typename RETURNTYPE, typename... ARGSTYPE> class RenderTaskItf {
public:
    typedef RETURNTYPE ReturnType;

    RenderTaskItf() = default;
    virtual ~RenderTaskItf() = default;

    virtual void Run(ARGSTYPE...) = 0;

    virtual bool operator < (const RenderTaskItf& other)
    {
        return this->id_ < other.id_;
    };

    void SetTag(uint64_t tag)
    {
        tag_ = tag;
    }

    uint64_t GetTag()
    {
        return tag_;
    }

    void SetId(uint64_t id)
    {
        id_ = id;
    }

    uint64_t GetId()
    {
        return id_;
    }

    void SetSequenceId(uint64_t id)
    {
        sequenceId_ = id;
    }

    uint64_t GetSequenceId()
    {
        return sequenceId_;
    }

    void SetRunFunc(std::function<RETURNTYPE(ARGSTYPE...)> run)
    {
        runFunc_ = run;
    }

    virtual void Wait() = 0;

    virtual RETURNTYPE GetReturn() = 0;

    virtual std::shared_future<RETURNTYPE> GetFuture() = 0;

protected:
    uint64_t id_;
    uint64_t tag_;
    uint64_t sequenceId_;
    std::function<RETURNTYPE(ARGSTYPE...)> runFunc_;
};

template <typename RETURNTYPE, typename... ARGSTYPE>
using RenderTaskPtr = std::shared_ptr<RenderTaskItf<RETURNTYPE, ARGSTYPE...>>;

template <typename RETURNTYPE, typename... ARGSTYPE> class TaskCompare {
public:
    bool operator () (const RenderTaskPtr<RETURNTYPE, ARGSTYPE...>& a, const RenderTaskPtr<RETURNTYPE, ARGSTYPE...>& b)
    {
        return !((*(a.get())) < (*(b.get())));
    }
};

template <typename RETURNTYPE, typename... ARGSTYPE>
void SetTag(const RenderTaskPtr<RETURNTYPE, ARGSTYPE...>& a, uint64_t tag)
{
    return (*(a.get())).SetTag(tag);
}

template <typename RETURNTYPE, typename... ARGSTYPE>
void SetFunc(const RenderTaskPtr<RETURNTYPE, ARGSTYPE...>& a, std::function<RETURNTYPE(ARGSTYPE...)> run)
{
    return (*(a.get())).SetRunFunc(run);
}

template <typename RETURNTYPE, typename... ARGSTYPE> uint64_t GetTag(const RenderTaskPtr<RETURNTYPE, ARGSTYPE...>& a)
{
    return (*(a.get())).GetTag();
}

using RenderCommonTaskPtr = RenderTaskPtr<void>;
using RenderTaskWithIdPtr = RenderTaskPtr<void, uint64_t>;
}
}

#endif