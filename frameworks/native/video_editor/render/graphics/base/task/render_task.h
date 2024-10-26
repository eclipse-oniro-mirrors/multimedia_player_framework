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

#ifndef OH_VEF_RENDER_TASK_H
#define OH_VEF_RENDER_TASK_H

#include <functional>
#include <future>
#include "render_task_interface.h"

namespace OHOS {
namespace Media {
template <typename RETURNTYPE = void, typename... ARGSTYPE>
class RenderTask : public RenderTaskItf<RETURNTYPE, ARGSTYPE...> {
public:
    RenderTask(std::function<RETURNTYPE(ARGSTYPE...)> run, uint64_t tag = 0, uint64_t id = 0)
        : barrier_(), barrierFuture_(barrier_.get_future())
    {
        RenderTaskItf<RETURNTYPE, ARGSTYPE...>::SetTag(tag);
        RenderTaskItf<RETURNTYPE, ARGSTYPE...>::SetId(id);
        RenderTaskItf<RETURNTYPE, ARGSTYPE...>::SetSequenceId(0);
        RenderTaskItf<RETURNTYPE, ARGSTYPE...>::SetRunFunc(run);
    }
    ~RenderTask() = default;

    void Run(ARGSTYPE... args) override
    {
        RunImpl<decltype(this), RETURNTYPE, ARGSTYPE...> impl(this);
        impl(args...);
    };

    void Wait() override
    {
        barrierFuture_.wait();
    };

    RETURNTYPE GetReturn() override
    {
        return barrierFuture_.get();
    };

    std::shared_future<RETURNTYPE> GetFuture() override
    {
        return barrierFuture_;
    };

private:
    template <typename THISPTYTPE, typename RUNRETURNTYPE, typename... RUNARGSTYPE> class RunImpl {
    public:
        explicit RunImpl(THISPTYTPE p)
        {
            pType_ = p;
        }
        void operator () (RUNARGSTYPE... args)
        {
            pType_->barrier_.set_value(pType_->runFunc_(args...));
        }
        THISPTYTPE pType_;
    };

    template <typename THISPTYTPE, typename... RUNARGSTYPE> struct RunImpl<THISPTYTPE, void, RUNARGSTYPE...> {
        explicit RunImpl(THISPTYTPE p)
        {
            pType_ = p;
        }
        void operator () (RUNARGSTYPE... args)
        {
            pType_->runFunc_(args...);
            pType_->barrier_.set_value();
        }
        THISPTYTPE pType_;
    };

private:
    std::promise<RETURNTYPE> barrier_;
    std::shared_future<RETURNTYPE> barrierFuture_;
};
}
}

#endif