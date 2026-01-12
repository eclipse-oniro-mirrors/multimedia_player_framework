/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_TADK_HANDLER_H
#define MOCK_TADK_HANDLER_H

#include "task_queue.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockTaskHandler : public ITaskHandler {
public:
    MockTaskHandler() = default;
    virtual ~MockTaskHandler() = default;

    MOCK_METHOD0(Execute, void());
    MOCK_METHOD0(Cancel, void());
    MOCK_METHOD0(IsCanceled, bool());
    MOCK_CONST_METHOD0(GetAttribute, Attribute());
    MOCK_METHOD0(Clear, void());
};
}  // namespace Media
}  // namespace OHOS
#endif // MOCK_TADK_HANDLER_H
