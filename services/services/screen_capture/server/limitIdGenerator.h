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

#ifndef SCREEN_CAPTURE_LIMIT_ID_GENERATOR_H
#define SCREEN_CAPTURE_LIMIT_ID_GENERATOR_H

#include <iostream>
#include <queue>
#include <mutex>

namespace OHOS {
namespace Media {
class UniqueIDGenerator {
public:
    explicit UniqueIDGenerator(int32_t limit);
    ~UniqueIDGenerator();
    int32_t GetNewID();
    int32_t ReturnID(int32_t id);

private:
    std::queue<int32_t> availableIDs_;
    int32_t limit_ = 0;
    std::mutex queueMtx_;
};
} // namespace Media
} // namespace OHOS

#endif // SCREEN_CAPTURE_LIMIT_ID_GENERATOR_H