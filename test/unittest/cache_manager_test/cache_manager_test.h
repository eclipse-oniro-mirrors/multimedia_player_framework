/*
* Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef CACHE_MANAGER_TEST_H
#define CACHE_MANAGER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "cache_manager.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace Media {
class CacheManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
private:
    std::unique_ptr<StreamCacheManager> manager_;
};
} // namespace Media
} // namespace OHOS
#endif // CACHE_MANAGER_TEST_H