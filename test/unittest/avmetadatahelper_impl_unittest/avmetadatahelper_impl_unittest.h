/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef AVMETADATAHELPER_IMPL_UNITTEST_H
#define AVMETADATAHELPER_IMPL_UNITTEST_H

#include "gtest/gtest.h"
#include "mock/mock_avbuffer.h"
#include "mock/mock_pixel_map.h"
#include "avmetadatahelper_impl.h"

namespace OHOS {
namespace Media {
class AVMetadataHelperImplUnitTest : public testing::Test {
public:
    // SetUpTestCase: before all testcases
    static void SetUpTestCase(void);
    // TearDownTestCase: after all testcase
    static void TearDownTestCase(void);
    // SetUp
    void SetUp(void);
    // TearDown
    void TearDown(void);

private:
    std::shared_ptr<AVMetadataHelperImpl> metadataHelperImpl_;
};
} // Media
} // OHOS
#endif // AVMETADATAHELPER_IMPL_UNITTEST_H
