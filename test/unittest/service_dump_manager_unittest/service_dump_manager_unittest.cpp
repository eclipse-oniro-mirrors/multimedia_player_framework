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

#include "service_dump_manager_unittest.h"
#include "media_errors.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

static const int32_t NUM_1 = 1;

void ServiceDumpManagerUnitTest::SetUpTestCase(void)
{
}

void ServiceDumpManagerUnitTest::TearDownTestCase(void)
{
}

void ServiceDumpManagerUnitTest::SetUp(void)
{
    manager_ = std::make_shared<ServiceDumpManager>();
}

void ServiceDumpManagerUnitTest::TearDown(void)
{
    manager_ = nullptr;
}

/**
 * @tc.name  : Test Dump
 * @tc.number: Dump_001
 * @tc.desc  : Test RegisterDfxDumper
 *             Test Dump args.find(static_cast<std::u16string>(iter.first)) != args.end()
 *             Test Dump fd != -1
 *             Test Dump iter.second(fd) != MSERR_OK
 *             Test Dump args.find(static_cast<std::u16string>(iter.first)) == args.end()
 * *           Test UnregisterDfxDumper
 */
HWTEST_F(ServiceDumpManagerUnitTest, Dump_001, TestSize.Level0)
{
    // Test RegisterDfxDumper
    ASSERT_NE(manager_, nullptr);
    DfxDumper dumper = [](int32_t fd) -> int32_t { return MSERR_INVALID_OPERATION;};
    std::u16string key = u"TestDumper";
    manager_->RegisterDfxDumper(key, dumper);

    // Test Dump fd != -1
    // Test Dump iter.second(fd) != MSERR_OK
    int32_t fd = NUM_1;
    std::unordered_set<std::u16string> args = { u"TestDumper"};
    auto result = manager_->Dump(fd, args);
    EXPECT_EQ(result, MSERR_INVALID_OPERATION);
    // Test Dump args.find(static_cast<std::u16string>(iter.first)) == args.end()
    args.clear();
    result = manager_->Dump(fd, args);
    EXPECT_EQ(result, MSERR_OK);

    // Test UnregisterDfxDumper
    manager_->UnregisterDfxDumper();
}

} // namespace Media
} // namespace OHOS