/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef DOWNLOADED_CACHE_LOADER_TEST_H
#define DOWNLOADED_CACHE_LOADER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "downloaded_cache_loader.h"
#include "cache_manager.h"
#include "loading_request.h"

namespace OHOS {
namespace Media {

class MockLoadingRequest : public LoadingRequest {
public:
    MOCK_METHOD(int32_t, RespondData, (int64_t uuid, int64_t offset, const std::shared_ptr<AVSharedMemory> &mem), (override));
    MOCK_METHOD(int32_t, RespondHeader, (int64_t uuid, std::map<std::string, std::string> header, std::string redirectUrl), (override));
    MOCK_METHOD(int32_t, FinishLoading, (int64_t uuid, int32_t requestedError), (override));
    MOCK_METHOD(uint64_t, GetUniqueId, (), (override));
    MOCK_METHOD(std::string, GetUrl, (), (override));
    MOCK_METHOD(std::map<std::string, std::string>, GetHeader, (), (override));
};

class DownloadedCacheLoaderTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<DownloadedCacheManager> cacheManager_;
    std::shared_ptr<DownloadedCacheLoader> cacheLoader_;
};

} // namespace Media
} // namespace OHOS

#endif // DOWNLOADED_CACHE_LOADER_TEST_H
