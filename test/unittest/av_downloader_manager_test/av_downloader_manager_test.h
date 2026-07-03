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

#ifndef AVDOWNLOADER_MANAGER_TEST_H
#define AVDOWNLOADER_MANAGER_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "av_downloader_manager.h"
#include "av_downloader_manager_impl.h"
#include "network_utils.h"

namespace OHOS {
namespace Media {

class MockAVDownloaderManagerCallback : public AVDownloaderManagerCallback {
public:
    MOCK_METHOD(void, OnStatusChange, (const std::string &taskId, AVDownloadTaskState state), (override));
    MOCK_METHOD(void, OnProgressChange, (const std::string &taskId, double progress), (override));
};

class TestableAVDownloaderManager : public AVDownloaderManagerImpl {
protected:
    MediaSourceUtils::NetConnType GetNetworkType() override
    {
        return simulatedNetworkType_;
    }
public:
    MediaSourceUtils::NetConnType simulatedNetworkType_ = MediaSourceUtils::NetConnType::NET_CONN_WIFI;
};

class AVDownloaderManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<AVDownloaderManagerImpl> managerImpl_;
    std::shared_ptr<MockAVDownloaderManagerCallback> mockCallback_;
};

} // namespace Media
} // namespace OHOS

#endif // AVDOWNLOADER_MANAGER_TEST_H
