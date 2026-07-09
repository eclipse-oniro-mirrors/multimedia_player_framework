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

#ifndef AVDOWNLOADER_MANAGER_NAPI_TEST_H
#define AVDOWNLOADER_MANAGER_NAPI_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include <map>
#include "av_downloader_manager.h"
#include "avdownloader_manager_napi.h"

namespace OHOS {
namespace Media {

class MockAVDownloaderManager : public AVDownloaderManager {
public:
    MOCK_METHOD(int32_t, SetAllowCellularAccess, (bool allow), (override));
    MOCK_METHOD(int32_t, SetRequestTimeout, (int32_t timeoutMs), (override));
    MOCK_METHOD(std::string, AddDownloadTask, (std::shared_ptr<Plugins::MediaSource> source), (override));
    MOCK_METHOD(int32_t, RemoveDownloadTask, (const std::string &taskId), (override));
    MOCK_METHOD(int32_t, PauseDownloadTask, (const std::string &taskId), (override));
    MOCK_METHOD(int32_t, ResumeDownloadTask, (const std::string &taskId), (override));
    MOCK_METHOD(std::vector<std::string>, GetDownloadTasks, (), (override));
    MOCK_METHOD(std::string, GetTaskCacheDirectory, (const std::string &taskId), (override));
    MOCK_METHOD(AVDownloadTaskState, GetTaskStatus, (const std::string &taskId), (override));
    MOCK_METHOD(double, GetTaskProgress, (const std::string &taskId), (override));
    MOCK_METHOD(int32_t, SetManagerCallback, (const std::weak_ptr<AVDownloaderManagerCallback> &callback), (override));
    MOCK_METHOD(int32_t, Release, (), (override));
};

class AVDownloaderManagerNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<MockAVDownloaderManager> mockManager_;
};

} // namespace Media
} // namespace OHOS

#endif // AVDOWNLOADER_MANAGER_NAPI_TEST_H
