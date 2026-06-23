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

#ifndef AVADS_CONTROLLER_NAPI_TEST_H
#define AVADS_CONTROLLER_NAPI_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <memory>
#include <string>
#include <mutex>

namespace OHOS {
namespace Media {

struct AdsAsyncContext {
    explicit AdsAsyncContext(void* env) : env_(env) {}
    ~AdsAsyncContext() = default;

    enum class OpType : uint8_t {
        ADD,
        REMOVE,
        SKIP,
        DISABLE_ALL,
    };

    OpType opType = OpType::ADD;
    std::shared_ptr<void> mediaSource = nullptr;
    int64_t startMs = 0;
    std::string adId;
    std::string outId;
    std::shared_ptr<void> player = nullptr;
    bool errFlag = false;
    int32_t errCode = 0;
    std::string errMessage = "";
    void* env_ = nullptr;
};

class AVAdsControllerNapi {
public:
    AVAdsControllerNapi() : player_(nullptr) {}
    ~AVAdsControllerNapi() {}

    void SetPlayer(void* player) {
        std::lock_guard<std::mutex> lock(mutex_);
        player_ = player;
    }
    void* GetPlayer() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return player_;
    }

private:
    void* player_;
    mutable std::mutex mutex_;
};

class AVAdsControllerNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::unique_ptr<AVAdsControllerNapi> controller_;
};

class AVAdsControllerNapiInterfaceTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}
};

} // namespace Media
} // namespace OHOS

#endif // AVADS_CONTROLLER_NAPI_TEST_H
