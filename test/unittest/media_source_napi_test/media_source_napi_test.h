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

#ifndef MEDIA_SOURCE_NAPI_TEST_H
#define MEDIA_SOURCE_NAPI_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <string>
#include <memory>
#include <vector>
#include "media_source.h"

namespace OHOS {
namespace Media {

class MockMediaSource : public Plugins::MediaSource {
public:
    MockMediaSource() : Plugins::MediaSource("") {}
    explicit MockMediaSource(const std::string &url) : Plugins::MediaSource(url) {}

    MOCK_METHOD(std::string, GetSourceUri, (), (const, override));
    MOCK_METHOD(MediaSourceType, GetSourceType, (), (const, override));
    MOCK_METHOD(std::vector<std::string>, GetSupportedProtocols, (), (const, override));
    MOCK_METHOD(std::vector<ProtocolType>, GetProtocolTypes, (), (const, override));
};

class MediaSourceNapiTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp(void) {}
    void TearDown(void) {}

protected:
    std::shared_ptr<MockMediaSource> mockMediaSource_;
};

} // namespace Media
} // namespace OHOS

#endif // MEDIA_SOURCE_NAPI_TEST_H
