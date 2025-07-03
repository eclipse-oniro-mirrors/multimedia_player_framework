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

#ifndef MOCK_EVENT_RECEIVER_H
#define MOCK_EVENT_RECEIVER_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {

class MockEventReceiver : public Media::Pipeline::EventReceiver {
public:
    MOCK_METHOD(void, OnEvent, (const Event& event), (override));
    MOCK_METHOD(void, NotifyRelease, (), (override));
};
}  // namespace Media
}  // namespace OHOS
#endif  // MOCK_EVENT_RECEIVER_H