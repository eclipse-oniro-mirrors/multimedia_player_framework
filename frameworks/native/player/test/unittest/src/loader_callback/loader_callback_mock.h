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

#ifndef PLAYER_LOADING_REQUEST_UNIT_TEST_H
#define PLAYER_LOADING_REQUEST_UNIT_TEST_H

#include "loading_request.h"
#include "task_queue.h"
namespace OHOS {
namespace Media {

class MockLoaderCallback : public LoaderCallback {
public:
    MockLoaderCallback();
    ~MockLoaderCallback();
    int64_t Open(std::shared_ptr<LoadingRequest> &request);
    void Read(int64_t uuid, int64_t requestedOffset, int64_t requestedLength);
    void Close(int64_t uuid);

private:
    std::map<int64_t, std::shared_ptr<LoadingRequest>> requests_;
    FILE *file_ = nullptr;
    TaskQueue taskQue_;
};
} // namespace Media
} // namespace OHOS

#endif