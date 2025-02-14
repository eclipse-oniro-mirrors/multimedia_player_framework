/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_HELPERDATASOURCECALLBACK_H
#define CJ_HELPERDATASOURCECALLBACK_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include "media_data_source.h"
#include "nocopyable.h"

namespace OHOS {
namespace Media {

struct HelperDataSourceCJCallback {
    HelperDataSourceCJCallback(
        const std::string& callbackName,
        const std::shared_ptr<AVSharedMemory>& mem,
        uint32_t length,
        int64_t pos)
        : callbackName_(callbackName), memory_(mem), length_(length), pos_(pos) {
    }
    ~HelperDataSourceCJCallback();
    void WaitResult();
    std::function<int32_t(uint8_t *, uint32_t, int64_t)> callback_;
    std::string callbackName_;
    std::shared_ptr<AVSharedMemory> memory_;
    uint32_t length_;
    int64_t pos_;
    int32_t readSize_ = 0;
    std::mutex mutexCond_;
    std::condition_variable cond_;
    bool setResult_ = false;
    bool isExit_ = false;
};

class CJHelperDataSourceCallback : public IMediaDataSource, public NoCopyable {
public:
    CJHelperDataSourceCallback(int64_t fileSize);
    virtual ~CJHelperDataSourceCallback();
    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1) override;
    int32_t GetSize(int64_t &size) override;
    int32_t GetCallbackId(int64_t &id);

    // This interface has been deprecated
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    // This interface has been deprecated
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override;
    int32_t SaveCallbackReference(const std::string &name, int64_t id);
    void ClearCallbackReference();
private:
    std::mutex mutex_;
    std::map<std::string, std::pair<int64_t, std::function<int32_t(uint8_t *, uint32_t, int64_t)>>> funcMap_;
    int64_t size_ = -1;
    std::shared_ptr<HelperDataSourceCJCallback> cb_ = nullptr;
};

} // namespace Media
} // namespace OHOS

#endif // CJ_HELPERDATASOURCECALLBACK_H
