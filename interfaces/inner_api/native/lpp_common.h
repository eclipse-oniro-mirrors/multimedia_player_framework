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

#ifndef LPP_COMMON_H
#define LPP_COMMON_H

#include <refbase.h>
#include "buffer/avbuffer.h"
#include "avcodec_common.h"

namespace OHOS {
namespace Media {
 
enum LppErrCode : int32_t {
    LPP_ERROR_OK = 0,
    LPP_ERROR_UNKONWN,
};
 
class LppDataPacket : public OHOS::RefBase {
public:
    
    virtual ~LppDataPacket() = default;
    int32_t GetRemainedCapacity();
    bool AppendOneBuffer(const std::shared_ptr<AVBuffer> &buffer);
    bool WriteToMessageParcel(MessageParcel &parcel);
    bool ReadFromMessageParcel(MessageParcel &parcel);
    virtual bool WriteToByteBuffer(std::shared_ptr<AVBuffer> &buffer);
    bool ReadFromByteBuffer(uint8_t *buffer, int32_t capacity);
    bool IsEmpty();
    virtual bool WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &buffer);
    int WriteOneFrameToAVBuffer(std::shared_ptr<AVBuffer> &avbuffer, int bufferOffset);
    void Clear();
    void Init();

public:
    std::vector<uint32_t> flag_;
    std::vector<int64_t> pts_;
    std::vector<int> size_;
    std::shared_ptr<AVMemory> memory_ {nullptr};

private:
    bool WriteVector(MessageParcel &parcel);
    bool ReadVector(MessageParcel &parcel);
    bool IsEos();
    int dataOffset_ {0};
    size_t vectorReadIndex_ {0};
    uint32_t frameCount_ {0};
};
 
} // namespace Media
} // namespace OHOS
#endif // LPP_COMMON_H