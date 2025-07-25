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

#ifndef AVSHAREDMEMORY_IPC_H
#define AVSHAREDMEMORY_IPC_H

#include <message_parcel.h>
#include "buffer/avsharedmemory.h"

namespace OHOS {
namespace Media {
int32_t WriteAVSharedMemoryToParcel(const std::shared_ptr<AVSharedMemory> &memory,
    MessageParcel &parcel);
std::shared_ptr<AVSharedMemory> ReadAVSharedMemoryFromParcel(MessageParcel &parcel);
std::shared_ptr<AVSharedMemory> ReadAVDataSrcMemoryFromParcel(MessageParcel &parcel);
} // namespace Media
} // namespace OHOS
#endif
