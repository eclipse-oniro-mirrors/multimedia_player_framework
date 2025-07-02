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

#ifndef HDI_NATIVE_BUFFER_H
#define HDI_NATIVE_BUFFER_H

#include "buffer_handle.h"
#include <refbase.h>

namespace OHOS {
namespace HDI {
namespace Base {

class NativeBuffer : public RefBase {
public:
    NativeBuffer()
    {
    }
    explicit NativeBuffer(const BufferHandle *handle)
    {
        (void)handle;
    }
};
} // namespace Base
} // namespace HDI
} // namespace OHOS

#endif // HDI_NATIVE_BUFFER_H
