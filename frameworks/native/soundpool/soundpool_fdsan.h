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
#ifndef SOUNDPOOL_FDSAN_H
#define SOUNDPOOL_FDSAN_H

#include <cstdio>

namespace OHOS {
namespace Media {
constexpr uint64_t FDSAN_VALUE_MASK = 0x00FFFFFFFFFFFFFF;
constexpr uint64_t FDSAN_INSTANCE_MASK = 0x00000000FFFFFFFF;
} // namespace Media
} // namespace OHOS

#endif // SOUNDPOOL_FDSAN_H