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

#ifndef MEDIA_SERVER_DATASHARE_H
#define MEDIA_SERVER_DATASHARE_H
#include <stdint.h>
#include <string> 

namespace OHOS {
namespace Media {
int32_t UpdateSettingsValue(const std::string &key, const std::string &value);
} // namespace Media
} // namespace OHOS
#endif
