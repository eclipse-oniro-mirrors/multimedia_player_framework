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

#ifndef MEDIA_LOG_H
#define MEDIA_LOG_H

#include <string>

#define MEDIA_LOGI(fmt, ...)
#define MEDIA_LOGW(fmt, ...)
#define MEDIA_LOGE(fmt, ...)
#define MEDIA_LOGD(fmt, ...)

#define PUBLIC_LOG_D64 "PRIu64"
#define PUBLIC_LOG_D32 "PRIu32"

#define CHECK_AND_RETURN_LOG(condition, ret, fmt, ...)
#define CHECK_AND_RETURN_RET_LOG(condition, ret, fmt, ...)
#define CHECK_AND_RETURN_RET_NOLOG(condition, ret, fmt, ...)
#define CHECK_AND_CONTINUE_LOG(condition, fmt, ...)
#define FALSE_RETURN_V_MSG_E(condition, ret, fmt, ...)
#define FALSE_RETURN_MSG(condition, fmt, ...)
#define FALSE_RETURN_V(condition, ret)
#define FALSE_RETURN(condition)

#define LOG_CORE 0
#define LOG_DOMAIN_PLAYER 0

#endif // MEDIA_LOG_H