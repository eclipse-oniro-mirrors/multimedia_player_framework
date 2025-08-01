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

#ifndef HDF_BASE_TYPE_H
#define HDF_BASE_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Enumerates HDF return value types.
 */
typedef enum {
    HDF_SUCCESS  = 0, /**< The operation is successful. */
    HDF_FAILURE = -1, /**< Failed to invoke the OS underlying function. */
} HDF_STATUS;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* HDF_BASE_TYPE_H */
/** @} */
