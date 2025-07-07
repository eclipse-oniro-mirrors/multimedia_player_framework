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
#ifndef MEDIA_LPP_ERRORS_H
#define MEDIA_LPP_ERRORS_H

#include "media_errors.h"

namespace OHOS {
namespace Media {

#ifdef SUPPORT_LPP
/**
 * @brief Enumerates HDF error codes.
 */
enum HDFErrCode : int32_t {
    HDF_ERR_OK = 0,                   /**< The operation is successful. */

    HDF_ERR_SHB_TIME_ANCHOR_GIANT_GAP = 0x010001,
    HDF_ERR_SHB_SET_SPEED_ERR = 0x010002,
    HDF_ERR_SHB_OUTPUT_BUFF_FOUND_ERR = 0x010003,
#define HDF_ERR_SHB_START (0x01FF00)         /**< Defines the start of error codes. */
#define HDF_ERR_SHB_NUM(v) (HDF_ERR_SHB_START + (v)) /**< Defines the error codes. */
    HDF_ERR_SHB_THREAD_CREATE_FAIL = HDF_ERR_SHB_NUM(1),
    HDF_ERR_SHB_MUTEX_INIT_FAIL = HDF_ERR_SHB_NUM(2),
    HDF_ERR_SHB_TIMER_INIT_FAIL = HDF_ERR_SHB_NUM(3),
    HDF_ERR_SHB_MSG_QUEUE_CREATE_FAIL = HDF_ERR_SHB_NUM(4),
    HDF_ERR_SHB_MEM_ALLOC_FAIL = HDF_ERR_SHB_NUM(5),
    HDF_ERR_SHB_DACC_INIT_FAIL = HDF_ERR_SHB_NUM(6),
    HDF_ERR_SHB_RS_RINGBUFF_INIT_FAIL = HDF_ERR_SHB_NUM(7),
    HDF_ERR_SHB_RS_UPLOAD_DATA_FAIL = HDF_ERR_SHB_NUM(8),
    HDF_ERR_SHB_VDEC_RINGBUFF_INIT_FAIL = HDF_ERR_SHB_NUM(9),
    HDF_ERR_SHB_SID_INVALID_ERR = HDF_ERR_SHB_NUM(10),
    HDF_ERR_SHB_INVALID_BUFF_CNT = HDF_ERR_SHB_NUM(11),

#define HDF_ERR_LPPDRV_START (0x020000)         /**< Defines the start of error codes. */
#define HDF_ERR_LPPDRV_NUM(v) (HDF_ERR_LPPDRV_START + (v)) /**< Defines the error codes. */
    HDF_ERR_LPPDRV_STATE_MACH_ERR = HDF_ERR_LPPDRV_NUM(1),
    HDF_ERR_LPPDRV_MMAP_FAIL = HDF_ERR_LPPDRV_NUM(0x00FF01),
    HDF_ERR_LPPDRV_SHB_CRASH = HDF_ERR_LPPDRV_NUM(0x00FF02),
    HDF_ERR_LPPDRV_INSTANCE_EXCEED_LIMIT = HDF_ERR_LPPDRV_NUM(0x00FF03),

#define HDF_ERR_DSS_START (0x03FF00)         /**< Defines the start of error codes. */
#define HDF_ERR_DSS_NUM(v) (HDF_ERR_DSS_START + (v)) /**< Defines the error codes. */
    HDF_ERR_DSS_CREATE_FAIL = HDF_ERR_DSS_NUM(1),
    HDF_ERR_DSS_MUTEX_TIMEOUT_FAIL = HDF_ERR_DSS_NUM(2),
    HDF_ERR_DSS_POWER_STATE_CHECK_FAIL = HDF_ERR_DSS_NUM(3),
    HDF_ERR_DSS_VSYNC_REGIST_FAIL = HDF_ERR_DSS_NUM(4),
};
#endif

__attribute__((visibility("default"))) MediaServiceErrCode AVCSErrorToMSError(int32_t code);
__attribute__((visibility("default"))) MediaServiceErrCode AudioStandardStatusToMSError(int32_t code);
__attribute__((visibility("default"))) MediaServiceErrCode AudioStandardErrorToMSError(int32_t code);
__attribute__((visibility("default"))) MediaServiceErrCode HDIStatusToMSError(int32_t code);
__attribute__((visibility("default"))) MediaServiceErrCode HDIErrorToMSError(int32_t code);

} // namespace Media
} // namespace OHOS
#endif // MEDIA_LPP_ERRORS_H