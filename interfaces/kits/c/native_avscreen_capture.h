/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#ifndef NATIVE_AVSCREEN_CAPTURE_H
#define NATIVE_AVSCREEN_CAPTURE_H

#include <stdint.h>
#include <stdio.h>
#include "native_avscreen_capture_errors.h"
#include "native_avscreen_capture_base.h"
#include "external_window.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @return Returns a pointer to an OH_AVScreenCapture instance
 * @since 10
 * @version 1.0
 */
struct OH_AVScreenCapture *OH_AVScreenCapture_Create(void);

/**
 * @brief To init the screen capture, typically, you need to configure the description information of the audio
 * and video, which can be extracted from the container. This interface must be called before StartAVScreenCapture
 * called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param config Information describing the audio and video config
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Init(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureConfig config);

/**
 * @brief Start the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenCapture(struct OH_AVScreenCapture *capture);

/**
 * @brief Start the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param window Pointer to an OHNativeWindow instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenCaptureWithSurface(struct OH_AVScreenCapture *capture,
    OHNativeWindow* window);

/**
 * @brief Stop the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StopScreenCapture(struct OH_AVScreenCapture *capture);

/**
 * @brief Start av screen record use to start save screen record file.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StartScreenRecording(struct OH_AVScreenCapture *capture);

/**
 * @brief Start av screen record use to stop save screen record file.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StopScreenRecording(struct OH_AVScreenCapture *capture);

/**
 * @brief Acquire the audio buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param audiobuffer Information describing the audio buffer of the capture
 * @param type Information describing the audio source type
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @deprecated since 12
 * @useinstead {@link OH_AVScreenCapture_OnBufferAvailable}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_AcquireAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AudioBuffer **audiobuffer, OH_AudioCaptureSourceType type);

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @deprecated since 12
 * @useinstead {@link OH_AVScreenCapture_OnBufferAvailable}
 * @since 10
 * @version 1.0
 */
OH_NativeBuffer* OH_AVScreenCapture_AcquireVideoBuffer(struct OH_AVScreenCapture *capture,
    int32_t *fence, int64_t *timestamp, struct OH_Rect *region);

/**
 * @brief Release the audio buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param type Information describing the audio source type
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @deprecated since 12
 * @useinstead {@link OH_AVScreenCapture_OnBufferAvailable}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseAudioBuffer(struct OH_AVScreenCapture *capture,
    OH_AudioCaptureSourceType type);

/**
 * @brief Release the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @deprecated since 12
 * @useinstead {@link OH_AVScreenCapture_OnBufferAvailable}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseVideoBuffer(struct OH_AVScreenCapture *capture);

/**
 * @brief Set the callback function so that your application
 * can respond to the events generated by the av screen capture. This interface must be called before Init is called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback A collection of all callback functions, see {@link OH_AVScreenCaptureCallback}
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @deprecated since 12
 * @useinstead {@link OH_AVScreenCapture_SetErrorCallback} {@link OH_AVScreenCapture_SetDataCallback}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCallback(struct OH_AVScreenCapture *capture,
    struct OH_AVScreenCaptureCallback callback);

/**
 * @brief Release the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_Release(struct OH_AVScreenCapture *capture);

/**
 * @brief Controls the switch of the microphone, which is turned on by default
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param isMicrophone The switch of the microphone
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 10
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetMicrophoneEnabled(struct OH_AVScreenCapture *capture,
    bool isMicrophone);
/**
 * @brief Set the state callback function so that your application can respond to the
 * state change events generated by the av screen capture. This interface must be called before Start is called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback State callback function, see {@link OH_AVScreenCapture_OnStateChange}
 * @param userData Pointer to user specific data
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetStateCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnStateChange callback, void *userData);

/**
 * @brief Set the data callback function so that your application can respond to the
 * data available events generated by the av screen capture. This interface must be called before Start is called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback Data callback function, see {@link OH_AVScreenCapture_OnBufferAvailable}
 * @param userData Pointer to user specific data
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetDataCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnBufferAvailable callback, void *userData);

/**
 * @brief Set the error callback function so that your application can respond to the
 * error events generated by the av screen capture. This interface must be called before Start is called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback Error callback function, see {@link OH_AVScreenCapture_OnError}
 * @param userData Pointer to user specific data
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetErrorCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnError callback, void *userData);

/**
 * @brief Controls the Rotation of the Screen, which is no rotate by default
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param canvasRotation Rotate The screen or not
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCanvasRotation(struct OH_AVScreenCapture *capture,
    bool canvasRotation);

/**
 * @brief Create a screen capture content filter
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @return Returns a pointer to an OH_AVScreenCapture_ContentFilter instance
 * @since 12
 * @version 1.0
 */
struct OH_AVScreenCapture_ContentFilter *OH_AVScreenCapture_CreateContentFilter(void);

/**
 * @brief Release the screen capture content filter
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param filter Pointer to an OH_AVScreenCapture_ContentFilter instance
 * @return Returns AVSCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseContentFilter(struct OH_AVScreenCapture_ContentFilter *filter);

/**
 * @brief Add content to the screen capture content filter
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param filter Pointer to an OH_AVScreenCapture_ContentFilter instance
 * @param content content to be added
 * @return Returns AVSCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ContentFilter_AddAudioContent(
    struct OH_AVScreenCapture_ContentFilter *filter, OH_AVScreenCaptureFilterableAudioContent content);

/**
 * @brief Set content filter to screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param filter Pointer to an OH_AVScreenCapture_ContentFilter instance
 * @return Returns AVSCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ExcludeContent(struct OH_AVScreenCapture *capture,
    struct OH_AVScreenCapture_ContentFilter *filter);

/**
  * @brief Configures exclusion list for system-level picker window
  * @details Filters specified windows before displaying the system-level picker.
  *          Excluded windows will not appear in the selection list.
  * @param capture [in] Screen capture handle created via OH_AVScreenCapture_Create
  * @param excludedWindowIDs [in] Array of window IDs to exclude (process-local)
  * @param windowCount [in] Number of excluded windows
  * @return Operation status codes:
  *         - AV_SCREEN_CAPTURE_ERR_OK: Success
  *         - AV_SCREEN_CAPTURE_ERR_INVALID_VAL: Invalid parameters
  *             (null pointer/cross-process window IDs)
  *         - AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT: Insufficient permissions
  * @since 22
  */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ExcludePickerWindows(
    struct OH_AVScreenCapture *capture, const int32_t *excludedWindowIDs, uint32_t windowCount);

/**
  * @brief Sets the mode for the system-level screen capture picker
  * @details Defines the content type displayed in the system-level picker.
  *          Mode changes take effect upon the next call to function PresentPicker.
  * @param capture [in] Pointer to the screen capture instance created via OH_AVScreenCapture_Create
  * @param pickerMode [in] Picker display mode (see OH_CapturePickerMode enum)
  * @return Operation status codes:
  *         - AV_SCREEN_CAPTURE_ERR_OK: Mode configuration succeeded
  *         - AV_SCREEN_CAPTURE_ERR_INVALID_VAL: Invalid mode value or null pointer
  *         - AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT: Ongoing capture session exists
  * @since 22
  */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetPickerMode(
    struct OH_AVScreenCapture *capture, OH_CapturePickerMode pickerMode);

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_AddWhiteListWindows(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount);

OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_RemoveWhiteListWindows(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount);

/**
 * @brief Add Window content to the screen capture content filter
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param filter Pointer to an OH_AVScreenCapture_ContentFilter instance
 * @param windowIDs Pointer to windowIDs to be added
 * @param windowCount length of windowID list
 * @return Returns AV_SCREEN_CAPTURE_ERR_OK if the execution is successful,
 * otherwise returns a specific error code, refer to {@link OH_AVSCREEN_CAPTURE_ErrCode}
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ContentFilter_AddWindowContent(
    struct OH_AVScreenCapture_ContentFilter *filter, int32_t *windowIDs, int32_t windowCount);

/**
 * @brief Resize the Resolution of the Screen
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param width Video frame width of avscreeencapture
 * @param height Video frame height of avscreeencapture
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr.
 *         {@link AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT} opertation not be permitted.
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ResizeCanvas(struct OH_AVScreenCapture *capture,
    int32_t width, int32_t height);

/**
 * @brief skip some windows' privacy mode of current app during the screen recording
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param windowIDs Pointer of windowID list
 * @param windowCount length of windowID list
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or input windowIDs are not belong current
 *         app.
 *         {@link AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT} opertation not be permitted.
 * @since 12
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SkipPrivacyMode(struct OH_AVScreenCapture *capture,
    int32_t *windowIDs, int32_t windowCount);

/**
 * @brief set up the max number of video frame per second
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param frameRate max frame rate of video
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or frameRate is not support.
 *         {@link AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT} opertation not be permitted.
 * @since 14
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetMaxVideoFrameRate(struct OH_AVScreenCapture *capture,
    int32_t frameRate);

/**
 * @brief determines whether the cursor is visible in the session
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param showCursor The switch of the cursor
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr.
 *         {@link AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT} opertation not be permitted, show cursor failed.
 * @since 15
 * @version 1.0
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ShowCursor(struct OH_AVScreenCapture *capture,
    bool showCursor);

/**
 * @brief Set the display device selection callback function so that your application can respond to the
 * display device selected event generated by the av screen capture.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback display device selection callback function, see {@link OH_AVScreenCapture_OnDisplaySelected}
 * @param userData Pointer to user specific data
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or input callback is nullptr.
 *         {@link AV_SCREEN_CAPTURE_ERR_NO_MEMORY} no memory, mem allocate failed.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_STATE} This interface should be called before Start is called.
 * @since 15
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetDisplayCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnDisplaySelected callback, void *userData);

/**
 * @brief Create a screen capture Strategy object
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @return Returns a pointer to the screen capture strategy object, or null if failure
 * @since 20
 */
OH_AVScreenCapture_CaptureStrategy* OH_AVScreenCapture_CreateCaptureStrategy(void);

/**
 * @brief Release the screen capture Strategy object
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input strategy is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_ReleaseCaptureStrategy(OH_AVScreenCapture_CaptureStrategy* strategy);

/**
 * @brief set the screen capture strategy for the specified screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture*} capture Pointer to an OH_AVScreenCapture which need to be setted.
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy which want to
 * set.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} capture or strategyvalue is nullptr.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_STATE} This interface should be called before Start is called.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureStrategy(
    struct OH_AVScreenCapture *capture, OH_AVScreenCapture_CaptureStrategy *strategy);

/**
 * @brief Call Settings Policy value for whether to allow screen capture during cellular calls
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {bool} value The default value is false, which means that screen recording is not allowed during cellular
 * calls.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy value is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForKeepCaptureDuringCall(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value);

/**
 * @brief Set the Capture Content Changed callback function so that your application can
 * customize event handler generated by the screen capture. This interface must be called before Start is called.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param callback contentchanged callback function, see {@link OH_AVScreenCapture_OnCaptureContentChanged}
 * @param userData Pointer to user specific data
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or input callback is nullptr.
 *         {@link AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT} opertation not be permitted, set ErrorCallback failed.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureContentChangedCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnCaptureContentChanged callback, void *userData);

/**
 * @brief Set or update the captureArea
 * @param {struct OH_AVScreenCapture*} capture capture Pointer to an OH_AVScreenCapture instance
 * @param {uint64_t} displayId Indicates the screen index for setting area recording
 * @param {OH_Rect*} area Pointer to an object describing the location and size of the region
 * @return Function result code.
 *          {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *          {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or displayid not exist or area is
            invalid.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureArea(struct OH_AVScreenCapture *capture,
    uint64_t displayId, OH_Rect* area);

/**
 * @brief Set the fill mode for screen capture when a privacy window exists
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {int32_t} value
 * If set to 0, it means that when there is a privacy window interface, the output screen image is completely black.
 * If set to 1, it means that when there is a privacy window interface, only the privacy window area of the output
 * screen becomes black, and other values returns an error.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy is nullptr or value is invalid.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPrivacyMaskMode(
    OH_AVScreenCapture_CaptureStrategy *strategy, int32_t value);

/**
 * @brief Set the canvas to rotate with the screen when capturing the screen
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {bool} value The default value is False, which means that the width and height of the VirtualDisplay
 * remain the initial settings. If set to True, it means that the width and height of the VirtualDisplay rotates
 * with the rotation of the screen..
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy value is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForCanvasFollowRotation(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value);

/**
 * @brief Register user selection notification callback function
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture*} capture Pointer to OH_AVScreenCapture which want to handle user selection info
 * @param {OH_AVScreenCapture_OnUserSelected} callback user selection callback function, see
 *        {@link OH_AVScreenCapture_OnUserSelected}
 * @param {void*} userData The control block pointer passed by the application is carried to the application when it
 *        is returned
 * @return Function result code.
 *          {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *          {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetSelectionCallback(struct OH_AVScreenCapture *capture,
    OH_AVScreenCapture_OnUserSelected callback, void *userData);

/**
 * @brief Get the recording content type selected by the user in the confirmation interface
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_UserSelectionInfo*} selection Pointer to an OH_AVScreenCapture_UserSelectionInfo instance
 * @param {int32_t*} type The capture object type selected by the user, 0: represents the screen, 1: represents the
 *        window.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} if selections is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetCaptureTypeSelected(OH_AVScreenCapture_UserSelectionInfo *selection,
    int32_t* type);

/**
 * @brief Get the Display ID of user selections in the confirmation interface
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_UserSelectionInfo*} selection Pointer to an OH_AVScreenCapture_UserSelectionInfo instance
 * @param {uint64_t*} displayId Returns the screen ID value selected by the user
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} if selections is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_GetDisplayIdSelected(OH_AVScreenCapture_UserSelectionInfo *selection,
    uint64_t* displayId);

/**
 * @brief Indicates whether to enable B-frame encoding, which is used to reduce the size of the recorded file.
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {bool} value The default value is false, which means B frames encoding are disabled.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForBFramesEncoding(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value);

/**
 * @brief set whether to pop up the screen capture Picker
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {bool} value
 *          if set to false, it means that the APP don't need to pop up the Picker after screen capture starts;
 *          if set to true, the Picker will pop up uniformly after screen capture starts;
 *          if not set, it means using the system recommended behavior.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy value is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForPickerPopUp(
    OH_AVScreenCapture_CaptureStrategy *strategy, bool value);

/**
 * @brief Set the fill mode of the captured image in the target area
 * @param {OH_AVScreenCapture_CaptureStrategy*} strategy Pointer to an OH_AVScreenCapture_CaptureStrategy instance
 * @param {OH_AVScreenCapture_FillMode} mode Value of the captured image fill mode
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} strategy value is nullptr.
 * @since 20
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_StrategyForFillMode(
    OH_AVScreenCapture_CaptureStrategy *strategy, OH_AVScreenCapture_FillMode mode);

/**
 * @brief set the highlight style of recording area.
 * @param {OH_AVScreenCapture*} capture Pointer to OH_AVScreenCapture which want to set highlight style.
 * @param {OH_AVScreenCaptureHighlightConfig} config the highlight parameters are to be set for this screen capture.
 * @return Function result code.
 *         {@link AV_SCREEN_CAPTURE_ERR_OK} if the execution is successful.
 *         {@link AV_SCREEN_CAPTURE_ERR_INVALID_VAL} input capture is nullptr or config is invalid.
 * @since 22
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_SetCaptureAreaHighlight(struct OH_AVScreenCapture *capture,
    OH_AVScreenCaptureHighlightConfig config);

/**
 * @brief Displays system-level picker for screen capture source selection
 * @details Activates system visual picker with two usage scenarios:
 *          1. Initial capture configuration: Select source before starting capture
 *          2. Dynamic source switching: Change capture target during active capture
 * @param capture [in] Initialized screen capture instance
 * @return Operation status codes:
 *         - AV_SCREEN_CAPTURE_ERR_OK(0): Picker activated successfully
 *         - AV_SCREEN_CAPTURE_ERR_INVALID_VAL: Null pointer or uninitialized instance
 *         - AV_SCREEN_CAPTURE_ERR_OPERATE_NOT_PERMIT: Permission denied or system restriction
 *         - AV_SCREEN_CAPTURE_ERR_SERVICE_DIED: System UI service unavailable
 * @since 22
 */
OH_AVSCREEN_CAPTURE_ErrCode OH_AVScreenCapture_PresentPicker(struct OH_AVScreenCapture *capture);
#ifdef __cplusplus
}
#endif

#endif // NATIVE_AVSCREEN_CAPTURE_H