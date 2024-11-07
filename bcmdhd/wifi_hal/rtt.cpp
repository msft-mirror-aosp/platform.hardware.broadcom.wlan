/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Portions copyright (C) 2023 Broadcom Limited
 *
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

#include <stdint.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/rtnetlink.h>
#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/errqueue.h>

#include <linux/pkt_sched.h>
#include <netlink/object-api.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

#include "nl80211_copy.h"

#include "sync.h"

#define LOG_TAG  "WifiHAL"

#include <log/log.h>
#include <utils/String8.h>

#include <hardware_legacy/wifi_hal.h>
#include "common.h"
#include "cpp_bindings.h"

using namespace android;
#define RTT_RESULT_V3_SIZE (sizeof(wifi_rtt_result_v3))
#define RTT_RESULT_V2_SIZE (sizeof(wifi_rtt_result_v2))
#define RTT_RESULT_V1_SIZE (sizeof(wifi_rtt_result))
#define UNSPECIFIED -1 // wifi HAL common definition for unspecified value
typedef enum {

    RTT_SUBCMD_SET_CONFIG = ANDROID_NL80211_SUBCMD_RTT_RANGE_START,
    RTT_SUBCMD_CANCEL_CONFIG,
    RTT_SUBCMD_GETCAPABILITY,
    RTT_SUBCMD_GETAVAILCHANNEL,
    RTT_SUBCMD_SET_RESPONDER,
    RTT_SUBCMD_CANCEL_RESPONDER,
} RTT_SUB_COMMAND;

typedef enum {
    RTT_ATTRIBUTE_TARGET_INVALID            = 0,
    RTT_ATTRIBUTE_TARGET_CNT                = 1,
    RTT_ATTRIBUTE_TARGET_INFO               = 2,
    RTT_ATTRIBUTE_TARGET_MAC                = 3,
    RTT_ATTRIBUTE_TARGET_TYPE               = 4,
    RTT_ATTRIBUTE_TARGET_PEER               = 5,
    RTT_ATTRIBUTE_TARGET_CHAN               = 6,
    RTT_ATTRIBUTE_TARGET_PERIOD             = 7,
    RTT_ATTRIBUTE_TARGET_NUM_BURST          = 8,
    RTT_ATTRIBUTE_TARGET_NUM_FTM_BURST      = 9,
    RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTM      = 10,
    RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTMR     = 11,
    RTT_ATTRIBUTE_TARGET_LCI                = 12,
    RTT_ATTRIBUTE_TARGET_LCR                = 13,
    RTT_ATTRIBUTE_TARGET_BURST_DURATION     = 14,
    RTT_ATTRIBUTE_TARGET_PREAMBLE           = 15,
    RTT_ATTRIBUTE_TARGET_BW                 = 16,
    RTT_ATTRIBUTE_TARGET_NTB_MIN_MEAS_TIME  = 17,
    RTT_ATTRIBUTE_TARGET_NTB_MAX_MEAS_TIME  = 18,
    /* Add Attributes related to the event */
    RTT_ATTRIBUTE_RESULTS_COMPLETE          = 30,
    RTT_ATTRIBUTE_RESULTS_PER_TARGET        = 31,
    RTT_ATTRIBUTE_RESULT_CNT                = 32,
    RTT_ATTRIBUTE_RESULT                    = 33,
    RTT_ATTRIBUTE_RESUTL_DETAIL             = 34,
    RTT_ATTRIBUTE_RESULT_FREQ               = 35,
    RTT_ATTRIBUTE_RESULT_BW                 = 36,
    RTT_ATTRIBUTE_RESULT_I2R_TX_LTF_RPT_CNT = 37,
    RTT_ATTRIBUTE_RESULT_R2I_TX_LTF_RPT_CNT = 38,
    RTT_ATTRIBUTE_RESULT_NTB_MIN_MEAS_TIME  = 39,
    RTT_ATTRIBUTE_RESULT_NTB_MAX_MEAS_TIME  = 40,
    /* Add any new RTT_ATTRIBUTE prior to RTT_ATTRIBUTE_MAX */
    RTT_ATTRIBUTE_MAX
} RTT_ATTRIBUTE;
typedef struct strmap_entry {
    int			id;
    String8		text;
} strmap_entry_t;
struct dot11_rm_ie {
    u8 id;
    u8 len;
    u8 token;
    u8 mode;
    u8 type;
} __attribute__ ((packed));
typedef struct dot11_rm_ie dot11_rm_ie_t;
#define DOT11_HDR_LEN 2
#define DOT11_RM_IE_LEN       5
#define DOT11_MNG_MEASURE_REQUEST_ID		38	/* 11H MeasurementRequest */
#define DOT11_MNG_MEASURE_REPORT_ID		39	/* 11H MeasurementResponse */
#define DOT11_MEASURE_TYPE_LCI		8   /* d11 measurement LCI type */
#define DOT11_MEASURE_TYPE_CIVICLOC	11  /* d11 measurement location civic */

static const strmap_entry_t err_info[] = {
    {RTT_STATUS_SUCCESS, String8("Success")},
    {RTT_STATUS_FAILURE, String8("Failure")},
    {RTT_STATUS_FAIL_NO_RSP, String8("No reponse")},
    {RTT_STATUS_FAIL_INVALID_TS, String8("Invalid Timestamp")},
    {RTT_STATUS_FAIL_PROTOCOL, String8("Protocol error")},
    {RTT_STATUS_FAIL_REJECTED, String8("Rejected")},
    {RTT_STATUS_FAIL_NOT_SCHEDULED_YET, String8("not scheduled")},
    {RTT_STATUS_FAIL_SCHEDULE,  String8("schedule failed")},
    {RTT_STATUS_FAIL_TM_TIMEOUT, String8("timeout")},
    {RTT_STATUS_FAIL_AP_ON_DIFF_CHANNEL, String8("AP is on difference channel")},
    {RTT_STATUS_FAIL_NO_CAPABILITY, String8("no capability")},
    {RTT_STATUS_FAIL_BUSY_TRY_LATER, String8("busy and try later")},
    {RTT_STATUS_ABORTED, String8("aborted")}
};

    static const char*
get_err_info(int status)
{
    int i;
    const strmap_entry_t *p_entry;
    int num_entries = sizeof(err_info)/ sizeof(err_info[0]);
    /* scan thru the table till end */
    p_entry = err_info;
    for (i = 0; i < (int) num_entries; i++)
    {
        if (p_entry->id == status)
            return p_entry->text.c_str();
        p_entry++;		/* next entry */
    }
    return "unknown error";			/* not found */
}

class GetRttCapabilitiesCommand : public WifiCommand
{
    wifi_rtt_capabilities_v3 *mCapabilities;
public:
    GetRttCapabilitiesCommand(wifi_interface_handle iface, wifi_rtt_capabilities_v3 *capabitlites)
        : WifiCommand("GetRttCapabilitiesCommand", iface, 0), mCapabilities(capabitlites)
    {
        memset(mCapabilities, 0, sizeof(*mCapabilities));
    }

    virtual int create() {
        ALOGD("Creating message to get rtt capabilities; iface = %d", mIfaceInfo->id);

        int ret = mMsg.create(GOOGLE_OUI, RTT_SUBCMD_GETCAPABILITY);
        if (ret < 0) {
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {
        rtt_capabilities_mc_az_t SrcCapabilities;
        wifi_rtt_capabilities_v3 DestCapabilities;

        ALOGD("In GetRttCapabilitiesCommand::handleResponse");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int id = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        void *data = reply.get_vendor_data();
        int len = reply.get_vendor_data_len();

        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d",
                id, subcmd, len, sizeof(*mCapabilities));

        memset(&SrcCapabilities, 0, sizeof(SrcCapabilities));
        memset(&DestCapabilities, 0, sizeof(DestCapabilities));

        memcpy(&SrcCapabilities, data,
                min(len, (int) sizeof(SrcCapabilities)));

        DestCapabilities.rtt_capab.rtt_one_sided_supported =
                SrcCapabilities.rtt_capab.rtt_one_sided_supported;
        DestCapabilities.rtt_capab.rtt_ftm_supported =
                SrcCapabilities.rtt_capab.rtt_ftm_supported;
        DestCapabilities.rtt_capab.lci_support =
                SrcCapabilities.rtt_capab.lci_support;
        DestCapabilities.rtt_capab.lcr_support =
                SrcCapabilities.rtt_capab.lcr_support;
        DestCapabilities.rtt_capab.preamble_support =
                SrcCapabilities.rtt_capab.preamble_support;
        DestCapabilities.rtt_capab.bw_support =
                SrcCapabilities.rtt_capab.bw_support;
        DestCapabilities.rtt_capab.responder_supported = 0;
        DestCapabilities.rtt_capab.mc_version = 0;

        DestCapabilities.az_preamble_support =
                SrcCapabilities.az_preamble_support;

        DestCapabilities.az_bw_support =
                SrcCapabilities.az_bw_support;

        DestCapabilities.ntb_initiator_supported =
                SrcCapabilities.ntb_initiator_supported;

        DestCapabilities.ntb_responder_supported =
                SrcCapabilities.ntb_responder_supported;

        memcpy(mCapabilities, &DestCapabilities, sizeof(DestCapabilities));
        return NL_OK;
    }
};


class GetRttResponderInfoCommand : public WifiCommand
{
    wifi_rtt_responder* mResponderInfo;
public:
    GetRttResponderInfoCommand(wifi_interface_handle iface, wifi_rtt_responder *responderInfo)
        : WifiCommand("GetRttResponderInfoCommand", iface, 0), mResponderInfo(responderInfo)
    {
        memset(mResponderInfo, 0 , sizeof(*mResponderInfo));

    }

    virtual int create() {
        ALOGD("Creating message to get responder info ; iface = %d", mIfaceInfo->id);

        int ret = mMsg.create(GOOGLE_OUI, RTT_SUBCMD_GETAVAILCHANNEL);
        if (ret < 0) {
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        ALOGD("In GetRttResponderInfoCommand::handleResponse");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int id = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        void *data = reply.get_vendor_data();
        int len = reply.get_vendor_data_len();

        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len,
                sizeof(*mResponderInfo));

        memcpy(mResponderInfo, data, min(len, (int) sizeof(*mResponderInfo)));

        return NL_OK;
    }
};


class EnableResponderCommand : public WifiCommand
{
    wifi_channel_info  mChannelInfo;
    wifi_rtt_responder* mResponderInfo;
    unsigned int m_max_duration_sec;
public:
    EnableResponderCommand(wifi_interface_handle iface, int id, wifi_channel_info channel_hint,
            unsigned max_duration_seconds, wifi_rtt_responder *responderInfo)
            : WifiCommand("EnableResponderCommand", iface, 0), mChannelInfo(channel_hint),
            mResponderInfo(responderInfo), m_max_duration_sec(max_duration_seconds)
    {
        memset(mResponderInfo, 0, sizeof(*mResponderInfo));
        memset(&mChannelInfo, 0, sizeof(mChannelInfo));
        m_max_duration_sec = 0;
    }

    virtual int create() {
        ALOGD("Creating message to set responder ; iface = %d", mIfaceInfo->id);

        int ret = mMsg.create(GOOGLE_OUI, RTT_SUBCMD_SET_RESPONDER);
        if (ret < 0) {
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {

        ALOGD("In EnableResponderCommand::handleResponse");

        if (reply.get_cmd() != NL80211_CMD_VENDOR) {
            ALOGD("Ignoring reply with cmd = %d", reply.get_cmd());
            return NL_SKIP;
        }

        int id = reply.get_vendor_id();
        int subcmd = reply.get_vendor_subcmd();

        void *data = reply.get_vendor_data();
        int len = reply.get_vendor_data_len();

        ALOGD("Id = %0x, subcmd = %d, len = %d, expected len = %d", id, subcmd, len,
                sizeof(*mResponderInfo));

        memcpy(mResponderInfo, data, min(len, (int) sizeof(*mResponderInfo)));

        return NL_OK;
    }
};


class CancelResponderCommand : public WifiCommand
{

public:
    CancelResponderCommand(wifi_interface_handle iface, int id)
        : WifiCommand("CancelResponderCommand", iface, 0)/*, mChannelInfo(channel)*/
    {

    }

    virtual int create() {
        ALOGD("Creating message to cancel responder ; iface = %d", mIfaceInfo->id);

        int ret = mMsg.create(GOOGLE_OUI, RTT_SUBCMD_CANCEL_RESPONDER);
        if (ret < 0) {
            return ret;
        }

        return ret;
    }

protected:
    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

};


class RttCommand : public WifiCommand
{
    unsigned numRttParams;
    int mCompleted;
    int currentIdx = 0;
    int totalCnt = 0;
    static const int MAX_RESULTS = 1024;
    wifi_rtt_result *rttResultsV1[MAX_RESULTS];
    wifi_rtt_result_v2 *rttResultsV2[MAX_RESULTS];
    wifi_rtt_result_v3 *rttResultsV3[MAX_RESULTS];
    wifi_rtt_config_v3 *rttParams;
    wifi_rtt_event_handler_v3 rttHandler;
    int nextidx = 0;
    wifi_channel channel = 0;
    wifi_rtt_bw bw;
    int result_size = 0;
    int opt_result_size = 0;
    u8 i2r_tx_ltf_repetition_count = 0;
    u8 r2i_tx_ltf_repetition_count = 0;
    u32 ntb_min_measurement_time = 0;
    u32 ntb_max_measurement_time = 0;

public:
    RttCommand(wifi_interface_handle iface, int id, unsigned num_rtt_config,
            wifi_rtt_config_v3 rtt_config[], wifi_rtt_event_handler_v3 handler)
        : WifiCommand("RttCommand", iface, id), numRttParams(num_rtt_config), rttParams(rtt_config),
        rttHandler(handler)
    {
        memset(rttResultsV1, 0, sizeof(rttResultsV1));
        memset(rttResultsV2, 0, sizeof(rttResultsV2));
        memset(rttResultsV3, 0, sizeof(rttResultsV3));
        currentIdx = 0;
        mCompleted = 0;
        totalCnt = 0;
        channel = 0;
        result_size = 0;
        opt_result_size = 0;
        channel = 0;
        result_size = 0;
        opt_result_size = 0;
    }

    RttCommand(wifi_interface_handle iface, int id)
        : WifiCommand("RttCommand", iface, id)
    {
        currentIdx = 0;
        mCompleted = 0;
        totalCnt = 0;
        numRttParams = 0;
        memset(rttResultsV1, 0, sizeof(rttResultsV1));
        memset(rttResultsV2, 0, sizeof(rttResultsV2));
        memset(rttResultsV3, 0, sizeof(rttResultsV3));
        rttParams = NULL;
        rttHandler.on_rtt_results_v3 = NULL;
        channel = 0;
        result_size = 0;
        opt_result_size = 0;
    }

    int createSetupRequest(WifiRequest& request) {
        int result = request.create(GOOGLE_OUI, RTT_SUBCMD_SET_CONFIG);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u8(RTT_ATTRIBUTE_TARGET_CNT, numRttParams);
        if (result < 0) {
            return result;
        }
        nlattr *rtt_config = request.attr_start(RTT_ATTRIBUTE_TARGET_INFO);
        for (unsigned i = 0; i < numRttParams; i++) {
            nlattr *attr2 = request.attr_start(i);
            if (attr2 == NULL) {
                return WIFI_ERROR_OUT_OF_MEMORY;
            }

            result = request.put_addr(RTT_ATTRIBUTE_TARGET_MAC, rttParams[i].rtt_config.addr);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_TYPE, rttParams[i].rtt_config.type);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PEER, rttParams[i].rtt_config.peer);
            if (result < 0) {
                return result;
            }

            result = request.put(RTT_ATTRIBUTE_TARGET_CHAN, &rttParams[i].rtt_config.channel,
                    sizeof(wifi_channel_info));
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_BURST,
                    rttParams[i].rtt_config.num_burst);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_FTM_BURST,
                    rttParams[i].rtt_config.num_frames_per_burst);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTM,
                    rttParams[i].rtt_config.num_retries_per_rtt_frame);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_NUM_RETRY_FTMR,
                    rttParams[i].rtt_config.num_retries_per_ftmr);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_PERIOD,
                    rttParams[i].rtt_config.burst_period);
            if (result < 0) {
                return result;
            }

            result = request.put_u32(RTT_ATTRIBUTE_TARGET_BURST_DURATION,
                    rttParams[i].rtt_config.burst_duration);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCI,
                    rttParams[i].rtt_config.LCI_request);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_LCR,
                    rttParams[i].rtt_config.LCR_request);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_BW,
                    rttParams[i].rtt_config.bw);
            if (result < 0) {
                return result;
            }

            result = request.put_u8(RTT_ATTRIBUTE_TARGET_PREAMBLE,
                    rttParams[i].rtt_config.preamble);
            if (result < 0) {
                return result;
            }

            /* Below params are applicable for only 11az ranging */
            if (rttParams[i].rtt_config.type == RTT_TYPE_2_SIDED_11AZ_NTB) {
                result = request.put_u32(RTT_ATTRIBUTE_TARGET_NTB_MIN_MEAS_TIME,
                        rttParams[i].ntb_min_measurement_time);
                if (result < 0) {
                    return result;
                }

                result = request.put_u32(RTT_ATTRIBUTE_TARGET_NTB_MAX_MEAS_TIME,
                        rttParams[i].ntb_max_measurement_time);
                if (result < 0) {
                    return result;
                }
            }

            request.attr_end(attr2);
        }

        request.attr_end(rtt_config);
        request.attr_end(data);
        return WIFI_SUCCESS;
    }

    int createTeardownRequest(WifiRequest& request, unsigned num_devices, mac_addr addr[]) {
        int result = request.create(GOOGLE_OUI, RTT_SUBCMD_CANCEL_CONFIG);
        if (result < 0) {
            return result;
        }

        nlattr *data = request.attr_start(NL80211_ATTR_VENDOR_DATA);
        result = request.put_u8(RTT_ATTRIBUTE_TARGET_CNT, num_devices);

        if (result < 0) {
            return result;
        }
        for(unsigned i = 0; i < num_devices; i++) {
            result = request.put_addr(RTT_ATTRIBUTE_TARGET_MAC, addr[i]);
            if (result < 0) {
                return result;
            }
        }
        request.attr_end(data);
        return result;
    }

    int start() {
        ALOGD("Setting RTT configuration");
        WifiRequest request(familyId(), ifaceId());
        int result = createSetupRequest(request);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create setup request; result = %d", result);
            return result;
        }

        registerVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);

        result = requestResponse(request);
        if (result != WIFI_SUCCESS) {
            unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
            ALOGE("failed to configure RTT setup; result = %d", result);
            return result;
        }

        ALOGI("Successfully started RTT operation");
        return result;
    }

    virtual int cancel() {
        ALOGD("Stopping RTT");

        WifiRequest request(familyId(), ifaceId());
        int result = createTeardownRequest(request, 0, NULL);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create stop request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop scan; result = %d", result);
            }
        }

        unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
        ALOGD("Stopped RTT");
        return WIFI_SUCCESS;
    }

    int cancel_specific(unsigned num_devices, mac_addr addr[]) {
        ALOGE("Stopping RTT");

        WifiRequest request(familyId(), ifaceId());
        int result = createTeardownRequest(request, num_devices, addr);
        if (result != WIFI_SUCCESS) {
            ALOGE("failed to create stop request; result = %d", result);
        } else {
            result = requestResponse(request);
            if (result != WIFI_SUCCESS) {
                ALOGE("failed to stop RTT; result = %d", result);
            }
        }

        unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
        return WIFI_SUCCESS;
    }

    virtual int handleResponse(WifiEvent& reply) {
        /* Nothing to do on response! */
        return NL_SKIP;
    }

    virtual int handleEvent(WifiEvent& event) {
        ALOGI("Got an RTT event");
        nlattr *vendor_data = event.get_attribute(NL80211_ATTR_VENDOR_DATA);
        int len = event.get_vendor_data_len();
        if (vendor_data == NULL || len == 0) {
            ALOGI("No rtt results found");
            return NL_STOP;
        }

        for (nl_iterator it(vendor_data); it.has_next(); it.next()) {
            if (it.get_type() == RTT_ATTRIBUTE_RESULTS_COMPLETE) {
                mCompleted = it.get_u32();
                ALOGI("Completed flag : %d\n", mCompleted);
            } else if (it.get_type() == RTT_ATTRIBUTE_RESULTS_PER_TARGET) {
                int result_cnt = 0;
                mac_addr bssid;
                for (nl_iterator it2(it.get()); it2.has_next(); it2.next()) {
                    if (it2.get_type() == RTT_ATTRIBUTE_TARGET_MAC) {
                        memcpy(bssid, it2.get_data(), sizeof(mac_addr));
                        ALOGI("target mac : %02x:%02x:%02x:%02x:%02x:%02x\n",
                                bssid[0], bssid[1], bssid[2], bssid[3],
                                bssid[4], bssid[5]);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_FREQ) {
                        channel = it2.get_u32();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        if (!channel) {
                            rttResultsV3[currentIdx]->rtt_result.frequency =
                                    UNSPECIFIED;
                        } else {
                            rttResultsV3[currentIdx]->rtt_result.frequency =
                                    channel;
                        }

                        ALOGI("rtt_resultV3 : \n\tchannel :%d",
                                rttResultsV3[currentIdx]->rtt_result.frequency);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_BW) {
                        bw = (wifi_rtt_bw)it2.get_u32();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        rttResultsV3[currentIdx]->rtt_result.packet_bw =
                                bw;

                        ALOGI("rtt_resultV3 : \n\tpacket_bw :%d",
                               rttResultsV3[currentIdx]->rtt_result.packet_bw);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_CNT) {
                        result_cnt = it2.get_u32();
                        ALOGI("result_cnt : %d\n", result_cnt);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_I2R_TX_LTF_RPT_CNT) {
                        i2r_tx_ltf_repetition_count = it2.get_u8();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        rttResultsV3[currentIdx]->i2r_tx_ltf_repetition_count =
                                i2r_tx_ltf_repetition_count;
                        ALOGI("rtt_resultv3 : \n\ti2r_tx_ltf_repetition_count :%d",
                                rttResultsV3[currentIdx]->i2r_tx_ltf_repetition_count);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_R2I_TX_LTF_RPT_CNT) {
                        r2i_tx_ltf_repetition_count = it2.get_u8();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        rttResultsV3[currentIdx]->r2i_tx_ltf_repetition_count =
                                r2i_tx_ltf_repetition_count;
                        ALOGI("rtt_resultv3 : \n\tr2i_tx_ltf_repetition_count :%d",
                                rttResultsV3[currentIdx]->r2i_tx_ltf_repetition_count);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_MIN_MEAS_TIME) {
                        ntb_min_measurement_time = it2.get_u32();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        rttResultsV3[currentIdx]->ntb_min_measurement_time =
                                ntb_min_measurement_time;
                        ALOGI("rtt_resultv3 : \n\t ntb_min_measurement_time :%lu units of 100 us",
                                rttResultsV3[currentIdx]->ntb_min_measurement_time);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT_NTB_MAX_MEAS_TIME) {
                        ntb_max_measurement_time = it2.get_u32();
                        if (rttResultsV3[currentIdx] == NULL) {
                            ALOGE("Not allocated, currentIdx %d\n", currentIdx);
                            break;
                        }
                        rttResultsV3[currentIdx]->ntb_max_measurement_time =
                                ntb_max_measurement_time;
                        ALOGI("rtt_resultv3 : \n\t ntb_max_measurement_time:%lu units of 10ms",
                                rttResultsV3[currentIdx]->ntb_max_measurement_time);
                    } else if (it2.get_type() == RTT_ATTRIBUTE_RESULT) {
                        currentIdx = nextidx;
                        int result_len = it2.get_len();
                        rttResultsV1[currentIdx] =
                                (wifi_rtt_result *)malloc(it2.get_len());
                        wifi_rtt_result *rtt_results_v1 = rttResultsV1[currentIdx];
                        if (rtt_results_v1 == NULL) {
                            mCompleted = 1;
                            ALOGE("failed to allocate the wifi_result_v1\n");
                            break;
                        }

                        /* Populate to the rtt_results_v1 struct */
                        memcpy(rtt_results_v1, it2.get_data(), it2.get_len());

                        /* handle the optional data */
                        result_len -= RTT_RESULT_V1_SIZE;
                        if (result_len > 0) {
                            dot11_rm_ie_t *ele_1;
                            dot11_rm_ie_t *ele_2;
                            /* The result has LCI or LCR element */
                            ele_1 = (dot11_rm_ie_t *)(rtt_results_v1 + 1);
                            if (ele_1->id == DOT11_MNG_MEASURE_REPORT_ID) {
                                if (ele_1->type == DOT11_MEASURE_TYPE_LCI) {
                                    rtt_results_v1->LCI = (wifi_information_element *)ele_1;
                                    result_len -= (ele_1->len + DOT11_HDR_LEN);
                                    opt_result_size += (ele_1->len + DOT11_HDR_LEN);
                                    /* get a next rm ie */
                                    if (result_len > 0) {
                                        ele_2 = (dot11_rm_ie_t *)((char *)ele_1 +
                                            (ele_1->len + DOT11_HDR_LEN));
                                        if ((ele_2->id == DOT11_MNG_MEASURE_REPORT_ID) &&
                                                (ele_2->type == DOT11_MEASURE_TYPE_CIVICLOC)) {
                                            rtt_results_v1->LCR = (wifi_information_element *)ele_2;
                                        }
                                    }
                                } else if (ele_1->type == DOT11_MEASURE_TYPE_CIVICLOC) {
                                    rtt_results_v1->LCR = (wifi_information_element *)ele_1;
                                    result_len -= (ele_1->len + DOT11_HDR_LEN);
                                    opt_result_size += (ele_1->len + DOT11_HDR_LEN);
                                    /* get a next rm ie */
                                    if (result_len > 0) {
                                        ele_2 = (dot11_rm_ie_t *)((char *)ele_1 +
                                                (ele_1->len + DOT11_HDR_LEN));
                                        if ((ele_2->id == DOT11_MNG_MEASURE_REPORT_ID) &&
                                                (ele_2->type == DOT11_MEASURE_TYPE_LCI)) {
                                            rtt_results_v1->LCI = (wifi_information_element *)ele_2;
                                        }
                                    }
                                }
                            }
                        }

                        /* Alloc struct v2 including new elements of ver2 */
                        rttResultsV2[currentIdx] =
                                (wifi_rtt_result_v2 *)malloc(RTT_RESULT_V2_SIZE + opt_result_size);
                        wifi_rtt_result_v2 *rtt_result_v2 = rttResultsV2[currentIdx];
                        if (rtt_result_v2 == NULL) {
                            ALOGE("failed to allocate the rtt_result\n");
                            break;
                        }

                        /* Populate the v2 result struct as per the v1 result struct elements */
                        memcpy(&rtt_result_v2->rtt_result,
                                (wifi_rtt_result *)rtt_results_v1, RTT_RESULT_V1_SIZE);
                        if (!channel) {
                            rtt_result_v2->frequency = UNSPECIFIED;
                        }

                        /* Copy the optional v1 data to v2 struct */
                        if (opt_result_size &&
                            (opt_result_size == (it2.get_len() - RTT_RESULT_V1_SIZE))) {

                            wifi_rtt_result_v2 *opt_rtt_result_v2 = NULL;
                            /* Intersect the optional data from v1 rtt result struct */
                            wifi_rtt_result *opt_rtt_result_v1 =
                                    (wifi_rtt_result *)(rtt_results_v1 + 1);

                            /* Move to v2 ptr to the start of the optional params */
                            opt_rtt_result_v2 =
                                    (wifi_rtt_result_v2 *)(rtt_result_v2 + 1);

                            /* Append optional rtt_result_v1 data to optional rtt_result_v2 */
                            memcpy(opt_rtt_result_v2, opt_rtt_result_v1,
                                    (it2.get_len() - RTT_RESULT_V1_SIZE));
                        } else {
                           ALOGI("Optional rtt result elements missing, skip processing\n");
                        }

                        /* Alloc struct v3 including new elements, reserve for new elements */
                        rttResultsV3[currentIdx] =
                                (wifi_rtt_result_v3 *)malloc(RTT_RESULT_V3_SIZE + opt_result_size);
                        wifi_rtt_result_v3 *rtt_result_v3 = rttResultsV3[currentIdx];
                        if (rtt_result_v3 == NULL) {
                            ALOGE("failed to allocate the rtt_result ver3\n");
                            break;
                        }

                        /* Populate the v3 struct with v1 struct, v1 struct opt + v2 struct + v2 struct opt */
                        memcpy(&rtt_result_v3->rtt_result,
                                (wifi_rtt_result_v2 *)rtt_result_v2,
                                RTT_RESULT_V2_SIZE + opt_result_size);

                        totalCnt++;
                        nextidx = currentIdx;
                        nextidx++;
                    }
                }
                ALOGI("Current Id: %d: retrieved rtt_resultv3 :\n"
                            " burst_num : %d, measurement_number : %d,\n"
                            " success_number : %d, number_per_burst_peer : %d, status : %s,\n"
                            " retry_after_duration : %d rssi : %d dbm,\n"
                            " rx_rate : %d Kbps, rtt : %lu pss, rtt_sd : %lu ps,\n"
                            " distance : %d mm, burst_duration : %d ms, freq : %d,\n"
                            " packet_bw : %d, negotiated_burst_num : %d\n",
                            currentIdx,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.burst_num,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.measurement_number,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.success_number,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.number_per_burst_peer,
                            get_err_info(rttResultsV3[currentIdx]->rtt_result.rtt_result.status),
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.retry_after_duration,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.rssi,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.rx_rate.bitrate * 100,
                            (unsigned long)rttResultsV3[currentIdx]->rtt_result.rtt_result.rtt,
                            (unsigned long)rttResultsV3[currentIdx]->rtt_result.rtt_result.rtt_sd,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.distance_mm,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.burst_duration,
                            rttResultsV3[currentIdx]->rtt_result.frequency,
                            rttResultsV3[currentIdx]->rtt_result.packet_bw,
                            rttResultsV3[currentIdx]->rtt_result.rtt_result.negotiated_burst_num);

            }
        }

        if (mCompleted) {
            unregisterVendorHandler(GOOGLE_OUI, RTT_EVENT_COMPLETE);
            {
                if (*rttHandler.on_rtt_results_v3) {
                    (*rttHandler.on_rtt_results_v3)(id(), totalCnt, rttResultsV3);
                }
            }

            for (int i = 0; i < currentIdx; i++) {
                free(rttResultsV1[i]);
                rttResultsV1[i] = NULL;

                free(rttResultsV2[i]);
                rttResultsV2[i] = NULL;

                free(rttResultsV3[i]);
                rttResultsV3[i] = NULL;
            }
            totalCnt = currentIdx = nextidx = 0;
            WifiCommand *cmd = wifi_unregister_cmd(wifiHandle(), id());
            if (cmd)
                cmd->releaseRef();
        }
        return NL_SKIP;
    }
};


/* API to request RTT measurement */
wifi_error wifi_rtt_range_request_v3(wifi_request_id id, wifi_interface_handle iface,
        unsigned num_rtt_config, wifi_rtt_config_v3 rtt_config[],
        wifi_rtt_event_handler_v3 handler)
{
    if (iface == NULL) {
        ALOGE("wifi_rtt_range_request_v3: NULL iface pointer provided."
                " Exit.");
        return WIFI_ERROR_INVALID_ARGS;
    }

    wifi_handle handle = getWifiHandle(iface);
    if (handle == NULL) {
        ALOGE("wifi_rtt_range_request_v3: NULL handle pointer provided."
            " Exit.");
        return WIFI_ERROR_INVALID_ARGS;
    }

    ALOGI("Rtt range_request; id = %d", id);
    RttCommand *cmd = new RttCommand(iface, id, num_rtt_config, rtt_config, handler);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    wifi_error result = wifi_register_cmd(handle, id, cmd);
    if (result != WIFI_SUCCESS) {
        cmd->releaseRef();
        return result;
    }
    result = (wifi_error)cmd->start();
    if (result != WIFI_SUCCESS) {
        wifi_unregister_cmd(handle, id);
        cmd->releaseRef();
        return result;
    }
    return result;
}

/* API to cancel RTT measurements */
wifi_error wifi_rtt_range_cancel(wifi_request_id id,  wifi_interface_handle iface,
        unsigned num_devices, mac_addr addr[])
{
   if (iface == NULL) {
	ALOGE("wifi_rtt_range_cancel: NULL iface pointer provided."
		" Exit.");
	return WIFI_ERROR_INVALID_ARGS;
   }

    wifi_handle handle = getWifiHandle(iface);
    if (handle == NULL) {
	ALOGE("wifi_rtt_range_cancel: NULL handle pointer provided."
		" Exit.");
	return WIFI_ERROR_INVALID_ARGS;
    }

    ALOGI("Rtt range_cancel_request; id = %d", id);
    RttCommand *cmd = new RttCommand(iface, id);
    NULL_CHECK_RETURN(cmd, "memory allocation failure", WIFI_ERROR_OUT_OF_MEMORY);
    cmd->cancel_specific(num_devices, addr);
    wifi_unregister_cmd(handle, id);
    cmd->releaseRef();
    return WIFI_SUCCESS;
}

/* API to get RTT capability */
wifi_error wifi_get_rtt_capabilities_v3(wifi_interface_handle iface,
        wifi_rtt_capabilities_v3 *capabilities)
{
    if (iface == NULL) {
        ALOGE("wifi_get_rtt_capabilities_v3: NULL iface pointer provided."
                " Exit.");
        return WIFI_ERROR_INVALID_ARGS;
    }

    if (capabilities == NULL) {
        ALOGE("wifi_get_rtt_capabilities_v3: NULL capabilities pointer provided."
                " Exit.");
        return WIFI_ERROR_INVALID_ARGS;
    }

    GetRttCapabilitiesCommand command(iface, capabilities);
    return (wifi_error) command.requestResponse();
}

/* API to get the responder information */
wifi_error wifi_rtt_get_responder_info(wifi_interface_handle iface,
        wifi_rtt_responder* responderInfo)
{
    if (iface == NULL) {
	ALOGE("wifi_rtt_get_responder_info: NULL iface pointer provided."
		" Exit.");
	return WIFI_ERROR_INVALID_ARGS;
    }

    GetRttResponderInfoCommand command(iface, responderInfo);
    return (wifi_error) command.requestResponse();

}

/**
 * Enable RTT responder mode.
 * channel_hint - hint of the channel information where RTT responder should be enabled on.
 * max_duration_seconds - timeout of responder mode.
 * wifi_rtt_responder - information for RTT responder e.g. channel used and preamble supported.
 */
wifi_error wifi_enable_responder(wifi_request_id id, wifi_interface_handle iface,
                                wifi_channel_info channel_hint, unsigned max_duration_seconds,
                                wifi_rtt_responder* responderInfo)
{
    EnableResponderCommand command(iface, id, channel_hint, max_duration_seconds, responderInfo);
    return (wifi_error) command.requestResponse();
}

/**
 * Disable RTT responder mode.
 */
wifi_error wifi_disable_responder(wifi_request_id id, wifi_interface_handle iface)
{
    CancelResponderCommand command(iface, id);
    return (wifi_error) command.requestResponse();
}

