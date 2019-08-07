/* Copyright (C) 2012-2017 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 - * \author nPulse Technologies, LLC.
 - * \author Matt Keeler <mk@npulsetech.com>
 *  *
 * Support for NAPATECH adapter with the 3GD Driver/API.
 * Requires libntapi from Napatech A/S.
 *
 */
#include "suricata-common.h"
#include "suricata.h"
#include "threadvars.h"
#include "util-optimize.h"
#include "tm-queuehandlers.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "util-privs.h"
#include "tmqh-packetpool.h"
#include "util-napatech.h"
#include "source-napatech.h"

#define DEBUG

#ifndef HAVE_NAPATECH

TmEcode NoNapatechSupportExit(ThreadVars *, const void *, void **);

void TmModuleNapatechStreamRegister(void)
{
	tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
	tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NoNapatechSupportExit;
	tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_ADMIN;
}

void TmModuleNapatechDecodeRegister(void)
{
	tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
	tmm_modules[TMM_DECODENAPATECH].ThreadInit = NoNapatechSupportExit;
	tmm_modules[TMM_DECODENAPATECH].Func = NULL;
	tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NULL;
	tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
	tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
	tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

TmEcode NoNapatechSupportExit(ThreadVars *tv, const void *initdata, void **data)
{
	SCLogError(SC_ERR_NAPATECH_NOSUPPORT,
			"Error creating thread %s: you do not have support for Napatech adapter "
			"enabled please recompile with --enable-napatech", tv->name);
	exit(EXIT_FAILURE);
}

#else /* Implied we do have NAPATECH support */

#include <numa.h>
#include <nt.h>


extern int max_pending_packets;

typedef struct NapatechThreadVars_ {
	ThreadVars *tv;
	NtNetStreamRx_t rx_stream;
	uint16_t stream_id;
	int hba;
	TmSlot *slot;
} NapatechThreadVars;

#ifdef NAPATECH_ENABLE_BYPASS
static int NapatechBypassCallback(Packet *p);
#endif

TmEcode NapatechStreamThreadInit(ThreadVars *, const void *, void **);
void NapatechStreamThreadExitStats(ThreadVars *, void *);
TmEcode NapatechPacketLoop(ThreadVars *tv, void *data, void *slot);

TmEcode NapatechDecodeThreadInit(ThreadVars *, const void *, void **);
TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data);
TmEcode NapatechDecode(ThreadVars *, Packet *, void *, PacketQueue *,
		PacketQueue *);

/* These are used as the threads are exiting to get a comprehensive count of
 * all the packets received and dropped.
 */
SC_ATOMIC_DECLARE(uint64_t, total_packets);
SC_ATOMIC_DECLARE(uint64_t, total_drops);
SC_ATOMIC_DECLARE(uint16_t, total_tallied);

/* Streams are counted as they are instantiated in order to know when all threads
 * are running*/
SC_ATOMIC_DECLARE(uint16_t, stream_count);

SC_ATOMIC_DECLARE(uint16_t, numa0_count);
SC_ATOMIC_DECLARE(uint16_t, numa1_count);
SC_ATOMIC_DECLARE(uint16_t, numa2_count);
SC_ATOMIC_DECLARE(uint16_t, numa3_count);

/**
 * \brief Register the Napatech  receiver (reader) module.
 */
void TmModuleNapatechStreamRegister(void) {
	tmm_modules[TMM_RECEIVENAPATECH].name = "NapatechStream";
	tmm_modules[TMM_RECEIVENAPATECH].ThreadInit = NapatechStreamThreadInit;
	tmm_modules[TMM_RECEIVENAPATECH].Func = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].PktAcqLoop = NapatechPacketLoop;
	tmm_modules[TMM_RECEIVENAPATECH].PktAcqBreakLoop = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].ThreadExitPrintStats =
			NapatechStreamThreadExitStats;
	tmm_modules[TMM_RECEIVENAPATECH].ThreadDeinit = NapatechStreamThreadDeinit;
	tmm_modules[TMM_RECEIVENAPATECH].RegisterTests = NULL;
	tmm_modules[TMM_RECEIVENAPATECH].cap_flags = SC_CAP_NET_RAW;
	tmm_modules[TMM_RECEIVENAPATECH].flags = TM_FLAG_RECEIVE_TM;

	SC_ATOMIC_INIT(total_packets);
	SC_ATOMIC_INIT(total_drops);
	SC_ATOMIC_INIT(total_tallied);
	SC_ATOMIC_INIT(stream_count);

	SC_ATOMIC_INIT(numa0_count);
	SC_ATOMIC_INIT(numa1_count);
	SC_ATOMIC_INIT(numa2_count);
	SC_ATOMIC_INIT(numa3_count);
}

/**
 * \brief Register the Napatech decoder module.
 */
void TmModuleNapatechDecodeRegister(void) {
	tmm_modules[TMM_DECODENAPATECH].name = "NapatechDecode";
	tmm_modules[TMM_DECODENAPATECH].ThreadInit = NapatechDecodeThreadInit;
	tmm_modules[TMM_DECODENAPATECH].Func = NapatechDecode;
	tmm_modules[TMM_DECODENAPATECH].ThreadExitPrintStats = NULL;
	tmm_modules[TMM_DECODENAPATECH].ThreadDeinit = NapatechDecodeThreadDeinit;
	tmm_modules[TMM_DECODENAPATECH].RegisterTests = NULL;
	tmm_modules[TMM_DECODENAPATECH].cap_flags = 0;
	tmm_modules[TMM_DECODENAPATECH].flags = TM_FLAG_DECODE_TM;
}

#ifdef NAPATECH_ENABLE_BYPASS
/**
 * /brief template of IPv4 header
 */
struct ipv4_hdr {
	uint8_t version_ihl; /**< version and header length */
	uint8_t type_of_service; /**< type of service */
	uint16_t total_length; /**< length of packet */
	uint16_t packet_id; /**< packet ID */
	uint16_t fragment_offset; /**< fragmentation offset */
	uint8_t time_to_live; /**< time to live */
	uint8_t next_proto_id; /**< protocol ID */
	uint16_t hdr_checksum; /**< header checksum */
	uint32_t src_addr; /**< source address */
	uint32_t dst_addr; /**< destination address */
} __attribute__ ((__packed__));

/**
 * /brief template of IPv6 header
 */
struct ipv6_hdr {
	uint32_t vtc_flow; /**< IP version, traffic class & flow label. */
	uint16_t payload_len; /**< IP packet length - includes sizeof(ip_header). */
	uint8_t proto; /**< Protocol, next header. */
	uint8_t hop_limits; /**< Hop limits. */
	uint8_t src_addr[16]; /**< IP address of source host. */
	uint8_t dst_addr[16]; /**< IP address of destination host(s). */
} __attribute__ ((__packed__));

/**
 * /brief template of UDP header
 */
struct udp_hdr {
	uint16_t src_port; /**< UDP source port. */
	uint16_t dst_port; /**< UDP destination port. */
	uint16_t dgram_len; /**< UDP datagram length */
	uint16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__ ((__packed__));

/**
 * /brief template of TCP header
 */
struct tcp_hdr {
	uint16_t src_port; /**< TCP source port. */
	uint16_t dst_port; /**< TCP destination port. */
	uint32_t sent_seq; /**< TX data sequence number. */
	uint32_t recv_ack; /**< RX data acknowledgement sequence number. */
	uint8_t data_off; /**< Data offset. */
	uint8_t tcp_flags; /**< TCP flags */
	uint16_t rx_win; /**< RX flow control window. */
	uint16_t cksum; /**< TCP checksum. */
	uint16_t tcp_urp; /**< TCP urgent pointer, if any. */
} __attribute__ ((__packed__));

/**
 * /brief template of SCTP header
 */
struct sctp_hdr {
	uint16_t src_port; /**< Source port. */
	uint16_t dst_port; /**< Destin port. */
	uint32_t tag; /**< Validation tag. */
	uint32_t cksum; /**< Checksum. */
} __attribute__ ((__packed__));

#define IPV4_ADDRESS(a) ((const char *)&a)[0] & 0xFF, ((const char *)&a)[1] & 0xFF, ((const char *)&a)[2] & 0xFF, ((const char *)&a)[3] & 0xFF

#define IPV6_ADDRESS(a) (unsigned int)(a[0] & 0xFF), (unsigned int)(a[1] & 0xFF), (unsigned int)(a[2] & 0xFF), (unsigned int)(a[3] & 0xFF),    \
		(unsigned int)(a[4] & 0xFF), (unsigned int)(a[5] & 0xFF), (unsigned int)(a[6] & 0xFF), (unsigned int)(a[7] & 0xFF),    \
		(unsigned int)(a[8] & 0xFF), (unsigned int)(a[9] & 0xFF), (unsigned int)(a[10] & 0xFF), (unsigned int)(a[11] & 0xFF),  \
		(unsigned int)(a[12] & 0xFF), (unsigned int)(a[13] & 0xFF), (unsigned int)(a[14] & 0xFF), (unsigned int)(a[15] & 0xFF)

#define RTE_PTYPE_L2_ETHER                  0x00000001
#define RTE_PTYPE_L3_IPV4                   0x00000010
#define RTE_PTYPE_L3_IPV6                   0x00000040
#define RTE_PTYPE_L3_MASK                   0x000000f0
#define RTE_PTYPE_L4_TCP                    0x00000100
#define RTE_PTYPE_L4_UDP                    0x00000200
#define RTE_PTYPE_L4_SCTP                   0x00000400
#define RTE_PTYPE_L4_MASK                   0x00000f00

static uint64_t flow_cnt = 0;
//static NtFlowAttr_t attr;

//static void PrintIP(uint32_t address)
//{
//    printf("%i.%i.%i.%i",
//            (address >> 24) & 0xff,
//            (address >> 16) & 0xff,
//            (address >> 8) & 0xff,
//            address & 0xff);
//}


static int port_adapter_map[MAX_PORTS] = { -1 };

/**
 * \brief Returns the ID of the adapter
 *
 * Get the ID of an adapter on which a given port resides.
 *
 * \param port for which adapter ID is requested.
 * \return ID of the adapter.
 *
 */
static int GetAdapter(uint8_t port) {
	int status;
	NtInfo_t hInfo; // Info handle
	NtInfoStream_t hInfoStream; // Info stream handle

	if (unlikely(port_adapter_map[port] == -1)) {
		if ((status = NT_InfoOpen(&hInfoStream, "ExampleInfo")) != NT_SUCCESS) {
			NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
			return -1;
		}
		// Read the system info
		hInfo.cmd = NT_INFO_CMD_READ_PORT_V9;
		hInfo.u.port_v9.portNo = (uint8_t) port;
		if ((status = NT_InfoRead(hInfoStream, &hInfo)) != NT_SUCCESS) {
			// Get the status code as text
			NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
			NT_InfoClose(hInfoStream);
			return -1;
		}
		port_adapter_map[port] = hInfo.u.port_v9.data.adapterNo;
	}
	return port_adapter_map[port];
}


#ifdef ENABLE_NT_DEBUG
void NapatechPrintIP(uint32_t address)
{
    printf("%i.%i.%i.%i",
            (address >> 24) & 0xff,
            (address >> 16) & 0xff,
            (address >> 8) & 0xff,
            address & 0xff);
}
#endif

/**
 * \brief Callback function to process Bypass events on Napatech Adapter.
 *
 * Callback function that sets up the Flow tables on the Napatech card
 * so that subsequent packets from this flow are bypassed on the hardware.
 *
 * \param p packet containing information about the flow to be bypassed
 *
 * \return Error code indicating success (1) or failure (0).
 *
 */
static int NapatechBypassCallback(Packet *p)
{
	int status;
	NtFlow_t flowMatch;

	NapatechPacketVars *ntpv = &(p->ntpv);
	uint32_t packetType = ((ntpv->dyn3->color_hi << 14) & 0xFFFFC000) | ntpv->dyn3->color_lo;
	uint8_t *packet = (uint8_t *) ntpv->dyn3 + ntpv->dyn3->descrLength;

	uint32_t layer3 = packetType & RTE_PTYPE_L3_MASK;
	uint32_t layer4 = packetType & RTE_PTYPE_L4_MASK;

	int adapter = GetAdapter(p->ntpv.dyn3->rxPort);
	NtFlowStream_t *phFlowStream = NapatechGetFlowStreamPtr(adapter);

	/* Only bypass TCP and UDP */
	if (!(PKT_IS_TCP(p) || PKT_IS_UDP(p))) {
		return 0;
	}

	++flow_cnt;

#ifdef ENABLE_NT_DEBUG

	NapatechPrintIP(pIPv4_hdr->src_addr);
	NAPATECH_DEBUG(" -> ");
	NapatechPrintIP(pIPv4_hdr->dst_addr);
	NAPATECH_DEBUG("+++ id: 0x%08x - action: 0x%x  port: %d  adapter: %d\n",
			        p->flow->flow_hash, p->action, p->ntpv.dyn3->rxPort, adapter);

#endif

	memset(flowMatch.u.raw, 0, sizeof (flowMatch.u.raw));

	switch (layer3) {
	case RTE_PTYPE_L3_IPV4:
	{
		struct ipv4_hdr *pIPv4_hdr = (struct ipv4_hdr *) (packet + ntpv->dyn3->offset0);
		flowMatch.u.ip4tuple4.da = pIPv4_hdr->dst_addr;
		flowMatch.u.ip4tuple4.sa = pIPv4_hdr->src_addr;
		break;
	}
	case RTE_PTYPE_L3_IPV6:
	{
		struct ipv6_hdr *pIPv6_hdr = (struct ipv6_hdr *) (packet + ntpv->dyn3->offset0);
		memcpy(flowMatch.u.ip6tuple4.da, pIPv6_hdr->dst_addr, 16);
		memcpy(flowMatch.u.ip6tuple4.sa, pIPv6_hdr->src_addr, 16);
		break;
	}
	default:
		return 0;
	}

	switch (layer4) {
	case RTE_PTYPE_L4_TCP:
	{
		struct tcp_hdr *tcp_hdr = (struct tcp_hdr *) (packet + ntpv->dyn3->offset1);

		if (layer3 == RTE_PTYPE_L3_IPV4) {
			flowMatch.u.ip4tuple4.dp = tcp_hdr->dst_port;
			flowMatch.u.ip4tuple4.sp = tcp_hdr->src_port;
		} else {
			flowMatch.u.ip6tuple4.dp = tcp_hdr->dst_port;
			flowMatch.u.ip6tuple4.sp = tcp_hdr->src_port;
		}
		flowMatch.color = flow_cnt;
		flowMatch.prot = 6;
		break;
	}
	case RTE_PTYPE_L4_UDP:
	{
		struct udp_hdr *udp_hdr = (struct udp_hdr *) (packet + ntpv->dyn3->offset1);

		if (layer3 == RTE_PTYPE_L3_IPV4) {
			flowMatch.u.ip4tuple4.dp = udp_hdr->dst_port;
			flowMatch.u.ip4tuple4.sp = udp_hdr->src_port;
		} else {
			flowMatch.u.ip6tuple4.dp = udp_hdr->dst_port;
			flowMatch.u.ip6tuple4.sp = udp_hdr->src_port;
		}
		flowMatch.color = flow_cnt;
		flowMatch.prot = 17;
		break;
	}
	case RTE_PTYPE_L4_SCTP:
	{
		struct sctp_hdr *sctp_hdr = (struct sctp_hdr *) (packet + ntpv->dyn3->offset1);

		if (layer3 == RTE_PTYPE_L3_IPV4) {
			flowMatch.u.ip4tuple4.dp = sctp_hdr->dst_port;
			flowMatch.u.ip4tuple4.sp = sctp_hdr->src_port;
		} else {
			flowMatch.u.ip6tuple4.dp = sctp_hdr->dst_port;
			flowMatch.u.ip6tuple4.sp = sctp_hdr->src_port;
		}
		flowMatch.color = flow_cnt;
		flowMatch.prot = 132;
		break;
	}
	default:
		return 0;
	}

	flowMatch.color = flow_cnt;
	flowMatch.op = 1;
	flowMatch.gfi = 1;
	flowMatch.id = p->flow->flow_hash;
	flowMatch.tau = 1;

	if (layer3 == RTE_PTYPE_L3_IPV4) {
		flowMatch.ft = NAPATECH_KEY_IPV4;
		flowMatch.kid = NAPATECH_KEY_IPV4; //NAPATECH_KEY_IPV4;
	} else {
		flowMatch.ft = NAPATECH_KEY_IPV6;
		flowMatch.kid = NAPATECH_KEY_IPV4; //NAPATECH_KEY_IPV6;
	}

	if ((status = NT_FlowWrite(*phFlowStream, &flowMatch, 0)) != NT_SUCCESS) {
		NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
        exit(EXIT_FAILURE);
		return 0;
	}

	return 1;
}
#endif

/**
 * \brief   Initialize the Napatech receiver thread, generate a single
 *          NapatechThreadVar structure for each thread, this will
 *          contain a NtNetStreamRx_t stream handle which is used when the
 *          thread executes to acquire the packets.
 *
 * \param tv        Thread variable to ThreadVars
 * \param initdata  Initial data to the adapter passed from the user,
 *                  this is processed by the user.
 *
 *                  For now, we assume that we have only a single name for the NAPATECH
 *                  adapter.
 *
 * \param data      data pointer gets populated with
 *
 */
TmEcode NapatechStreamThreadInit(ThreadVars *tv, const void *initdata,
		void **data) {
	SCEnter();
	struct NapatechStreamDevConf *conf =
			(struct NapatechStreamDevConf *) initdata;
	uint16_t stream_id = conf->stream_id;
	*data = NULL;

	NapatechThreadVars *ntv = SCCalloc(1, sizeof(NapatechThreadVars));
	if (unlikely(ntv == NULL)) {
		SCLogError(SC_ERR_MEM_ALLOC,
				"Failed to allocate memory for NAPATECH  thread vars.");
		exit(EXIT_FAILURE);
	}

	memset(ntv, 0, sizeof(NapatechThreadVars));
	ntv->stream_id = stream_id;
	ntv->tv = tv;
	ntv->hba = conf->hba;
	SCLogDebug("Started processing packets from NAPATECH  Stream: %lu",
			ntv->stream_id);

	*data = (void *) ntv;
	SCReturnInt(TM_ECODE_OK);
}

static PacketQueue packets_to_release[MAX_STREAMS];

/**
 * \brief Callback to indicate that the packet buffer can be returned to the hardware.
 *
 *  Called when Suricata is done processing the packet.  The packet is placed into
 *  a queue so that it can be retrieved and released by the packet processing thread.
 *
 * \param p Packet to return to the system.
 *
 */
static void NapatechReleasePacket(struct Packet_ *p) {
	PacketFreeOrRelease(p);
	PacketEnqueue(&packets_to_release[p->ntpv.stream_id], p);
}

/**
 * \brief Returns the NUMA node associated with the currently running thread.
 *
 * \return ID of the NUMA node.
 *
 */
static int GetNumaNode(void) {
	int cpu = 0;
	int node = 0;

#if defined(__linux__)
	cpu = sched_getcpu();
	node = numa_node_of_cpu(cpu);
#else
	SCLogWarning(SC_ERR_NAPATECH_NOSUPPORT,
			"Auto configuration of NUMA node is not supported on this OS.");
#endif

	return node;
}

/**
 * \brief Outputs hints on the optimal host-buffer configuration to aid tuning.
 *
 * \param log_level of the currently running instance.
 *
 */
static void RecommendNUMAConfig(SCLogLevel log_level) {
	char string0[16];
	char string1[16];
	char string2[16];
	char string3[16];
	int set_cpu_affinity = 0;

	if (ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity) != 1) {
		set_cpu_affinity = 0;
	}

	if (set_cpu_affinity) {
		SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
				"Minimum host buffers that should be defined in ntservice.ini:");

		SCLog(log_level, __FILE__, __FUNCTION__, __LINE__, "   NUMA Node 0: %d",
				(SC_ATOMIC_GET(numa0_count)));

		if (numa_max_node() >= 1)
			SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
					"   NUMA Node 1: %d ", (SC_ATOMIC_GET(numa1_count)));

		if (numa_max_node() >= 2)
			SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
					"   NUMA Node 2: %d ", (SC_ATOMIC_GET(numa2_count)));

		if (numa_max_node() >= 3)
			SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
					"   NUMA Node 3: %d ", (SC_ATOMIC_GET(numa3_count)));

		snprintf(string0, 16, "[%d, 16, 0]", SC_ATOMIC_GET(numa0_count));
		snprintf(string1, 16, (numa_max_node() >= 1 ? ",[%d, 16, 1]" : ""),
				SC_ATOMIC_GET(numa1_count));
		snprintf(string2, 16, (numa_max_node() >= 2 ? ",[%d, 16, 2]" : ""),
				SC_ATOMIC_GET(numa2_count));
		snprintf(string3, 16, (numa_max_node() >= 3 ? ",[%d, 16, 3]" : ""),
				SC_ATOMIC_GET(numa3_count));

		SCLog(log_level, __FILE__, __FUNCTION__, __LINE__,
				"E.g.: HostBuffersRx=%s%s%s%s", string0, string1, string2,
				string3);
	} else if (log_level == SC_LOG_ERROR) {
		SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
				"Or, try running /opt/napatech3/bin/ntpl -e \"delete=all\" to clean-up stream NUMA config.");
	}
}

#ifdef NAPATECH_ENABLE_BYPASS

#endif

/**
 * \brief   Main Napatechpacket processing loop
 *
 * \param tv     Thread variable to ThreadVars
 * \param data   Pointer to NapatechThreadVars with data specific to Napatech
 * \param slot   TMSlot where this instance is running.
 *
 */
TmEcode NapatechPacketLoop(ThreadVars *tv, void *data, void *slot) {
	int32_t status;
	char error_buffer[100];
	uint64_t pkt_ts;
	NtNetBuf_t packet_buffer;
	NapatechThreadVars *ntv = (NapatechThreadVars *) data;
	uint64_t hba_pkt_drops = 0;
	uint64_t hba_byte_drops = 0;
	uint16_t hba_pkt = 0;
	int numa_node = -1;
	int set_cpu_affinity = 0;
	int closer = 0;

	/* This just keeps the startup output more orderly. */
	usleep(200000 * ntv->stream_id);

	if (NapatechIsAutoConfigEnabled()) {
		numa_node = GetNumaNode();
		switch (numa_node) {
		case 0:
			SC_ATOMIC_ADD(numa0_count, 1);
			break;
		case 1:
			SC_ATOMIC_ADD(numa1_count, 1);
			break;
		case 2:
			SC_ATOMIC_ADD(numa2_count, 1);
			break;
		case 3:
			SC_ATOMIC_ADD(numa3_count, 1);
			break;
		default:
			break;
		}

		if (ConfGetBool("threading.set-cpu-affinity", &set_cpu_affinity) != 1) {
			set_cpu_affinity = 0;
		}

		if (set_cpu_affinity) {
			NapatechSetupNuma(ntv->stream_id, numa_node);
		}

		numa_node = GetNumaNode();
		SC_ATOMIC_ADD(stream_count, 1);
		if (SC_ATOMIC_GET(stream_count) == NapatechGetNumConfiguredStreams()) {
			/* The last thread to run sets up and deletes the streams */
			status = NapatechSetupTraffic(NapatechGetNumFirstStream(),
					NapatechGetNumLastStream());

			closer = 1;

			if (status == 0x20002061) {
				SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
						"Check host buffer configuration in ntservice.ini.");
				RecommendNUMAConfig(SC_LOG_ERROR);
				exit(EXIT_FAILURE);

			} else if (status == 0x20000008) {
				SCLogError(SC_ERR_NAPATECH_STREAMS_REGISTER_FAILED,
						"Check napatech.ports in the suricata config file.");
				exit(EXIT_FAILURE);
			}
			RecommendNUMAConfig(SC_LOG_INFO);
		}
	}

	SCLogInfo(
			"Napatech Packet Loop Started - cpu: %3d, cpu_numa: %3d   stream: %3u ",
			sched_getcpu(), numa_node, ntv->stream_id);

	if (ntv->hba > 0) {
		char *s_hbad_pkt = SCCalloc(1, 32);
		if (unlikely(s_hbad_pkt == NULL)) {
			SCLogError(SC_ERR_MEM_ALLOC,
					"Failed to allocate memory for NAPATECH stream counter.");
			exit(EXIT_FAILURE);
		}
		snprintf(s_hbad_pkt, 32, "nt%d.hba_drop", ntv->stream_id);
		hba_pkt = StatsRegisterCounter(s_hbad_pkt, tv);
		StatsSetupPrivate(tv);
		StatsSetUI64(tv, hba_pkt, 0);
	}
	SCLogDebug("Opening NAPATECH Stream: %lu for processing", ntv->stream_id);

	if ((status = NT_NetRxOpen(&(ntv->rx_stream), "SuricataStream",
			NT_NET_INTERFACE_PACKET, ntv->stream_id, ntv->hba)) != NT_SUCCESS) {

		NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
		SCFree(ntv);
		SCReturnInt(TM_ECODE_FAILED);
	}

	TmSlot *s = (TmSlot *) slot;
	ntv->slot = s->slot_next;

	while (!(suricata_ctl_flags & SURICATA_STOP)) {
		/* make sure we have at least one packet in the packet pool, to prevent
		 * us from alloc'ing packets at line rate */
		PacketPoolWait();

		/* Napatech returns packets 1 at a time */
		status = NT_NetRxGet(ntv->rx_stream, &packet_buffer, 1000);
		if (unlikely(
				status == NT_STATUS_TIMEOUT || status == NT_STATUS_TRYAGAIN)) {
			continue;
		} else if (unlikely(status != NT_SUCCESS)) {
			NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
			SCLogInfo("Failed to read from Napatech Stream %d: %s",
					ntv->stream_id, error_buffer);
			SCReturnInt(TM_ECODE_FAILED);
		}

		Packet *p = PacketGetFromQueueOrAlloc();
		if (unlikely(p == NULL)) {
			NT_NetRxRelease(ntv->rx_stream, packet_buffer);
			SCReturnInt(TM_ECODE_FAILED);
		}

		pkt_ts = NT_NET_GET_PKT_TIMESTAMP(packet_buffer);

		/*
		 * Handle the different timestamp forms that the napatech cards could use
		 *   - NT_TIMESTAMP_TYPE_NATIVE is not supported due to having an base
		 *     of 0 as opposed to NATIVE_UNIX which has a base of 1/1/1970
		 */
		switch (NT_NET_GET_PKT_TIMESTAMP_TYPE(packet_buffer)) {
		case NT_TIMESTAMP_TYPE_NATIVE_UNIX:
			p->ts.tv_sec = pkt_ts / 100000000;
			p->ts.tv_usec =
					((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
			break;
		case NT_TIMESTAMP_TYPE_PCAP:
			p->ts.tv_sec = pkt_ts >> 32;
			p->ts.tv_usec = pkt_ts & 0xFFFFFFFF;
			break;
		case NT_TIMESTAMP_TYPE_PCAP_NANOTIME:
			p->ts.tv_sec = pkt_ts >> 32;
			p->ts.tv_usec =
					((pkt_ts & 0xFFFFFFFF) / 1000) + (pkt_ts % 1000) > 500 ?
							1 : 0;
			break;
		case NT_TIMESTAMP_TYPE_NATIVE_NDIS:
			/* number of seconds between 1/1/1601 and 1/1/1970 */
			p->ts.tv_sec = (pkt_ts / 100000000) - 11644473600;
			p->ts.tv_usec =
					((pkt_ts % 100000000) / 100) + (pkt_ts % 100) > 50 ? 1 : 0;
			break;
		default:
			SCLogError(SC_ERR_NAPATECH_TIMESTAMP_TYPE_NOT_SUPPORTED,
					"Packet from Napatech Stream: %u does not have a supported timestamp format",
					ntv->stream_id);
			NT_NetRxRelease(ntv->rx_stream, packet_buffer);
			SCReturnInt(TM_ECODE_FAILED);
		}

		if (unlikely(ntv->hba > 0)) {
			NtNetRx_t stat_cmd;
			stat_cmd.cmd = NT_NETRX_READ_CMD_STREAM_DROP;
			/* Update drop counter */
			if (unlikely(
					(status = NT_NetRxRead(ntv->rx_stream, &stat_cmd))
					!= NT_SUCCESS)) {
				NAPATECH_ERROR(SC_ERR_NAPATECH_OPEN_FAILED, status);
				SCLogInfo(
						"Couldn't retrieve drop statistics from the RX stream: %u",
						ntv->stream_id);
			} else {
				hba_pkt_drops = stat_cmd.u.streamDrop.pktsDropped;

				StatsSetUI64(tv, hba_pkt, hba_pkt_drops);
			}
			StatsSyncCountersIfSignalled(tv);
		}

#ifdef NAPATECH_ENABLE_BYPASS
		p->ntpv.dyn3 = _NT_NET_GET_PKT_DESCR_PTR_DYN3(packet_buffer);
		p->BypassPacketsFlow = NapatechBypassCallback;
#endif
		p->ReleasePacket = NapatechReleasePacket;
		p->ntpv.nt_packet_buf = packet_buffer;
		p->ntpv.stream_id = ntv->stream_id;
		p->datalink = LINKTYPE_ETHERNET;

		if (unlikely(
				PacketSetData(p,
						(uint8_t * ) NT_NET_GET_PKT_L2_PTR(packet_buffer),
						NT_NET_GET_PKT_WIRE_LENGTH(packet_buffer)))) {

			TmqhOutputPacketpool(ntv->tv, p);
			NT_NetRxRelease(ntv->rx_stream, packet_buffer);
			SCReturnInt(TM_ECODE_FAILED);
		}

		if (unlikely(
				TmThreadsSlotProcessPkt(ntv->tv, ntv->slot, p)
				!= TM_ECODE_OK)) {
			TmqhOutputPacketpool(ntv->tv, p);
			NT_NetRxRelease(ntv->rx_stream, packet_buffer);
			SCReturnInt(TM_ECODE_FAILED);
		}

		/* Release any packets that were returned by the callback function */
		Packet *rel_pkt = PacketDequeue(&packets_to_release[ntv->stream_id]);
		while (rel_pkt != NULL) {
			NT_NetRxRelease(ntv->rx_stream, rel_pkt->ntpv.nt_packet_buf);
			rel_pkt = PacketDequeue(&packets_to_release[ntv->stream_id]);
		}
		StatsSyncCountersIfSignalled(tv);
	} // while

	if (closer) {
#ifdef NAPATECH_ENABLE_BYPASS
		NapatechCloseFlowStreams();
#endif
		NapatechDeleteFilters();
	}

	if (unlikely(ntv->hba > 0)) {
		SCLogInfo("Host Buffer Allowance Drops - pkts: %ld,  bytes: %ld",
				hba_pkt_drops, hba_byte_drops);
	}

	SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Print some stats to the log at program exit.
 *
 * \param tv Pointer to ThreadVars.
 * \param data Pointer to data, ErfFileThreadVars.
 */
void NapatechStreamThreadExitStats(ThreadVars *tv, void *data) {
	NapatechThreadVars *ntv = (NapatechThreadVars *) data;
	NapatechCurrentStats stat = NapatechGetCurrentStats(ntv->stream_id);

	double percent = 0;
	if (stat.current_drops > 0)
		percent = (((double) stat.current_drops)
				/ (stat.current_packets + stat.current_drops)) * 100;

	SCLogInfo("nt%lu - pkts: %lu; drop: %lu (%5.2f%%); bytes: %lu",
			(uint64_t ) ntv->stream_id, stat.current_packets,
			stat.current_drops, percent, stat.current_bytes);

	SC_ATOMIC_ADD(total_packets, stat.current_packets);
	SC_ATOMIC_ADD(total_drops, stat.current_drops);
	SC_ATOMIC_ADD(total_tallied, 1);

	if (SC_ATOMIC_GET(total_tallied) == NapatechGetNumConfiguredStreams()) {
		if (SC_ATOMIC_GET(total_drops) > 0)
			percent =
					(((double) SC_ATOMIC_GET(total_drops))
							/ (SC_ATOMIC_GET(total_packets)
									+ SC_ATOMIC_GET(total_drops))) * 100;

		SCLogInfo(" ");
		SCLogInfo("--- Total Packets: %ld  Total Dropped: %ld (%5.2f%%)",
				SC_ATOMIC_GET(total_packets), SC_ATOMIC_GET(total_drops),
				percent);
	}
}

/**
 * \brief   Deinitializes the NAPATECH card.
 * \param   tv pointer to ThreadVars
 * \param   data pointer that gets cast into PcapThreadVars for ptv
 */
TmEcode NapatechStreamThreadDeinit(ThreadVars *tv, void *data) {
	SCEnter();
	NapatechThreadVars *ntv = (NapatechThreadVars *) data;

	SCLogDebug("Closing Napatech Stream: %d", ntv->stream_id);
	NT_NetRxClose(ntv->rx_stream);

	SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   This function passes off to link type decoders.
 *
 * NapatechDecode reads packets from the PacketQueue and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data pointer that gets cast into PcapThreadVars for ptv
 * \param pq pointer to the current PacketQueue
 */
TmEcode NapatechDecode(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq,
		PacketQueue *postpq) {
	SCEnter();

	DecodeThreadVars *dtv = (DecodeThreadVars *) data;

	/* XXX HACK: flow timeout can call us for injected pseudo packets
	 *           see bug: https://redmine.openinfosecfoundation.org/issues/1107 */
	if (p->flags & PKT_PSEUDO_STREAM_END)
		return TM_ECODE_OK;

	// update counters
	DecodeUpdatePacketCounters(tv, dtv, p);

	switch (p->datalink) {
	case LINKTYPE_ETHERNET:
		DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p), pq);
		break;
	default:
		SCLogError(SC_ERR_DATALINK_UNIMPLEMENTED,
				"Error: datalink type %" PRId32 " not yet supported in module NapatechDecode",
				p->datalink);
		break;
	}

	PacketDecodeFinalize(tv, dtv, p);
	SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Initialization of Napatech Thread.
 *
 * \param t pointer to ThreadVars
 * \param initdata - unused.
 * \param data pointer that gets cast into DecoderThreadVars
 */
TmEcode NapatechDecodeThreadInit(ThreadVars *tv, const void *initdata,
		void **data) {
	SCEnter();
	DecodeThreadVars *dtv = NULL;
	dtv = DecodeThreadVarsAlloc(tv);
	if (dtv == NULL)
		SCReturnInt(TM_ECODE_FAILED);

	DecodeRegisterPerfCounters(dtv, tv);
	*data = (void *) dtv;
	SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief   Deinitialization of Napatech Thread.
 *
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into DecoderThreadVars
 */
TmEcode NapatechDecodeThreadDeinit(ThreadVars *tv, void *data) {
	if (data != NULL)
		DecodeThreadVarsFree(tv, data);
	SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_NAPATECH */
