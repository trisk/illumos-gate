/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/modctl.h>
#include <sys/blkdev.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/sysmacros.h>

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include "virtiovar.h"
#include "virtioreg.h"

#define VIRTIO_SCSI_CDB_SIZE 32
#define	VIRTIO_SCSI_SENSE_SIZE 96

/* Feature bits */
#define VIRTIO_SCSI_F_INOUT	(0x1 << 0)
#define VIRTIO_SCSI_F_HOTPLUG	(0x1 << 1)

/* registers offset in bytes */
#define VIRTIO_SCSI_CFG_NUM_QUEUES 0
#define VIRTIO_SCSI_CFG_SEG_MAX    4
#define VIRTIO_SCSI_CFG_MAX_SECTORS 8
#define VIRTIO_SCSI_CFG_CMD_PER_LUN 12
#define VIRTIO_SCSI_CFG_EVI_SIZE    16
#define VIRTIO_SCSI_CFG_SENSE_SIZE  20
#define VIRTIO_SCSI_CFG_CDB_SIZE    24
#define VIRTIO_SCSI_CFG_MAX_CHANNEL 28
#define VIRTIO_SCSI_CFG_MAX_TARGET  32
#define VIRTIO_SCSI_CFG_MAX_LUN     36

/* response codes */
#define VIRTIO_SCSI_S_OK	0
#define VIRTIO_SCSI_S_FUNCTION_COMPLETED	0
#define VIRTIO_SCSI_S_OVERRUN	1
#define VIRTIO_SCSI_S_ABORTED	2
#define VIRTIO_SCSI_S_BAD_TARGET	3
#define VIRTIO_SCSI_S_RESET	4
#define VIRTIO_SCSI_S_BUSY	5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE	6
#define VIRTIO_SCSI_S_TARGET_FAILURE	7
#define VIRTIO_SCSI_S_NEXUS_FAILURE	8
#define VIRTIO_SCSI_S_FAILURE	9
#define VIRTIO_SCSI_S_FUNCTION_SUCCEEDED	10
#define VIRTIO_SCSI_S_FUNCTION_REJECTED	11
#define VIRTIO_SCSI_S_INCORRECT_LUN	12

/* Controlq type codes */
#define VIRTIO_SCSI_T_TMF	0
#define VIRTIO_SCSI_T_AN_QUERY	1
#define VIRTIO_SCSI_T_AN_SUBSCRIBE	2

/* events */
#define VIRTIO_SCSI_T_EVENTS_MISSED	0x80000000
#define VIRTIO_SCSI_T_NO_EVENT	0
#define VIRTIO_SCSI_T_TRANSPORT_RESET	1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY	2

#define VIOSCSI_MAX_TARGET     256

/*reasons of reset event */
#define VIRTIO_SCSI_EVT_RESET_HARD	0
#define VIRTIO_SCSI_EVT_RESET_RESCAN	1
#define VIRTIO_SCSI_EVT_RESET_REMOVED	2

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/* Data structures */

/* virtio SCSI command request */
struct virtio_scsi_cmd_req {
	uint8_t lun[8];
	uint64_t tag;
	uint8_t	task_attr;
	uint8_t	prio;
	uint8_t crn;
	uint8_t cdb[VIRTIO_SCSI_CDB_SIZE];
} __packed;

/* virtio SCSI response */
struct virtio_scsi_cmd_resp {
	uint32_t sense_len;
	uint32_t res_id;
	uint16_t status_qualifier;
	uint8_t	status;
	uint8_t response;
	uint8_t sense[VIRTIO_SCSI_SENSE_SIZE];
} __packed;

/*Task managment request */
struct virtio_scsi_ctrl_tmf_req {
	uint32_t type;
	uint32_t subtype;
	uint8_t  lun[8];
	uint64_t tag;
} __packed;

struct virtio_scsi_ctrl_tmf_resp {
	uint8_t response;
} __packed;

/* asynchronous notification query/subscription */
struct virtio_scsi_ctrl_an_req {
	uint32_t type;
	uint8_t lun[8];
	uint32_t event_requested;
} __packed;

struct virtio_scsi_ctrl_an_resp {
	uint32_t event_actual;
	uint8_t	response;
} __packed;

struct virtio_scsi_event {

	uint32_t event;
	uint8_t lun[8];
	uint32_t reason;
} __packed;

#define VIRTIO_SCSI_BUFFER_ALLOCATED  0x1
#define VIRTIO_SCSI_BUFFER_FREE       0x2

struct virtio_scsi_buffer {

	uint8_t	state; /* state of the buffer - allocated/free */
	caddr_t	buffer_virt; /* virtual address of the buffer */
	ddi_dma_handle_t buffer_dmah; /*  DMA handle */
	ddi_dma_cookie_t buffer_dmac; /* first cookie in the chain */
	ddi_acc_handle_t buffer_acch;  /* access handle for DMA buffer memory */
	unsigned int	buffer_ncookies; /* number of cookies */
	u_int		buffer_nwins; /* number of DMA windows */
	size_t		buffer_size;  /* total buffer size */
};

struct virtio_scsi_request {

	struct scsi_pkt *req_pkt; /* SCSA packet we are servicing */
	struct vq_entry  *req_ve; /* VQ entry we are using */
	/* first buffer is for virtio scsi headers/stuff */
	/* second one - for data payload */
	struct virtio_scsi_buffer virtio_headers_buf;

	boolean_t dir; /* request direction (to/from HBA) */
	int polling_done; /* true if the request is completed */

	unsigned char scbp[DEFAULT_SCBLEN];
	unsigned char cdbp[DEFAULT_CDBLEN];
};

struct virtio_scsi_ld {
	dev_info_t	*dip;
	uint8_t		lun_type;
	uint8_t		reserved[3];
};

struct virtio_scsi_softc {
	dev_info_t		*sc_dev; /* mirrors virtio_softc->sc_dev */
	struct virtio_softc	sc_virtio;
	uint64_t		sc_features;

	struct virtqueue	*sc_control_vq;
	struct virtqueue	*sc_event_vq;
	struct virtqueue	*sc_request_vq;

	scsi_hba_tran_t		*sc_hba_tran;
	uint32_t		sc_max_channel;
	uint32_t		sc_max_target;
	uint32_t		sc_max_lun;
	uint32_t		sc_cdb_size;
	uint32_t		sc_max_seg;
	/* maximal number of requests */
	uint32_t		sc_max_req; /* maximal request queue depth */
	struct virtio_scsi_ld   sc_ld[VIOSCSI_MAX_TARGET];
	struct virtio_scsi_buffer event_buffers[4];
};

/* Configuration registers */
/*
 * Static Variables.
 */
static char virtio_scsi_ident[] = "VirtIO SCSI HBA driver";

static uint_t vioscsi_intr_handler(caddr_t arg1, caddr_t arg2);
static int virtio_scsi_attach(dev_info_t *, ddi_attach_cmd_t);
static int virtio_scsi_detach(dev_info_t *, ddi_detach_cmd_t);
static int virtio_scsi_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int virtio_scsi_quiesce(dev_info_t *);

static int vioscsi_tran_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
		void *, dev_info_t **);

static int vioscsi_tran_bus_reset(dev_info_t *hba_dip, int level);

static void vioscsi_tran_dma_free(struct scsi_address *ap, struct scsi_pkt *pkt);
static void vioscsi_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static int vioscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom);

static int vioscsi_tran_setcap(struct scsi_address *ap, char *cap, int value,
			int whom);
static int vioscsi_tran_reset(struct scsi_address *ap, int level);
static int vioscsi_tran_reset_notify(struct scsi_address *ap,
		int flag, void (*callback)(caddr_t ), caddr_t arg);

static int vioscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int vioscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int vioscsi_tran_bus_unquiesce(dev_info_t *hba_dip);
static int vioscsi_tran_bus_quiesce(dev_info_t *hba_dip);

static int vioscsi_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
scsi_hba_tran_t *hba_tran, struct scsi_device *sd);

static int vioscsi_tran_tgt_probe(struct scsi_device *sd, int (*waitfunc)(void));
static void vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *hba_tran, struct scsi_device *sd);


/* TODO: remove this */
static struct virtio_scsi_softc *global_virtio_scsi_softc;

static struct dev_ops virtio_scsi_dev_ops = {
	DEVO_REV,
	0,
	virtio_scsi_getinfo, /* getinfo */
	nulldev,	/* identify */
	nulldev,	/* probe */
	virtio_scsi_attach,	/* attach */
	virtio_scsi_detach,	/* detach */
	nodev,		/* reset */
	NULL,		/* cb_ops */
	NULL,		/* bus_ops */
	NULL,		/* power */
	virtio_scsi_quiesce	/* quiesce */
};

/* Standard Module linkage initialization for a Streams driver */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	virtio_scsi_ident,	/* short description */
	&virtio_scsi_dev_ops	/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	{
		(void *)&modldrv,
		NULL,
	},
};

static ddi_device_acc_attr_t virtio_scsi_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,	/* virtio is always native byte order */
	DDI_STORECACHING_OK_ACC,
	DDI_DEFAULT_ACC
};

/* DMA attr for the data blocks. */
static ddi_dma_attr_t virtio_scsi_data_dma_attr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0,				/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	1,				/* dma_attr_align	*/
	1,				/* dma_attr_burstsizes	*/
	1,				/* dma_attr_minxfer	*/
	4096,				/* dma_attr_maxxfer, set in attach */
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_seg		*/
	64,				/* dma_attr_sgllen, set in attach */
	1,				/* dma_attr_granular	*/
	0,				/* dma_attr_flags	*/
};


/* SCSI HBA stuff going below */
static int
vioscsi_tran_tgt_probe(struct scsi_device *sd, int (*waitfunc)(void))
{
	return scsi_hba_probe(sd, waitfunc);
}

static int
vioscsi_name_node(dev_info_t *dip, char *name, int len)
{
	int tgt, lun;

	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			DDI_PROP_DONTPASS, "target", -1);
	if (tgt == -1)
		return (DDI_FAILURE);

	lun = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
			DDI_PROP_DONTPASS, "lun", -1);
	if (lun == -1)
		return (DDI_FAILURE);

	(void) snprintf(name, len, "%x,%x", tgt, lun);

	return (DDI_SUCCESS);
}

static
dev_info_t *
vioscsi_find_child(struct virtio_scsi_softc *sc, uint16_t tgt, uint8_t lun)
{
	dev_info_t *child = NULL;
	char addr[SCSI_MAXNAMELEN];
	char tmp[MAXNAMELEN];

	if (tgt < sc->sc_max_target) {

		if (sc->sc_ld[tgt].dip != NULL)
			child = sc->sc_ld[tgt].dip;
		else {

			(void) sprintf(addr, "%x,%x", tgt, lun);

			for (child = ddi_get_child(sc->sc_dev);
				child; child = ddi_get_next_sibling(child)) {

				if (ndi_dev_is_persistent_node(child) == 0)
					continue;

				if (vioscsi_name_node(child, tmp,
					sizeof(tmp)) != DDI_SUCCESS)
					continue;

				if (strcmp(addr, tmp) == 0)
					break;
			}
		}
	}
	return child;
}

/* ARGSUSED */
static int
vioscsi_tran_tgt_init(dev_info_t *hba_dip,
		 dev_info_t *tgt_dip, scsi_hba_tran_t *hba_tran,
		 struct scsi_device *sd)
{
	struct virtio_scsi_softc *sc =
		sd->sd_address.a_hba_tran->tran_hba_private;

	uint16_t tgt = sd->sd_address.a_target;
	uint8_t lun = sd->sd_address.a_lun;

	if (ndi_dev_is_persistent_node(tgt_dip)) {

		if (vioscsi_find_child(sc, tgt, lun) != NULL) {

			if (ndi_merge_node(tgt_dip, vioscsi_name_node) != DDI_SUCCESS)
				return (DDI_SUCCESS);
		}
		return (DDI_SUCCESS);
	}

	if (tgt > sc->sc_max_target)
		return (DDI_FAILURE);

	if (lun != 0 && (sc->sc_ld[tgt].dip == NULL))
		return (DDI_FAILURE);

	sc->sc_ld[tgt].dip = tgt_dip;

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static void
vioscsi_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
			scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	/* TODO: remove debug output */
	printf("%s: called!\n", __FUNCTION__);
	return;
}

static int
vioscsi_tran_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{

	struct vq_entry *ve;
	struct virtio_scsi_request *req = pkt->pkt_ha_private;
	struct virtio_scsi_softc *sc = ap->a_hba_tran->tran_hba_private;
	struct virtio_scsi_cmd_req *cmd_req = NULL;

	struct virtio_scsi_buffer *req_buf = &req->virtio_headers_buf;
	int i;

	cmd_req = (struct virtio_scsi_cmd_req *)req_buf->buffer_virt;

	/* fill in cmd_req */
	cmd_req->lun[0] = 1;
	cmd_req->lun[1] = ap->a_target;
	cmd_req->lun[2] = (ap->a_lun >> 8) | 0x40;
	cmd_req->lun[3] = (ap->a_lun & 0xff);
	cmd_req->tag = (unsigned long)pkt;
	cmd_req->task_attr = 0;
	cmd_req->prio = 0;
	cmd_req->crn = 0;

	if (pkt->pkt_cdbp == NULL) {
		printf("pkt with NULL CDB! pkt at 0x%p\n", (void *)pkt);
		return (TRAN_BADPKT);
	}

	(void) memcpy(cmd_req->cdb, pkt->pkt_cdbp, pkt->pkt_cdblen);

	/* allocate vq_entry */
	ve = vq_alloc_entry(sc->sc_request_vq);

	if (ve == NULL) {
		/* TODO: remove debug output, count some statistic */
		/* TODO: shall we implement some queuing logic here ? */
		/* i.e. queue request if there is no space in the VIRTIO queues */
		/* but just return TRAN_BUSY for now */
		/* TODO: do not forget to count some statistic! */
		printf("%s: cannot allocate VE entry!\n", __func__);
		return (TRAN_BUSY);
	}
	/* add request header */
	virtio_ve_add_indirect_buf(ve,
			req_buf->buffer_dmac.dmac_laddress,
			sizeof(struct virtio_scsi_cmd_req), B_TRUE);
	/* and some space for response */
	virtio_ve_add_indirect_buf(ve,
			req_buf->buffer_dmac.dmac_laddress +
				sizeof(struct virtio_scsi_cmd_req),
			sizeof(struct virtio_scsi_cmd_resp), B_FALSE);

	/* add some payload, if any */
	if (pkt->pkt_numcookies) {
		ddi_dma_cookie_t *dmac;
		for (i = 0; i < pkt->pkt_numcookies; i ++) {
			dmac = &pkt->pkt_cookies[i];
			virtio_ve_add_indirect_buf(ve, dmac->dmac_laddress,
				dmac->dmac_size, pkt->pkt_dma_flags & DDI_DMA_WRITE);
		}
	}
	/* FIXME: use virtio_set_private stuff instead of directly pointing */
	ve->qe_private = req;
//	virtio_set_private(ve, req);

	/* push vq_entry into the queue */
	virtio_push_chain(ve, B_TRUE);

	if (pkt->pkt_flags & FLAG_NOINTR) {
		/* disable interrupts for a while */
		virtio_stop_vq_intr(sc->sc_request_vq);

		/* TODO: add timeout here */
		while (req->polling_done == 0) {
			(void) vioscsi_intr_handler((caddr_t)&sc->sc_virtio, NULL);
			drv_usecwait(10);
		}
		req->polling_done = 0;
		virtio_start_vq_intr(sc->sc_request_vq);
	}
	/* end */
	return (TRAN_ACCEPT);
}

/* ARGSUSED */
static int
vioscsi_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	/* IMO we do not need tran_abort for VIRTIO SCSI case */
	/* TODO: investigate it */

	printf("%s: called!\n", __FUNCTION__);
	return DDI_FAILURE;
}

static void
virtio_scsi_buffer_release(struct virtio_scsi_buffer *vb)
{
	if (vb->state != VIRTIO_SCSI_BUFFER_ALLOCATED)
		return;

	(void) ddi_dma_unbind_handle(vb->buffer_dmah);

	if (vb->buffer_acch)
		(void) ddi_dma_mem_free(&vb->buffer_acch);

	(void) ddi_dma_free_handle(&vb->buffer_dmah);

	vb->state = VIRTIO_SCSI_BUFFER_FREE;
	return;
}

static int
virtio_scsi_buffer_setup(struct virtio_scsi_softc *sc, struct virtio_scsi_buffer* vb, size_t buffer_size)
{
	size_t len;
	int err;

	if (vb->state != VIRTIO_SCSI_BUFFER_FREE) {
		printf("%s: cannot setup not-free buffer\n" ,__func__);
		return DDI_FAILURE;
	}

	err = ddi_dma_alloc_handle(sc->sc_dev, &virtio_scsi_data_dma_attr,
		DDI_DMA_SLEEP, NULL, &vb->buffer_dmah);
	if (err != DDI_SUCCESS) {
		printf("%s: cannot allocate handle, err %d\n", __func__, err);
		return DDI_FAILURE;
	}

	err = ddi_dma_mem_alloc(vb->buffer_dmah, buffer_size, &virtio_scsi_acc_attr,
		DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		&vb->buffer_virt, &len, &vb->buffer_acch);

	if (err != DDI_SUCCESS) {
		printf("%s: cannot allocate memory! err %d blk_size %d\n", __func__, err, (int)buffer_size);
		goto unbind_handle;
	}

	err = ddi_dma_addr_bind_handle(vb->buffer_dmah, NULL, vb->buffer_virt,
		len, DDI_DMA_READ | DDI_DMA_WRITE, DDI_DMA_SLEEP, NULL,
		&vb->buffer_dmac, &vb->buffer_ncookies);

	if (err != DDI_SUCCESS) {
		printf("%s: cannot bind handle, error %d\n", __func__, err);
		goto release_dma_mem;
	}
	vb->state = VIRTIO_SCSI_BUFFER_ALLOCATED;
	vb->buffer_size = buffer_size; /* may be len? */
	return (DDI_SUCCESS);

unbind_handle:
	(void) ddi_dma_unbind_handle(vb->buffer_dmah);

release_dma_mem:
	(void) ddi_dma_mem_free(&vb->buffer_acch);

	return (DDI_FAILURE);
}

 /* preallocate DMA handles and stuff for requests */
 /* TODO: update virtio_scsi_buffer_setup to take into account kmflags */
/* ARGSUSED */
static int
virtio_scsi_req_construct(void *buffer, void *user_arg, int kmflags)
{
	struct virtio_scsi_softc *sc = user_arg;
	struct virtio_scsi_request *req = buffer;
	struct virtio_scsi_buffer *buf;

	buf = &req->virtio_headers_buf;

	buf->state = VIRTIO_SCSI_BUFFER_FREE;

	/* allocate DMA resources for the vioscsi headers */
	/* SCSA will allocate the rest */
	if (virtio_scsi_buffer_setup(sc, buf, 1024) != DDI_SUCCESS)
		return (ENOMEM);

	return 0;
}

/* ARGSUSED */
static void
virtio_scsi_req_destruct(void *buffer, void *user_args)
{
	struct virtio_scsi_request *req = buffer;

	virtio_scsi_buffer_release(&req->virtio_headers_buf);
}

/* ARGSUSED */
static int
vioscsi_tran_setup_pkt(struct scsi_pkt *pkt,
		int (*callback)(caddr_t), caddr_t arg)
{
	/* nothing to do, all resources are already preallocated */
	return 0;
}

/* ARGSUSED */
static void
vioscsi_tran_teardown_pkt(struct scsi_pkt *pkt)
{
	/* nothing to do. resources will be released by packet destructor */
}

static int
vioscsi_tran_pkt_constructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran,
	int kmflags)
{
	struct virtio_scsi_request *req = pkt->pkt_ha_private;
	struct virtio_scsi_softc *sc = tran->tran_hba_private;

	(void) memset(req, 0, sizeof(*req));
	req->req_pkt = pkt;

	return virtio_scsi_req_construct(req, sc, kmflags);
}

static void
vioscsi_tran_pkt_destructor(struct scsi_pkt *pkt, scsi_hba_tran_t *tran)
{
	struct virtio_scsi_request *req = pkt->pkt_ha_private;
	struct virtio_scsi_softc *sc = tran->tran_hba_private;

	virtio_scsi_req_destruct(req, sc);
}

/* TODO: do we really need this callback ? */
/* ARGSUSED */
static void
vioscsi_tran_dma_free(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct virtio_scsi_request *req = pkt->pkt_ha_private;

	virtio_scsi_buffer_release(&req->virtio_headers_buf);
}

/* ARGSUSED */
static void
vioscsi_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	/* TODO: do we need this callback for VIRTIO SCSI? */
	return;
}

/* ARGSUSED */
static int
vioscsi_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int rval = 0;
	struct virtio_scsi_softc *sc = ap->a_hba_tran->tran_hba_private;

	if (cap == NULL) {
		return (-1);
	}
	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
		rval = 4096;
		break;

	case SCSI_CAP_MSG_OUT:
		rval = 1;
		break;

	case SCSI_CAP_DISCONNECT:
		rval = 0;
		break;

	case SCSI_CAP_SYNCHRONOUS:
		rval = 0;
		break;

	case SCSI_CAP_WIDE_XFER:
		rval = 1;
		break;

	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;

	case SCSI_CAP_UNTAGGED_QING:
		rval = 1;
		break;

	case SCSI_CAP_PARITY:
		rval = 1;
		break;

	case SCSI_CAP_LINKED_CMDS:
		rval = 0;
		break;

	case SCSI_CAP_GEOMETRY:
		rval = -1;
		break;

	case SCSI_CAP_CDB_LEN:
		rval = sc->sc_cdb_size;
		break;

	default:
		rval = -1;
	}
	return (rval);
}

/* ARGSUSED */
static int
vioscsi_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int rval = 1;

	if (cap == NULL || whom == 0) {
		return (-1);
	}
	switch (scsi_hba_lookup_capstr(cap)) {
		default:
			rval = 1;
	}
	return (rval);
}

/* ARGSUSED */
static int
vioscsi_tran_reset(struct scsi_address *ap, int level)
{
	/* TODO: implement RESET for VIRTIO SCSI */
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
vioscsi_tran_reset_notify(struct scsi_address *ap, int flags,
			void (*callback)(caddr_t), caddr_t arg)
{
	/* TODO: implement RESET for VIRTIO SCSI */
	return (DDI_FAILURE);
}

static int
virtio_scsi_probe_lun(struct scsi_device *sd)
{
	int rval;
	int probe_result;

	probe_result = scsi_hba_probe(sd, NULL_FUNC);

	rval =  (probe_result == SCSIPROBE_EXISTS) ? NDI_SUCCESS : NDI_FAILURE;
	return (rval);
}

static int
virtio_scsi_config_child(struct virtio_scsi_softc *sc, struct scsi_device *sd, dev_info_t **ddip)
{
	char *nodename = NULL;
	char **compatible = NULL;
	int ncompatible = 0;
	char *childname = NULL;
	dev_info_t *ldip = NULL;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;
	int dtype = sd->sd_inq->inq_dtype & DTYPE_MASK;
	int rval;

	scsi_hba_nodename_compatible_get(sd->sd_inq, NULL, dtype, NULL, &nodename,
		&compatible, &ncompatible);

	if (nodename == NULL) {
		printf("%s: no compatible driver for %d:%d\n", __func__, tgt, lun);
		rval = NDI_FAILURE;
		goto finish;
	}
	childname = (dtype == DTYPE_DIRECT) ? "sd" : nodename;


	rval = ndi_devi_alloc(sc->sc_dev, childname, DEVI_SID_NODEID, &ldip);

	if (rval == NDI_SUCCESS) {
#if 1
		/* TODO: replace debug output with dev_warn or something */
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "target", tgt) != DDI_PROP_SUCCESS) {
			rval = NDI_FAILURE;
			printf("cannot update target node\n");
			goto finish;
		}
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "lun", lun) != DDI_PROP_SUCCESS) {
			rval = NDI_FAILURE;
			printf("cannot update lun node\n");
			goto finish;
		}
		if (ndi_prop_update_string_array(DDI_DEV_T_NONE, ldip, "compatible", compatible, ncompatible)
			!= DDI_PROP_SUCCESS) {
				printf("cannot update compatible string array\n");
				rval = NDI_FAILURE;
				goto finish;
		}
		printf("before ndi_devi_online: driver name %s\n",
			ddi_driver_name(ldip));
#endif
		rval = ndi_devi_online(ldip, NDI_ONLINE_ATTACH);

		if (rval != NDI_SUCCESS) {
			printf("%s: unable to online\n", __func__);
			ndi_prop_remove_all(ldip);
			(void) ndi_devi_free(ldip);
		}
	}
finish:
	if (ddip) {
		*ddip = ldip;
	}
	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (rval);
}

static int
virtio_scsi_config_lun(struct virtio_scsi_softc *sc, int tgt, uint8_t lun, dev_info_t **ldip)
{
	struct scsi_device sd;
	dev_info_t *child;
	int rval;

	if ((child = vioscsi_find_child(sc, tgt, lun)) != NULL) {
		if (ldip)
			*ldip = child;
		return (NDI_SUCCESS);
	}
	bzero(&sd, sizeof(struct scsi_device));

	sd.sd_address.a_hba_tran = sc->sc_hba_tran;
	sd.sd_address.a_target = (uint16_t)tgt;
	sd.sd_address.a_lun = (uint8_t)lun;

	if ((rval = virtio_scsi_probe_lun(&sd)) == NDI_SUCCESS)
		rval = virtio_scsi_config_child(sc, &sd, ldip);

	if (sd.sd_inq) {
		kmem_free(sd.sd_inq, SUN_INQSIZE);
		sd.sd_inq = NULL;
	}
	return (rval);
}

static int
virtio_scsi_parse_devname(char *devnm, int *tgt, int *lun)
{
	char devbuf[SCSI_MAXNAMELEN];
	char *addr;
	char *p, *tp, *lp;
	long num;

	(void) strcpy(devbuf, devnm);
	addr = "";

	for (p = devbuf; *p != '\0'; p ++) {
		if (*p == '@') {
			addr = p + 1;
			*p = '\0';
		} else if (*p == ':') {
			*p = '\0';
			break;
		}
	}
	for (p = tp = addr, lp = NULL; *p != '\0'; p ++) {
		if (*p == ',') {
			lp = p + 1;
			*p = '\0';
			break;
		}
	}
	if (tgt && tp) {
		if (ddi_strtol(tp, NULL, 0x10, &num)) {
			return (DDI_FAILURE);
		}
		*tgt = (int)num;
	}
	if (lun && lp) {
		if (ddi_strtol(lp, NULL, 0x10, &num)) {
			return (DDI_FAILURE);
		}
		*lun = (int)num;
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
vioscsi_tran_bus_config(dev_info_t *hba_dip, uint_t flags, ddi_bus_config_op_t
op,  void *arg, dev_info_t **childs)
{
	int circ;
	int ret = DDI_SUCCESS;
	int tgt, lun;

	struct virtio_scsi_softc *sc = global_virtio_scsi_softc;

	ndi_devi_enter(hba_dip, &circ);


	/* TODO: investigate, and probably implement more ioclts */
	/* currently supported set is enough for sd */
	switch (op) {
		case BUS_CONFIG_ONE:
			if (strchr((char *)arg, '@') == NULL) {
				ret = DDI_FAILURE;
				goto out;
			}

			if (virtio_scsi_parse_devname(arg, &tgt, &lun) != 0) {
				ret = DDI_FAILURE;
				goto out;
			}

			if (lun == 0) {
				ret = virtio_scsi_config_lun(sc, tgt, lun, childs);
			}
			else {
				ret = NDI_FAILURE;
			}
			goto out;

		case BUS_CONFIG_DRIVER:
		case BUS_CONFIG_ALL: {

			uint32_t tgt;

			for (tgt = 0; tgt  < sc->sc_max_target; tgt ++) {
				(void) virtio_scsi_config_lun(sc, tgt, 0, NULL);
			}

		default:
			ret = NDI_FAILURE;
		}

	}
out:
	ndi_devi_exit(hba_dip, circ);
	return (ret);
}

/* ARGSUSED */
static int
vioscsi_tran_bus_reset(dev_info_t *hba_dip, int level)
{
	/*TODO: implement bus reset? */
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
vioscsi_tran_bus_quiesce(dev_info_t *hba_dip)
{
	/* TODO: although virtual scsi bus cannot be quiesced */
	/* probalby we need to stop putting requests into the VQ */
	/* and notify the host SCSI bus somehow that we are stopped. not sure if current virtio SCSI */
	/* provides such a capability */
	printf("%s: called!\n", __FUNCTION__);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
vioscsi_tran_bus_unquiesce(dev_info_t *hba_dip)
{
	/* TODO: the same comment as for virtio_tran_bus_quiesce */
	printf("%s: called!\n", __FUNCTION__);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
uint_t
vioscsi_intr_handler(caddr_t arg1, caddr_t arg2)
{
	struct virtio_softc *vsc = (void *) arg1;
	struct virtio_scsi_softc *sc = container_of(vsc,
		struct virtio_scsi_softc, sc_virtio);
	struct vq_entry *ve;
	struct virtio_scsi_request *req;
	struct virtio_scsi_cmd_resp *resp;
	struct scsi_arq_status *arqstat;
	struct scsi_pkt *pkt;
	uint32_t len;
	struct virtio_scsi_buffer *req_buf = NULL;

	/* TODO: push request into the ready queue and schedule taskq */
	while ((ve = virtio_pull_chain(sc->sc_request_vq, &len)))
	{
		 //req = virtio_get_private(ve);
		req = ve->qe_private;
		ve->qe_private = NULL;

		pkt = req->req_pkt;

		req_buf = &req->virtio_headers_buf;

		resp = (struct virtio_scsi_cmd_resp *)(req_buf->buffer_virt + sizeof(struct virtio_scsi_cmd_req));

		/* TODO: translate virtio SCSI responses into the SCSA status codes */
		switch (resp->response) {

			/* virtio scsi processes request sucessfully, check the request SCSI status */
			case VIRTIO_SCSI_S_OK:

				switch (resp->status) {
					case 0:
					/* ok, request processed by host SCSI */
						pkt->pkt_scbp[0] = STATUS_GOOD;
						break;
					default:
						((struct scsi_status *)pkt->pkt_scbp)->sts_chk = 1;
						if (pkt->pkt_cdbp[0] != SCMD_TEST_UNIT_READY) {

							pkt->pkt_state |= STATE_ARQ_DONE;
							arqstat = (void *)(pkt->pkt_scbp);
							arqstat->sts_rqpkt_reason = CMD_CMPLT;
							arqstat->sts_rqpkt_resid = 0;
							arqstat->sts_rqpkt_state = STATE_GOT_BUS |
								 STATE_GOT_TARGET | STATE_SENT_CMD | STATE_XFERRED_DATA;
							*(uint8_t *)&arqstat->sts_rqpkt_status = STATUS_GOOD;
							(void) memcpy(&arqstat->sts_sensedata, resp->sense, resp->sense_len);
						}
				}
				pkt->pkt_resid = 0;
				pkt->pkt_state |= STATE_XFERRED_DATA;
				pkt->pkt_reason = CMD_CMPLT;

				break;
			default:
				pkt->pkt_reason = CMD_TRAN_ERR;
		}
		/* if packet is processed in polling mode - notify the caller that it may done */
		/* no races, because in this case we are not invoked by virtio interrupt */
		req->polling_done = 1;

		scsi_hba_pkt_comp(pkt);

		virtio_free_chain(ve);
	}
	return (DDI_INTR_CLAIMED);
}

static int
vioscsi_register_ints(struct virtio_scsi_softc *sc)
{
	int ret;

	struct virtio_int_handler virtio_scsi_intr_h[] = {
		{ vioscsi_intr_handler },
		{ NULL },
	};

	ret = virtio_register_ints(&sc->sc_virtio,
	    NULL, virtio_scsi_intr_h);

	return (ret);
}

/* ARGSUSED */
static int
virtio_scsi_getinfo(dev_info_t *devinfo, ddi_info_cmd_t cmd, void *arg,
	void **resultp)
{
	int rval = DDI_SUCCESS;
	int minor = getminor((dev_t)arg);
	struct virtio_scsi_softc *sc = global_virtio_scsi_softc;

	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
		/*FIXME: only one instance is supported */
			*resultp = sc->sc_dev;
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = (void *)(intptr_t)(MINOR2INST(minor));
			break;
		default:
			rval = DDI_FAILURE;
			*resultp = NULL;
	}
	return (rval);
}

static int
virtio_scsi_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;
	int instance;
	struct virtio_scsi_softc *sc;
	struct virtio_softc *vsc;
	scsi_hba_tran_t *hba_tran;

	instance = ddi_get_instance(devinfo);

	printf("%s: kmem_cached SCSA version\n", __func__);
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	case DDI_PM_RESUME:
		ret = DDI_FAILURE;

	default:
		ret = DDI_FAILURE;
	}

	/* TODO: rework static allocation */
	sc = kmem_zalloc(sizeof(struct virtio_scsi_softc), KM_SLEEP);
	global_virtio_scsi_softc = sc;

	vsc = &sc->sc_virtio;

	/* Duplicate for faster access / less typing */
	sc->sc_dev = devinfo;
	vsc->sc_dev = devinfo;

	/* map BAR0 */
	ret = ddi_regs_map_setup(devinfo, 1,
	    (caddr_t *)&sc->sc_virtio.sc_io_addr,
	    0, 0, &virtio_scsi_acc_attr, &sc->sc_virtio.sc_ioh);

	if (ret != DDI_SUCCESS) {
		goto exit_sc;
	}

	virtio_device_reset(&sc->sc_virtio);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_ACK);
	virtio_set_status(&sc->sc_virtio, VIRTIO_CONFIG_DEVICE_STATUS_DRIVER);

	/* TODO: get device features and stuff */

	sc->sc_max_target =
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_MAX_TARGET);

	sc->sc_max_lun =
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_MAX_LUN);


	sc->sc_max_channel =
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_MAX_CHANNEL);

	sc->sc_max_req = sc->sc_max_lun *
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_CMD_PER_LUN);

	sc->sc_cdb_size =
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_CDB_SIZE);

	sc->sc_max_seg =
		virtio_read_device_config_4(&sc->sc_virtio,
			VIRTIO_SCSI_CFG_SEG_MAX);

	if (vioscsi_register_ints(sc)) {
		goto enable_intrs_fail;
	}
	/* allocate queues */

	/* 128 indirect descriptors seems to be enough */
	sc->sc_control_vq = virtio_alloc_vq(&sc->sc_virtio, 0,
		0, 128, "Virtio SCSI control queue");
	if (sc->sc_control_vq == NULL) {
		goto enable_intrs_fail;
	}
	sc->sc_event_vq = virtio_alloc_vq(&sc->sc_virtio, 1,
		0, 128, "Virtio SCSI event queue");

	if (sc->sc_event_vq == NULL) {
		goto release_control;
	}
	sc->sc_request_vq = virtio_alloc_vq(&sc->sc_virtio, 2,
		0, 128, "Virtio SCSI request queue");

	if (sc->sc_request_vq == NULL) {
		goto release_event;
	}

	hba_tran = scsi_hba_tran_alloc(devinfo, SCSI_HBA_CANSLEEP);

	sc->sc_hba_tran = hba_tran;

	hba_tran->tran_hba_len = sizeof(struct virtio_scsi_request);
	hba_tran->tran_hba_private = sc;
	hba_tran->tran_tgt_private = NULL;
	hba_tran->tran_tgt_init = vioscsi_tran_tgt_init;
	hba_tran->tran_tgt_probe = vioscsi_tran_tgt_probe;
	hba_tran->tran_tgt_free = vioscsi_tran_tgt_free;

	hba_tran->tran_start = vioscsi_tran_start;
	hba_tran->tran_abort = vioscsi_tran_abort;
	hba_tran->tran_reset = vioscsi_tran_reset;
	hba_tran->tran_getcap = vioscsi_tran_getcap;
	hba_tran->tran_setcap = vioscsi_tran_setcap;

	hba_tran->tran_setup_pkt = vioscsi_tran_setup_pkt;
	hba_tran->tran_teardown_pkt = vioscsi_tran_teardown_pkt;
	hba_tran->tran_pkt_constructor = vioscsi_tran_pkt_constructor;
	hba_tran->tran_pkt_destructor = vioscsi_tran_pkt_destructor;

	hba_tran->tran_dmafree = vioscsi_tran_dma_free;
	hba_tran->tran_sync_pkt = vioscsi_tran_sync_pkt;
	hba_tran->tran_reset_notify = vioscsi_tran_reset_notify;
	hba_tran->tran_quiesce = vioscsi_tran_bus_quiesce;
	hba_tran->tran_unquiesce = vioscsi_tran_bus_unquiesce;
	hba_tran->tran_bus_reset = vioscsi_tran_bus_reset;
	hba_tran->tran_bus_config = vioscsi_tran_bus_config;

	ret = scsi_hba_attach_setup(devinfo, &virtio_scsi_data_dma_attr,
			 hba_tran, SCSI_HBA_TRAN_CLONE | SCSI_HBA_TRAN_CDB | SCSI_HBA_TRAN_SCB);
	if (ret != DDI_SUCCESS) {
		goto release_request;
	}

	if (ddi_create_minor_node(devinfo, "devctl", S_IFCHR,
		INST2DEVCTL(instance), DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) {
		goto detach_hba;
	}
	/* FIXME: have to destroy devctl node */
	if (ddi_create_minor_node(devinfo, "scsi", S_IFCHR,
		INST2DEVCTL(instance), DDI_NT_SCSI_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {

		(void) ddi_remove_minor_node(devinfo, "devctl");
		goto detach_hba;
	}
	ddi_report_dev(devinfo);

	(void) virtio_enable_ints(&sc->sc_virtio);
	return (DDI_SUCCESS);

detach_hba:
	(void) scsi_hba_detach(devinfo);

release_request:
	virtio_free_vq(sc->sc_request_vq);

release_event:
	virtio_free_vq(sc->sc_event_vq);

release_control:
	virtio_free_vq(sc->sc_control_vq);

enable_intrs_fail:
	ddi_regs_map_free(&sc->sc_virtio.sc_ioh);

exit_sc:
	kmem_free(sc, sizeof(* sc));
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int virtio_scsi_quiesce(dev_info_t *devinfo)
{
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
virtio_scsi_detach(dev_info_t *devinfo, ddi_detach_cmd_t cmd)
{
	struct virtio_scsi_softc *sc;

	if ((sc = ddi_get_driver_private(devinfo)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_PM_SUSPEND:
		cmn_err(CE_WARN, "suspend not supported yet");
		return (DDI_FAILURE);

	default:
		cmn_err(CE_WARN, "cmd 0x%x unrecognized", cmd);
		return (DDI_FAILURE);
	}

	virtio_stop_vq_intr(sc->sc_request_vq);

	virtio_release_ints(&sc->sc_virtio);

	/* SCSA will take care about kmem cache destruction */
	if (scsi_hba_detach(devinfo) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	virtio_free_vq(sc->sc_request_vq);
	virtio_free_vq(sc->sc_event_vq);
	virtio_free_vq(sc->sc_control_vq);

	(void) ddi_remove_minor_node(devinfo, "scsi");
	(void) ddi_remove_minor_node(devinfo, "devctl");

	kmem_free(sc, sizeof(* sc));

	return (DDI_SUCCESS);
}

int _init(void)
{
	int err = 0;

	if (err != 0)
		return DDI_FAILURE;

	err = scsi_hba_init(&modlinkage);

	if (err != 0) {
		return err;
	}
	err = mod_install(&modlinkage);
	if (err != 0) {
		scsi_hba_fini(&modlinkage);
		return err;
	}
	return DDI_SUCCESS;
}

int _fini(void)
{
	int err;

	err = mod_remove(&modlinkage);
	if (err != 0) {
		return err;
	}

	scsi_hba_fini(&modlinkage);

	return DDI_SUCCESS;
}

int _info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
