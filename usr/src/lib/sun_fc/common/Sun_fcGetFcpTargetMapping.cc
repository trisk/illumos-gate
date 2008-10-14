/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include "Trace.h"
#include "Exceptions.h"
#include "sun_fc.h"



#include <string.h>
#include "Handle.h"
#include "HBA.h"
#include "HBAPort.h"
inline HBA_WWN
getFirstAdapterPortWWN(HBA_HANDLE handle) {
	HBA_WWN hba_wwn;
	memset(hba_wwn.wwn, 0, sizeof (hba_wwn));
	try {
	    Handle *myHandle = Handle::findHandle(handle);
	    HBA *hba = myHandle->getHBA();
	    HBAPort *port = hba->getPortByIndex(0);
	    uint64_t tmp = htonll(port->getPortWWN());
	    memcpy(hba_wwn.wwn, &tmp, sizeof (hba_wwn));
	} catch (...) { }
	return (hba_wwn);
}

#ifdef	__cplusplus
extern "C" {
#endif

/**
 * @memo	    Retrieves the mapping between FCP targets and OS
 *		    SCSI information
 * @return	    HBA_STATUS_OK if the mapping structure contains valid
 *		    mapping data.
 * @param	    handle The HBA to fetch mappings for
 * @param	    mapping The user-allocated mapping structure
 *
 * @doc		    This routine will call the V2 interface and convert
 *		    the results to the old data structure.  It will
 *		    call the V2 interface for all ports on the HBA.
 */
HBA_STATUS
Sun_fcGetFcpTargetMapping(HBA_HANDLE handle, PHBA_FCPTARGETMAPPING mapping) {
	HBA_STATUS		    status;
	int			    count;
	PHBA_FCPTARGETMAPPINGV2	    mappingV2;

	Trace log("Sun_fcGetFcpTargetMapping");

	if (mapping == NULL) {
	    log.userError("NULL mapping argument.");
	    return (HBA_STATUS_ERROR_ARG);
	}
	mappingV2 = (PHBA_FCPTARGETMAPPINGV2) new uchar_t[
	    (sizeof (HBA_FCPSCSIENTRYV2)*(mapping->NumberOfEntries-1)) +
	    sizeof (HBA_FCPTARGETMAPPINGV2)];
	mappingV2->NumberOfEntries = mapping->NumberOfEntries;



	status = Sun_fcGetFcpTargetMappingV2(handle,
	    getFirstAdapterPortWWN(handle), mappingV2);
	mapping->NumberOfEntries = mappingV2->NumberOfEntries;
	if (status == HBA_STATUS_OK) {
		/*
		 * need to copy from PHBA_FCPTARGETMAPPINGV2 to
		 * PHBA_FCPTARGETMAPPING
		 */
		for (count = 0; count < mapping->NumberOfEntries; count++) {
			memcpy(&mapping->entry[count].ScsiId,
			    &mappingV2->entry[count].ScsiId,
			    sizeof (mapping->entry[count].ScsiId));
			memcpy(&mapping->entry[count].FcpId,
			    &mappingV2->entry[count].FcpId,
			    sizeof (mapping->entry[count].FcpId));
		}
	}

	delete(mappingV2);
	return (status);
}
#ifdef	__cplusplus
}
#endif
