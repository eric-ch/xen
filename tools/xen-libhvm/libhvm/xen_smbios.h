/*
 * xen_smbios.c: definitions for a Xen vendor SMBIOS structure.
 *
 * Copyright (c) 2013 Ross Philipson
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef XEN_SMBIOS_H
#define XEN_SMBIOS_H

/* The following defines a possible Xen vendor specific SMBIOS struct
 * that could be passed to an HVM guest. Such a structure could be
 * useful for passing information to a guest that has no other Xen tools
 * installed, for expample, passing information to installer packages
 * to control their behavior.
 *
 * See xh_xen_vendor_smbios_structure
 */

/* SMBIOS Vendor type value for Xen */
#define XEN_SMBIOS_VENDOR_TYPE 251

/* Length in bytes of the fixed portion of the table for a given revision */
#define XEN_SMBIOS_TABLE_LENGTH 20

/* Magic value to help identify the XenClient table */
#define XEN_SMBIOS_MAGIC 0x222D3338  /* "XSMB" */

/* Current revision value */
#define XEN_SMBIOS_REVISION 1

/* String number for the tag string */
#define XEN_SMBIOS_TAG_STRING_NUM 1

/* String number for the manufacturer name */
#define XEN_SMBIOS_MANUFACTURER_STRING_NUM 2

/* String number for the product name */
#define XEN_SMBIOS_PRODUCT_STRING_NUM 3

/* Usage specific feature flags */
#define XEN_SMBIOS_FEATURES_NONE 0x00000000

/* Platform quirks flags */
#define XEN_SMBIOS_QUIRKS_NONE   0x00000000

/* Table tag string identifier following fixed portion of the table */
#define XEN_SMBIOS_TAG_STRING "XEN-SMBIOS-TABLE"

struct xen_vendor_smbios_rev1 {
    /* standard structure header */
    uint8_t type;
    uint8_t length;
    uint16_t handle;
    /* xen smbios fixed table area */
    uint32_t magic;
    uint8_t revision;
    uint8_t tag_str;
    uint8_t manufacturer_str;
    uint8_t product_str;
    uint32_t features;
    uint32_t quirks;
} __attribute__ ((packed));

#endif /* XEN_SMBIOS_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
