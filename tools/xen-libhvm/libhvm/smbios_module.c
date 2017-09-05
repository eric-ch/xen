/*
 * smbios_module.c: routines for reading SMBIOS structs from host memory
 * or sysfs.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>
#include "xenhvm.h"
#include "xen_smbios.h"
#include "xh_internal.h"

#define XH_SMBIOS_FLAG_FOUND   0x80

struct xh_smbios_ctx {
    struct xh_common_ctx common_ctx;

    struct xh_smbios_spec *type_list;
    uint32_t type_count;

    union {
        struct {
            off_t paddr;
            uint16_t length;
            uint16_t count;
            uint8_t *vaddr;
        } mmap;
        struct {
            uint32_t reserved;
        } sysfs;
    } source;
};

#define XH_SMBIOS_SYSFS_PARENT "/sys/firmware/dmi/entries/"
#define XH_SMBIOS_SYSFS_DIRFMT "%d-%d"

static int xh_check_smbios_table(struct xh_smbios_ctx *smctx,
                                 uint8_t type,
                                 uint16_t ordinal)
{
    uint32_t i;

    /* Check if this table is wanted. Note that this module building code
     * will take any table type requested, be it DMTF defined or vendor
     * specific. The hvmloader code that processes it though will be limited
     * in what tables will accepted for pass-through.
     */

    for ( i = 0; i < smctx->type_count; i++ )
    {
        if ( smctx->type_list[i].flags & XH_SMBIOS_FLAG_GE ) {
            if (smctx->type_list[i].type > type)
                continue;
        } else if ( smctx->type_list[i].type != type ) {
            continue;
        }

        /* Match, see if it is the first or all are wanted */
        if ( smctx->type_list[i].flags & XH_SMBIOS_FLAG_ALL )
            return 1;

        /* Only one is wanted */
        if ( (smctx->type_list[i].flags & XH_SMBIOS_FLAG_FOUND) == 0 )
        {
            /* Take the one at the ordinal value 0 if ordinal is specified */
            if ( (ordinal == XH_ORDINAL_UNSPECIFIED)||(ordinal == 0) )
            {
                smctx->type_list[i].flags |= XH_SMBIOS_FLAG_FOUND;
                return 1;
            }
        }

        break;
    }

    return 0;
}

static int xh_smbios_entry_point_mmap(struct xh_smbios_ctx *smctx,
                                      uint8_t *entry_point,
                                      int is_eps)
{
    uint8_t sum = 0;
    uint32_t count;

    /* For any of the failures scanning or running checksums */
    errno = ENOENT;

    if ( is_eps )
    {
        /* Checksum sanity check on _SM_ entry point */
        for ( count = 0; count < entry_point[XH_SMBIOS_EPS_LENGTH]; count++ )
            sum += entry_point[count];

        if ( sum != 0 )
            return -1;

        /* Nothing else really interesting in the EPS, move to the IEPS */
        entry_point += XH_SMBIOS_IEPS_STRING;
        if ( memcmp(entry_point, "_DMI_", 5) != 0 )
            return -1;
    }

    /* Entry point is IEPS, do checksum of this portion */
    for ( count = 0; count < XH_SMBIOS_DMI_LENGTH; count++ )
        sum += entry_point[count];

    if ( sum != 0 )
        return -1;

    /* Now get structure table values */
    smctx->source.mmap.paddr =
        (*(uint32_t*)(entry_point +
            XH_SMBIOS_TABLE_ADDRESS - XH_SMBIOS_IEPS_STRING));
    smctx->source.mmap.length =
        (*(uint16_t*)(entry_point +
            XH_SMBIOS_TABLE_LENGTH - XH_SMBIOS_IEPS_STRING));
    smctx->source.mmap.count =
        (*(uint16_t*)(entry_point +
            XH_SMBIOS_STRUCT_COUNT - XH_SMBIOS_IEPS_STRING));

    /* Make sure these values are realistic, like not enough room for even
     * one structure header.
     */
    if ( (smctx->source.mmap.length < 4)||(smctx->source.mmap.count == 0) )
        return -1;

    smctx->source.mmap.vaddr =
        xh_mmap(smctx->source.mmap.paddr, smctx->source.mmap.length);
    if ( smctx->source.mmap.vaddr == NULL )
        return -1;

    return 0;
}

static int xh_locate_smbios_mmap(struct xh_smbios_ctx *smctx)
{
    size_t loc = 0;
    uint8_t *vaddr;
    int rc = -1;
    XH_ERR;

    /* Use EFI tables if present */
    rc = xh_efi_locate("SMBIOS", 6, &loc);
    if ( (rc == 0)&&(loc != 0) )
    {
        vaddr = xh_mmap(loc, XH_SMBIOS_SM_LENGTH);
        if ( vaddr == NULL )
            return -1;

        rc = xh_smbios_entry_point_mmap(smctx, vaddr, 1);
        XH_PUSHERR();
        xh_unmmap(vaddr, XH_SMBIOS_SM_LENGTH);
        XH_POPERR();
        return rc;
    }

    /* Locate SMBIOS entry via memory scan of ROM region */
    vaddr = xh_mmap(XH_SCAN_ROM_BIOS_BASE, XH_SCAN_ROM_BIOS_SIZE);
    if ( vaddr == NULL )
        return -1;

    for ( loc = 0; loc <= (XH_SCAN_ROM_BIOS_SIZE - XH_SMBIOS_SM_LENGTH); loc += 16)
    {
        /* Stop before 0xFFE0. Look for _SM_ signature for newer entry point
         * which preceeds _DMI_, else look for only the older _DMI_
         */
        if ( memcmp(vaddr + loc, "_SM_", 4) == 0 )
        {
            rc = xh_smbios_entry_point_mmap(smctx, vaddr + loc, 1);
            if ( rc == 0 ) /* found it */
                break;
        }
        else if ( memcmp(vaddr + loc, "_DMI_", 5) == 0 )
        {
            rc = xh_smbios_entry_point_mmap(smctx, vaddr + loc, 0);
            if ( rc == 0 ) /* found it */
                break;
        }
    }

    XH_PUSHERR();
    xh_unmmap(vaddr, XH_SCAN_ROM_BIOS_SIZE);
    XH_POPERR();

    return rc;
}

static int xh_decode_smbios_mmap(struct xh_smbios_ctx *smctx)
{
    uint16_t idx;
    uint8_t *ptr, *tail;
    uint32_t copied;

    if ( xh_locate_smbios_mmap(smctx) )
        return -1;

    ptr = smctx->source.mmap.vaddr;

    for ( idx = 0; idx < smctx->source.mmap.count; idx++ )
    {
        if ( (ptr[XH_SMBIOS_STRUCT_LENGTH] < 4)||
            ((ptr + ptr[XH_SMBIOS_STRUCT_LENGTH]) >
             (ptr + smctx->source.mmap.length)) )
        {
            errno = ENOENT;
            return -1;
        }

        /* Run the tail pointer past the end of this struct and all strings */
        tail = ptr + ptr[XH_SMBIOS_STRUCT_LENGTH];
        while ( (tail - ptr + 1) < smctx->source.mmap.length )
        {
            if ( (tail[0] == 0)&&(tail[1] == 0) )
                break;
            tail++;
        }
        tail += 2;

        if ( xh_check_smbios_table(smctx,
                                   ptr[XH_SMBIOS_STRUCT_TYPE],
                                   XH_ORDINAL_UNSPECIFIED) )
        {
            copied = xh_copy_common(&(smctx->common_ctx), ptr, tail - ptr);
            if ( copied == 0 ) /* Memory allocation failure, drop out. */
                return -1;
        }

        /* Test for terminating structure */
        if ( ptr[XH_SMBIOS_STRUCT_TYPE] == XH_SMBIOS_TYPE_EOT )
        {
            /* Table is done - sanity check */
            if ( idx != smctx->source.mmap.count - 1 )
            {
                errno = ENOENT;
                return -1;
            }
        }

        ptr = tail;
    }

    return 0;
}

static int xh_decode_smbios_sysfs(struct xh_smbios_ctx *smctx)
{
#define XH_SMBIOS_DIR_MAX 64
    DIR *parent;
    struct dirent *de;
    uint8_t *table_buf;
    uint32_t table_length, copied;
    int ret, tid, ord, rc = 0;
    char table_file[sizeof(XH_SMBIOS_SYSFS_PARENT) + XH_SMBIOS_DIR_MAX + 1];
    XH_ERR;

    parent = opendir(XH_SMBIOS_SYSFS_PARENT);
    if ( parent == NULL )
        return -1;

    de = readdir(parent);
    while ( de != NULL )
    {
        if ( de->d_name[0] == '.' )
        {
            de = readdir(parent);
            continue;
        }

        /* Dir of the form M-N where M is the table ID and N is the
         * table instance (0 - n).
         */
        ret = sscanf(de->d_name, "%d-%d", &tid, &ord);
        if ( ret != 2 )
        {
            rc = -1;
            break;
        }

        if ( xh_check_smbios_table(smctx, tid, ord) )
        {
            strcpy(table_file, XH_SMBIOS_SYSFS_PARENT);
            strncat(table_file, de->d_name, XH_SMBIOS_DIR_MAX);
            strncat(table_file, "/raw", XH_SMBIOS_DIR_MAX);

            table_buf = xh_read_bin_sysfs(table_file, &table_length);
            if ( table_buf == NULL )
            {
                rc = -1;
                break;
            }

            copied = xh_copy_common(&(smctx->common_ctx),
                                    table_buf,
                                    table_length);
            XH_PUSHERR();
            free(table_buf);
            XH_POPERR();
            if ( copied == 0 )
            {
                rc = -1;
                break;
            }
        }

        de = readdir(parent);
    }

    XH_PUSHERR();
    closedir(parent);
    XH_POPERR();

    return rc;
}

static void xh_smbios_context_cleanup(struct xh_smbios_ctx *smctx)
{
    if ( smctx->source.mmap.vaddr != NULL )
        xh_unmmap(smctx->source.mmap.vaddr, smctx->source.mmap.length);

    free(smctx->type_list);
    xh_cleanup_common(&(smctx->common_ctx));
}

int xh_find_smbios_structures(enum xh_decode_mode mode,
                              struct xh_smbios_spec *type_list,
                              uint32_t type_count,
                              uint8_t **out_buffer,
                              uint32_t *out_length)
{
    struct xh_smbios_ctx smctx;
    int rc = 0;
    XH_ERR;

    if ( (type_list == NULL)||(type_count == 0)||
         (out_buffer == NULL)||(out_length == NULL) )
    {
        errno = EINVAL;
        return -1;
    }

    memset(&smctx, 0, sizeof(struct xh_smbios_ctx));

    /* Copy the type list size it will be used to track state. */
    smctx.type_list = calloc(type_count, sizeof(struct xh_smbios_spec));
    if ( smctx.type_list == NULL )
        return -1;

    memcpy(smctx.type_list, type_list,
        (type_count*sizeof(struct xh_smbios_spec)));
    smctx.type_count = type_count;

    if ( xh_init_common(mode, &(smctx.common_ctx)) )
        goto error_out;

    /* Use the mode specified. If XH_DECODE_BOTH is specified then try
     * to use sysfs first, fall back to mmap if that fails.
     */
    if ( mode == XH_DECODE_BOTH )
    {
        rc = xh_decode_smbios_sysfs(&smctx);
        if ( rc )
            rc = xh_decode_smbios_mmap(&smctx);
    }
    else if ( mode == XH_DECODE_SYSFS )
        rc = xh_decode_smbios_sysfs(&smctx);
    else if ( mode == XH_DECODE_MMAP )
        rc = xh_decode_smbios_mmap(&smctx);

    if ( rc )
        goto error_out;

    /* Final format of the module header */
    xh_format_common(&(smctx.common_ctx), XH_FIRMWARE_SMBIOS);

    *out_buffer = smctx.common_ctx.buffer;
    *out_length = smctx.common_ctx.total_length;
    smctx.common_ctx.buffer = NULL;

    xh_smbios_context_cleanup(&smctx);
    return 0;

error_out:

    XH_PUSHERR();
    xh_smbios_context_cleanup(&smctx);
    XH_POPERR();

    return rc;
}

int xh_xen_vendor_smbios_structure(const char *manufacturer,
                                   const char *product,
                                   uint32_t features,
                                   uint32_t quirks,
                                   uint8_t **out_buffer,
                                   uint32_t *out_length)
{
    struct xen_vendor_smbios_rev1 *xvt;
    char *ptr;
    uint32_t length;

    /* Determine size which includes the strings and terminator. */
    if ( manufacturer == NULL )
        manufacturer = "Xen";
    if ( product == NULL )
        product = "HVM domU";

    /* Add a terminator for each string + one for the table end. */
    length = sizeof(struct xen_vendor_smbios_rev1);
    length += strlen(manufacturer) + strlen(product);
    length += strlen(XEN_SMBIOS_TAG_STRING) + 4;
    xvt = malloc(length);
    if ( xvt == NULL )
        return -1;
    memset(xvt, 0, length);

    /* Setup header, use a handle value that is unlikely to conflict. */
    xvt->type = XEN_SMBIOS_VENDOR_TYPE;
    xvt->length = sizeof(struct xen_vendor_smbios_rev1);
    xvt->handle = (XEN_SMBIOS_VENDOR_TYPE << 8) | 0xA5;

    xvt->magic = XEN_SMBIOS_MAGIC;
    xvt->revision = XEN_SMBIOS_REVISION;
    xvt->tag_str = XEN_SMBIOS_TAG_STRING_NUM;
    xvt->manufacturer_str = XEN_SMBIOS_MANUFACTURER_STRING_NUM;
    xvt->product_str = XEN_SMBIOS_PRODUCT_STRING_NUM;
    xvt->features = features;
    xvt->quirks = quirks;

    ptr = (char*)xvt + sizeof(struct xen_vendor_smbios_rev1);

    strcpy(ptr, XEN_SMBIOS_TAG_STRING);
    ptr += strlen(XEN_SMBIOS_TAG_STRING) + 1;

    strcpy(ptr, manufacturer);
    ptr += strlen(manufacturer) + 1;

    strcpy(ptr, product);

    *out_buffer = (uint8_t*)xvt;
    *out_length = length;

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
