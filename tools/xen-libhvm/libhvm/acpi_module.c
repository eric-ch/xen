/*
 * acpi_module.c: routines for reading ACPI tables from host memory
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
#include <sys/stat.h>
#include "xenhvm.h"
#include "xen_smbios.h"
#include "xh_internal.h"

struct xh_acpi_ctx {
    struct xh_common_ctx common_ctx;

    struct xh_acpi_spec *table_list;
    uint32_t table_count;

    union {
        struct {
            off_t rsdt_paddr;
            uint8_t *rsdt_vaddr;
            uint32_t rsdt_length;
            off_t xsdt_paddr;
            uint8_t *xsdt_vaddr;
            uint32_t xsdt_length;
            int is_rev1;
        } mmap;
        struct {
            uint32_t reserved;
        } sysfs;
    } source;
};

struct xh_acpi_table_info {
    off_t paddr;
    uint8_t *vaddr;
    uint32_t length;
};

enum xh_match_table {
    XH_MATCH_ERROR = 0,
    XH_MATCH_MISS,
    XH_MATCH_FOUND
};

#define XH_ACPI_SYSFS_PARENT "/sys/firmware/acpi/tables/"

static int xh_process_rsdp_mmap(struct xh_acpi_ctx *acctx, uint8_t *rsdp)
{
    uint8_t sum;
    uint32_t count, length;
    XH_ERR;

    /* Checksum sanity check over the RSDP */
    if ( rsdp[XH_ACPI_RSDP_REVISION] < 2 )
    {
        length = XH_ACPI_RSDP_CS_LENGTH;
        acctx->source.mmap.is_rev1 = 1;
    }
    else
        length = XH_ACPI_RSDP_XCS_LENGTH;

    for ( sum = 0, count = 0; count < length; count++ )
        sum += rsdp[count];

    if ( sum != 0 )
    {
        errno = ENOENT;
        goto error_out;
    }

    /* looks like the RSDP, get RSDT table */
    acctx->source.mmap.rsdt_paddr =
        (*(uint32_t*)(rsdp + XH_ACPI_RSDP_RSDT_BASE));
    acctx->source.mmap.rsdt_length =
        XH_ACPI_HEADER_LENGTH;
    acctx->source.mmap.rsdt_vaddr =
        xh_mmap(acctx->source.mmap.rsdt_paddr, XH_ACPI_HEADER_LENGTH);
    if ( acctx->source.mmap.rsdt_vaddr == NULL )
        goto error_out;

    /* Check the signatures for the RSDT */
    if ( memcmp(acctx->source.mmap.rsdt_vaddr, "RSDT", 4) != 0)
    {
        errno = ENOENT;
        goto error_out;
    }

    /* Remap the entire table */
    acctx->source.mmap.rsdt_length =
        (*(uint32_t*)(acctx->source.mmap.rsdt_vaddr + XH_ACPI_TABLE_LENGTH));
    xh_unmmap(acctx->source.mmap.rsdt_vaddr, XH_ACPI_HEADER_LENGTH);

    acctx->source.mmap.rsdt_vaddr =
        xh_mmap(acctx->source.mmap.rsdt_paddr,
                acctx->source.mmap.rsdt_length);
    if ( acctx->source.mmap.rsdt_vaddr == NULL )
        goto error_out;

    if ( acctx->source.mmap.is_rev1 )
        goto done_out;

    /* Else, also have an XSDT */
    acctx->source.mmap.xsdt_paddr =
        (*(uint64_t*)(rsdp + XH_ACPI_RSDP_XSDT_BASE));
    acctx->source.mmap.xsdt_length =
        XH_ACPI_HEADER_LENGTH;
    acctx->source.mmap.xsdt_vaddr =
        xh_mmap(acctx->source.mmap.xsdt_paddr, XH_ACPI_HEADER_LENGTH);
    if ( acctx->source.mmap.xsdt_vaddr == NULL )
        goto error_out;

    /* Check the signatures for the XSDT */
    if ( memcmp(acctx->source.mmap.xsdt_vaddr, "XSDT", 4) != 0)
    {
        errno = ENOENT;
        goto error_out;
    }

    /* Remap the entire table */
    acctx->source.mmap.xsdt_length =
        (*(uint32_t*)(acctx->source.mmap.xsdt_vaddr + XH_ACPI_TABLE_LENGTH));
    xh_unmmap(acctx->source.mmap.xsdt_vaddr, XH_ACPI_HEADER_LENGTH);

    acctx->source.mmap.xsdt_vaddr =
        xh_mmap(acctx->source.mmap.xsdt_paddr,
                acctx->source.mmap.xsdt_length);
    if ( acctx->source.mmap.xsdt_vaddr == NULL )
        goto error_out;

done_out:
    return 0;

error_out:
    XH_PUSHERR();
    if ( acctx->source.mmap.rsdt_vaddr != NULL )
        xh_unmmap(acctx->source.mmap.rsdt_vaddr,
                  acctx->source.mmap.rsdt_length);
    if ( acctx->source.mmap.xsdt_vaddr != NULL )
        xh_unmmap(acctx->source.mmap.xsdt_vaddr,
                  acctx->source.mmap.xsdt_length);
    XH_POPERR();

    return -1;
}

static int xh_locate_acpi_mmap(struct xh_acpi_ctx *acctx)
{
    size_t loc = 0;
    uint8_t *vaddr;
    int rc = -1;
    XH_ERR;

    /* Use EFI tables if present */
    rc = xh_efi_locate("ACPI20", 6, &loc);
    if ( (rc == 0) && (loc != 0) )
    {
        vaddr = xh_mmap(loc, XH_ACPI_RSDP_LENGTH);
        if ( vaddr == NULL )
            return -1;

        rc = xh_process_rsdp_mmap(acctx, vaddr);
        XH_PUSHERR();
        xh_unmmap(vaddr, XH_ACPI_RSDP_LENGTH);
        XH_POPERR();
        return rc;
    }

    /* Locate ACPI entry via memory scan of ROM region */
    vaddr = xh_mmap(XH_SCAN_ROM_BIOS_BASE, XH_SCAN_ROM_BIOS_SIZE);
    if ( vaddr == NULL )
        return -1;

    for ( loc = 0; loc <= (XH_SCAN_ROM_BIOS_SIZE - XH_ACPI_RSDP_LENGTH); loc += 16)
    {
        /* Stop before 0xFFDC */
        /* look for RSD PTR  signature */
        if ( memcmp(vaddr + loc, "RSD PTR ", 8) == 0 )
        {
            rc = xh_process_rsdp_mmap(acctx, vaddr + loc);
            if ( rc == 0 ) /* found it */
                break;
        }
    }

    XH_PUSHERR();
    xh_unmmap(vaddr, XH_SCAN_ROM_BIOS_SIZE);
    XH_POPERR();

    return rc;
}

static enum xh_match_table xh_match_table(off_t paddr,
                                          struct xh_acpi_spec *table,
                                          struct xh_acpi_table_info *ti,
                                          uint32_t *pord)
{
    uint8_t *vaddr;

    vaddr = xh_mmap(paddr, XH_ACPI_HEADER_LENGTH);
    if ( vaddr == NULL )
        return XH_MATCH_ERROR;

    if ( memcmp(vaddr, table->signature, 4) != 0 )
    {
        xh_unmmap(vaddr, XH_ACPI_HEADER_LENGTH);
        return XH_MATCH_MISS;
    }

    if ( (table->ordinal != XH_ACPI_ORDINAL_UNSPECIFIED)&&
         (table->ordinal != *pord) )
    {
        (*pord)++;
        xh_unmmap(vaddr, XH_ACPI_HEADER_LENGTH);
        return XH_MATCH_MISS;
    }

    /* Found it, map the entire table and return it. */
    ti->length = (*(uint32_t*)(vaddr + XH_ACPI_TABLE_LENGTH));
    xh_unmmap(vaddr, XH_ACPI_HEADER_LENGTH);
    vaddr = xh_mmap(paddr, ti->length);
    if ( vaddr == NULL )
        return XH_MATCH_ERROR;
    ti->paddr = paddr;
    ti->vaddr = vaddr;

    return XH_MATCH_FOUND;
}

static int xh_xsdt_find_table(struct xh_acpi_ctx *acctx,
                              struct xh_acpi_spec *table,
                              struct xh_acpi_table_info *ti)
{
    uint64_t *paddr_list;
    uint32_t length, count, i, ordinal = 0;
    int rc = 0;
    enum xh_match_table match;

    length = acctx->source.mmap.xsdt_length - XH_ACPI_HEADER_LENGTH;
    count = length/sizeof(uint64_t);
    paddr_list =
        (uint64_t*)(acctx->source.mmap.xsdt_vaddr + XH_ACPI_HEADER_LENGTH);

    for ( i = 0; i < count; i++, paddr_list++ )
    {
        match = xh_match_table(*paddr_list, table, ti, &ordinal);
        if ( match == XH_MATCH_MISS )
            continue;

        if ( match == XH_MATCH_ERROR )
            rc = -1;

        /* Else it was found */
        break;
    }

    return rc;
}

static int xh_rsdt_find_table(struct xh_acpi_ctx *acctx,
                              struct xh_acpi_spec *table,
                              struct xh_acpi_table_info *ti)
{
    uint32_t *paddr_list;
    uint32_t length, count, i, ordinal = 0;
    int rc = -1;
    enum xh_match_table match;

    length = acctx->source.mmap.rsdt_length - XH_ACPI_HEADER_LENGTH;
    count = length/sizeof(uint32_t);
    paddr_list =
        (uint32_t*)(acctx->source.mmap.rsdt_vaddr + XH_ACPI_HEADER_LENGTH);

    for ( i = 0; i < count; i++, paddr_list++ )
    {
        match = xh_match_table(*paddr_list, table, ti, &ordinal);
        if ( match == XH_MATCH_MISS )
            continue;

        if ( match == XH_MATCH_ERROR )
            rc = -1;

        /* Else it was found */
        break;
    }

    return rc;
}

static int xh_decode_acpi_mmap(struct xh_acpi_ctx *acctx)
{
    struct xh_acpi_table_info ti;
    uint32_t i, copied;
    int rc = 0;
    XH_ERR;

    if ( xh_locate_acpi_mmap(acctx) )
        return -1;

    /* Sanity check: make sure there are tables to locate. */
    if ( !acctx->source.mmap.is_rev1 )
    {
        if ( acctx->source.mmap.xsdt_length <= XH_ACPI_TABLE_LENGTH )
        {
            errno = ENOENT;
            return -1; /* invalid - no tables?? */
        }
    }
    else
    {
        if ( acctx->source.mmap.rsdt_length <= XH_ACPI_TABLE_LENGTH )
        {
            errno = ENOENT;
            return -1; /* invalid - no tables?? */
        }
    }

    for ( i = 0; i < acctx->table_count; i++ )
    {
        memset(&ti, 0, sizeof(struct xh_acpi_table_info));

        /* Try to find each requested table. */
        if ( !acctx->source.mmap.is_rev1 )
            rc = xh_xsdt_find_table(acctx, &acctx->table_list[i], &ti);
        else
            rc = xh_rsdt_find_table(acctx, &acctx->table_list[i], &ti);
        if ( rc )
            break;

        copied = xh_copy_common(&(acctx->common_ctx),
                                ti.vaddr,
                                ti.length);

        XH_PUSHERR();
        xh_unmmap(ti.vaddr, ti.length);
        if ( copied == 0 )
        {
            XH_POPERR();
            rc = -1;
            break;
        }
    }

    return rc;
}

static int xh_decode_acpi_sysfs(struct xh_acpi_ctx *acctx)
{
#define XH_ACPI_DIR_MAX 64
    uint32_t i, table_length, copied;
    int rc = 0;
    struct stat st;
    uint8_t *table_buf;
    char table_file[sizeof(XH_ACPI_SYSFS_PARENT) + XH_ACPI_DIR_MAX + 1];
    char ordinal[XH_ACPI_DIR_MAX + 1];
    XH_ERR;

    for ( i = 0; i < acctx->table_count; i++ )
    {
        strcpy(table_file, XH_ACPI_SYSFS_PARENT);
        strncat(table_file, acctx->table_list[i].signature,
                XH_ACPI_SIGNATURE_SIZE);
        if ( (acctx->table_list[i].ordinal == 0)||
             (acctx->table_list[i].ordinal == XH_ACPI_ORDINAL_UNSPECIFIED) )
        {
            /* When more than one table with a given signature is present, an
             * ordinal value is appeded (1 - n). If only one is present then
             * the tables base signature is used.
             */
            rc = stat(table_file, &st);
            if ( rc )
            {
                strncat(table_file, "1", XH_ACPI_DIR_MAX);
                rc = stat(table_file, &st);
                if ( rc )
                    break;
            }
        }
        else
        {
            /* If an ordinal value is specified other than 0, look for an
             * exact match on the file name.
             */
            snprintf(ordinal, XH_ACPI_DIR_MAX, "%d",
                     (acctx->table_list[i].ordinal + 1));
            strncat(table_file, ordinal, XH_ACPI_DIR_MAX);
            rc = stat(table_file, &st);
            if ( rc )
                break;
        }

        table_buf = xh_read_bin_sysfs(table_file, &table_length);
        if ( table_buf == NULL )
        {
            rc = -1;
            break;
        }

        copied = xh_copy_common(&(acctx->common_ctx),
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

    return rc;
}

static void xh_acpi_context_cleanup(struct xh_acpi_ctx *acctx)
{
    if ( acctx->source.mmap.rsdt_vaddr != NULL )
        xh_unmmap(acctx->source.mmap.rsdt_vaddr,
                  acctx->source.mmap.rsdt_length);
    if ( acctx->source.mmap.xsdt_vaddr != NULL )
        xh_unmmap(acctx->source.mmap.xsdt_vaddr,
                  acctx->source.mmap.xsdt_length);

    if ( acctx->common_ctx.buffer != NULL )
        free(acctx->common_ctx.buffer);
}

int xh_find_acpi_tables(enum xh_decode_mode mode,
                        struct xh_acpi_spec *table_list,
                        uint32_t table_count,
                        uint8_t **out_buffer,
                        uint32_t *out_length)
{
    struct xh_acpi_ctx acctx;
    int rc = 0;
    XH_ERR;

    if ( (table_list == NULL)||(table_count == 0)||
         (out_buffer == NULL)||(out_length == NULL) )
    {
        errno = EINVAL;
        return -1;
    }

    memset(&acctx, 0, sizeof(struct xh_acpi_ctx));

    /* Store a pointer to the table list for processing. */
    acctx.table_list = table_list;
    acctx.table_count = table_count;

    if ( xh_init_common(mode, &(acctx.common_ctx)) )
        goto error_out;

    /* Use the mode specified. If XH_DECODE_BOTH is specified then try
     * to use sysfs first, fall back to mmap if that fails.
     */
    if ( mode == XH_DECODE_BOTH )
    {
        rc = xh_decode_acpi_sysfs(&acctx);
        if ( rc )
            rc = xh_decode_acpi_mmap(&acctx);
    }
    else if ( mode == XH_DECODE_SYSFS )
        rc = xh_decode_acpi_sysfs(&acctx);
    else if ( mode == XH_DECODE_MMAP )
        rc = xh_decode_acpi_mmap(&acctx);

    if ( rc )
        goto error_out;

    /* Final format of the module header */
    xh_format_common(&(acctx.common_ctx), XH_FIRMWARE_ACPI);

    *out_buffer = acctx.common_ctx.buffer;
    *out_length = acctx.common_ctx.total_length;
    acctx.common_ctx.buffer = NULL;

    xh_acpi_context_cleanup(&acctx);
    return 0;

error_out:

    XH_PUSHERR();
    xh_acpi_context_cleanup(&acctx);
    XH_POPERR();

    return rc;
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
