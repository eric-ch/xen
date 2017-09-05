/*
 * xenhvm.h: public header for the libxenhvm lib.
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

#ifndef XEN_LIBHVM_H
#define XEN_LIBHVM_H

/* The mode by which the firmware is to be read. When both is specified,
 * sysfs is attempted first and then memory mapping is tried.
 */
enum xh_decode_mode {
    XH_DECODE_SYSFS = 1,
    XH_DECODE_MMAP,
    XH_DECODE_BOTH
};

struct xh_data_item {
    uint8_t  *data;
    uint32_t  length;
};

#define XH_SMBIOS_FLAG_FIRST 0x01
#define XH_SMBIOS_FLAG_ALL   0x02
#define XH_SMBIOS_FLAG_GE    0x04

/* Specifier for a desired SMBIOS type. There may be multiple instances
 * of a given SMBIOS structure. The flags above allow reading just their
 * first or all of a given type. This specifier structure could be expanded
 * to specify an ordinal if desired.
 */
struct xh_smbios_spec {
    uint8_t type;
    uint8_t flags;
};

#define XH_ACPI_SIGNATURE_SIZE       0x4
#define XH_ACPI_ORDINAL_UNSPECIFIED  0xFFFFFFFF

/* Specified for a desired ACPI table. There may be multiple instances
 * of ACPI tables with the same signature (e.g. SSDTs). The ordinal allows
 * a specific one to be selected. If XH_ACPI_ORDINAL_UNSPECIFIED is set
 * then the fist match will be used. At most 1 table will be returned for
 * each specifier.
 */
struct xh_acpi_spec {
    const char signature[XH_ACPI_SIGNATURE_SIZE];
    uint32_t ordinal;
};

#define XH_FIRMWARE_SMBIOS           0x00000001
#define XH_FIRMWARE_ACPI             0x00000002

/* Returned structure with a set of fw tables/structs. Each
 * is preceded by a 32b length specifier.
 */
struct xh_firmware_block {
    /* Type of firmware entries in block */
    uint32_t     type;
    /* Length of entire block including this header */
    uint32_t     length;
    /* Number of entries that follow */
    uint32_t     count;

    /* Firmware blocks start here */
};

/* Fetch ACPI tables specified by the table_list using
 * the mode requested. The table_count argument indicates
 * how may entries are in table_list.
 */
int xh_find_acpi_tables(enum xh_decode_mode mode,
                        struct xh_acpi_spec *table_list,
                        uint32_t table_count,
                        uint8_t **out_buffer,
                        uint32_t *out_length);

/* Fetch SMBIOS structures specified by the type_list using
 * the mode requested. The type_count argument indicates
 * how may entries are in type_list.
 */
int xh_find_smbios_structures(enum xh_decode_mode mode,
                              struct xh_smbios_spec *type_list,
                              uint32_t type_count,
                              uint8_t **out_buffer,
                              uint32_t *out_length);

/* Form and return a Xen SMBIOS vendor structure. See xen_smbios.h
 * for more information on this structure.
 */
int xh_xen_vendor_smbios_structure(const char *manufacturer,
                                   const char *product,
                                   uint32_t features,
                                   uint32_t quirks,
                                   uint8_t **out_buffer,
                                   uint32_t *out_length);

/* Call to free buffers returned in the above routines. */
void xh_free_buffer(void *buf);

#endif /* XEN_LIBHVM_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
