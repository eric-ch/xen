/*
 * xh_internal.h: internal support routines.
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

#ifndef XEN_XH_INTERNAL_H
#define XEN_XH_INTERNAL_H

/* Common definitions */
#define XH_SCAN_ROM_BIOS_BASE 0xF0000
#define XH_SCAN_ROM_BIOS_SIZE 0x10000

/* SMBIOS Definitions */
#define XH_SMBIOS_SM_LENGTH       0x20
#define XH_SMBIOS_DMI_LENGTH      0x0F
#define XH_SMBIOS_HEADER_LENGTH   0x04

#define XH_SMBIOS_EPS_STRING      0x00 /* 4 BYTES "_SM_" anchor string */
#define XH_SMBIOS_EPS_CHECKSUM    0x04 /* BYTE CS sums to zero when added to bytes in EPS */
#define XH_SMBIOS_EPS_LENGTH      0x05 /* BYTE Length of the Entry Point Structure */
#define XH_SMBIOS_MAJOR_VERSION   0x06 /* BYTE */
#define XH_SMBIOS_MINOR_VERSION   0x07 /* BYTE */
#define XH_SMBIOS_MAX_STRUCT_SIZE 0x08 /* WORD Size of the largest SMBIOS structure */
#define XH_SMBIOS_REVISION        0x0A /* BYTE */
#define XH_SMBIOS_FORMATTED_AREA  0x0B /* 5 BYTES, see spec for revision */
#define XH_SMBIOS_IEPS_STRING     0x10 /* 5 BYTES "_DMI_" intermediate anchor string */
#define XH_SMBIOS_IEPS_CHECKSUM   0x15 /* BYTE CS sums to zero when added to bytes in IEPS */
#define XH_SMBIOS_TABLE_LENGTH    0x16 /* WORD Total length of SMBIOS Structure Table */
#define XH_SMBIOS_TABLE_ADDRESS   0x18 /* DWORD The 32-bit physical starting address of the read-only SMBIOS Structures */
#define XH_SMBIOS_STRUCT_COUNT    0x1C /* WORD Total number of structures present in the SMBIOS Structure Table */
#define XH_SMBIOS_BCD_REVISION    0x1E /* BYTE */

#define XH_SMBIOS_STRUCT_TYPE     0x00 /* BYTE Specifies the type of structure */
#define XH_SMBIOS_STRUCT_LENGTH   0x01 /* BYTE Specifies the length of the formatted area of the structure */
#define XH_SMBIOS_STRUCT_HANDLE   0x02 /* WORD Specifies 16-bit number in the range 0 to 0FFFEh */

#define XH_SMBIOS_TYPE_EOT        127

/* ACPI Definitions */
#define XH_ACPI_RSDP_LENGTH            0x24
#define XH_ACPI_RSDP_CS_LENGTH         0x14
#define XH_ACPI_RSDP_XCS_LENGTH        0x24
#define XH_ACPI_HEADER_LENGTH          0x24

#define XH_ACPI_RSDP_SIGNATURE         0x00 /* 8 BYTES ASCII "RSD PTR " anchor string */
#define XH_ACPI_RSDP_CHECKSUM          0x08 /* BYTE ACPI 1.0 CS sums to zero when added to bytes in RSDP */
#define XH_ACPI_RSDP_OEM_ID            0x09 /* 6 BYTES ASCII OEM ID */
#define XH_ACPI_RSDP_REVISION          0x0F /* BYTE 0 for ACPI 1.0 or 2 for ACPI 2.0 */
#define XH_ACPI_RSDP_RSDT_BASE         0x10 /* 4 BYTES 32b physical base address of the RSDT */
#define XH_ACPI_RSDP_RSDP_LENGTH       0x14 /* 4 BYTES length of this table */
#define XH_ACPI_RSDP_XSDT_BASE         0x18 /* 8 BYTES 64b physical base address of the XSDT */
#define XH_ACPI_RSDP_EXT_CHECKSUM      0x20 /* BYTE ACPI 2.0 CS sums to zero when added to bytes in RSDP */
#define XH_ACPI_RSDP_RESERVED          0x21 /* 3 BYTES align table */

#define XH_ACPI_TABLE_SIGNATURE        0x00 /* 4 BYTES signature string */
#define XH_ACPI_TABLE_LENGTH           0x04 /* 4 BYTES length of the table in bytes including header */
#define XH_ACPI_TABLE_REVISION         0x08 /* BYTE minor rev number */
#define XH_ACPI_TABLE_CHECKSUM         0x09 /* BYTE sums to zero when added to bytes in table */
#define XH_ACPI_TABLE_OEM_ID           0x0A /* 6 BYTES ASCII OEM ID */
#define XH_ACPI_TABLE_OEM_TABLE_ID     0x10 /* 8 BYTES ASCII OEM TABLE ID */
#define XH_ACPI_TABLE_OEM_REVISION     0x18 /* 4 BYTES OEM rev number */
#define XH_ACPI_TABLE_CREATOR_ID       0x1C /* 4 BYTES ASCII CREATOR ID */
#define XH_ACPI_TABLE_CREATOR_REVISION 0x20 /* 4 BYTES CREATOR REVISION */

/* Common context pieces */
#define XH_INITIAL_ALLOC       0x1000
#define XH_ORDINAL_UNSPECIFIED 0xFFFF

struct xh_common_ctx {
    enum xh_decode_mode mode;

    uint8_t *buffer;
    uint32_t buffer_length;
    uint32_t total_length;
    uint32_t count;
};

/* Utility macros and routines */
#define XH_ERR       int __err
#define XH_PUSHERR() __err = errno
#define XH_POPERR()  errno = __err

uint8_t* xh_mmap(off_t phys_addr, size_t length);
void xh_unmmap(uint8_t *vaddr, size_t length);
int xh_efi_locate(const char *efi_entry,
                  uint32_t length,
                  size_t *location);
uint8_t *xh_read_bin_sysfs(const char *file,
                           uint32_t *length_out);

int xh_init_common(enum xh_decode_mode mode,
                   struct xh_common_ctx *cctx);
uint32_t xh_copy_common(struct xh_common_ctx *cctx,
                        uint8_t *ptr,
                        uint32_t length);
void xh_format_common(struct xh_common_ctx *cctx,
                      uint32_t type);
void xh_cleanup_common(struct xh_common_ctx *cctx);

#endif /* XEN_XH_INTERNAL_H */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
