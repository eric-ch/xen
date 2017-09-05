/*
 * biospt.c: test/sample application using libhvm.
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <xenhvm.h>

#define XH_SMBIOS_SYSFS_PARENT "/sys/firmware/dmi/entries"

static void hexdump(void *_p, int len)
{
    uint8_t *buf = (uint8_t *)_p;
    int i, j;

    for ( i = 0; i < len; i += 16 )
    {
        printf("%8.8x:", i);
        /*printf ("%p:", &buf[i]);*/
        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printf(" %02x", buf[k]);
            else
                printf("   ");
        }
        printf(" ");

        for ( j = 0; j < 16; ++j )
        {
            int k = i + j;
            if ( k < len )
                printf("%c", ((buf[k] > 32) && (buf[k] < 127)) ? buf[k] : '.');
            else
                printf(" ");
        }

        printf("\n");
    }
}

static uint8_t *xh_read_table_sysfs(const char *table_dir,
                                    uint32_t *length)
{
#define XH_LENGTH_BUF_SIZE 64 /* plenty of room */
    FILE *fs = NULL;
    uint8_t *data = NULL;
    size_t rs;
    unsigned long int raw_length;
    uint32_t str_length;
    char *table_file;
    char length_buf[XH_LENGTH_BUF_SIZE];

    /* First open the length file to find the size of the table to read */
    str_length = strlen(table_dir) + 16;
    table_file = malloc(str_length);
    if ( table_file == NULL )
        return NULL;

    snprintf(table_file, str_length, "%s/length", table_dir);

    fs = fopen(table_file, "rb");
    if ( fs == NULL )
        goto error_out;

    rs = fread(length_buf, 1, XH_LENGTH_BUF_SIZE, fs);
    if ( rs == 0 )
    {
        errno = ENODATA;
        goto error_out;
    }

    fclose(fs);
    fs = NULL;

    length_buf[rs - 1] = '\0';
    raw_length = strtoul(length_buf, NULL, 10);

    if ( raw_length == ULONG_MAX )
        goto error_out;

    if ( raw_length == 0 )
    {
        errno = ENODATA;
        goto error_out;
    }

    /* Have some reasonable size for the SMBIOS table, read it */
    data = malloc(raw_length);
    if ( data == NULL )
        goto error_out;

    snprintf(table_file, str_length, "%s/raw", table_dir);

    fs = fopen(table_file, "rb");
    if ( fs == NULL )
        goto error_out;

    rs = fread(data, 1, raw_length, fs);
    if ( rs != raw_length )
    {
        errno = ENODATA;
        goto error_out;
    }

    fclose(fs);

    *length = raw_length;
    return data;

error_out:
    if ( fs != NULL )
        fclose(fs);

    free(data);

    return NULL;
}

uint8_t *xh_read_file(const char *filename,
                      unsigned long *size)
{
    FILE *fs = NULL;
    uint8_t *data = NULL;
    off_t datalen = 0;
    struct stat st;
    size_t rs;

    fs = fopen(filename, "rb");
    if ( fs == NULL )
    {
        printf("Open file %s failed - errno: %d\n", filename, errno);
        goto out;
    }

    if ( fstat(fileno(fs), &st) )
    {
        printf("Stat file %s failed\n", filename);
        goto out;
    }

    if ( st.st_size > INT_MAX )
    {
        printf("file %s is too large\n", filename);
        errno = EFBIG;
        goto out;
    }

    if ( st.st_size == 0 )
    {
        printf("file %s is empty\n", filename);
        errno = ENODATA;
        goto out;
    }

    datalen = st.st_size;

    data = malloc(datalen);
    if ( data == NULL )
        goto out;

    /* sysfs files do not report their actual size */
    rs = fread(data, 1, datalen, fs);
    if ( rs == 0 )
    {
        printf("No data while reading %s", filename);
        errno = ENODATA;
        goto out;
    }

    fclose(fs);

    if ( size != NULL )
        *size = rs;

    return data;

out:
    if ( fs != NULL )
        fclose(fs);

    free(data);

    return NULL;
}

static void dmifiles(const char *subdir)
{
    DIR *d;
    struct dirent *de;
    char namestr[512];
    uint8_t *buf;
    unsigned long len = 0;
    uint32_t tlen = 0;

    snprintf(namestr, sizeof(namestr), "%s/%s", XH_SMBIOS_SYSFS_PARENT, subdir);

    d = opendir(namestr);
    if ( d == NULL )
    {
        printf("Failed subdir opendir() - errno: %d\n", errno);
        return;
    }

    de = readdir(d);
    while ( de != NULL )
    {
        if ( de->d_name[0] != '.' )
            printf("DMI File: %s\n", de->d_name);
        de = readdir(d);
    }

    strcat(namestr, "/length");
    buf = xh_read_file(namestr, &len);
    if ( buf != NULL )
    {
        printf("Length file size: %lu\n", len);
        buf[len - 1] = '\0';
        printf("Length file data: %s\n", buf);
        free(buf);
    }

    snprintf(namestr, sizeof(namestr), "%s/%s", XH_SMBIOS_SYSFS_PARENT, subdir);
    printf("Reading table from dir: %s\n", namestr);
    buf = xh_read_table_sysfs(namestr, &tlen);
    printf("Read table, length: %x\n", tlen);
    printf("==== START DATA ====\n");
    hexdump(buf, tlen);
    printf("==== END   DATA ====\n");
    free(buf);
    closedir(d);
}

static int xenhvm_read_dmi_files(void)
{
    DIR *d;
    struct dirent *de;

    d = opendir(XH_SMBIOS_SYSFS_PARENT);
    if ( d == NULL )
    {
        printf("opendir() failed - errno: %d\n", errno);
        return -1;
    }

    de = readdir(d);
    while ( de != NULL )
    {
        if ( de->d_name[0] != '.' )
        {
            printf("Directory: %s\n", de->d_name);
            dmifiles(de->d_name);
        }
        de = readdir(d);
    }

    closedir(d);

    return 0;
}

int xenhvm_smbios_fw(int i)
{
    struct xh_smbios_spec tl[5] = {
        {0, XH_SMBIOS_FLAG_FIRST},
        {1, XH_SMBIOS_FLAG_FIRST},
        {3, XH_SMBIOS_FLAG_FIRST},
        {11, XH_SMBIOS_FLAG_FIRST},
        {218, XH_SMBIOS_FLAG_ALL}
    };
    int r = 0;
    uint8_t *b;
    uint32_t l;

    if ( i == 1 )
    {
       printf("Running SMBIOS read from firmware using mmap.\n");
       r = xh_find_smbios_structures(XH_DECODE_MMAP, &tl[0], 5, &b, &l);
    }
    else if ( i == 2 )
    {
       printf("Running SMBIOS read from firmware using sysfs.\n");
       r = xh_find_smbios_structures(XH_DECODE_SYSFS, &tl[0], 5, &b, &l);
    }

    if ( r )
    {
        printf("xh_find_smbios_structures failed, errno: %d\n", errno);
        return -1;
    }

    printf("==== START DATA ====\n");
    hexdump(b, l);
    printf("==== END   DATA ====\n");
    free(b);

    return 0;
}

int xenhvm_acpi_fw(int i)
{
    struct xh_acpi_spec tl[2] = {
        {"SLIC", XH_ACPI_ORDINAL_UNSPECIFIED},
        {"SSDT", 0}
    };
    int r = 0;
    uint8_t *b;
    uint32_t l;

    if ( i == 3 )
    {
       printf("Running ACPI read from firmware using mmap.\n");
       r = xh_find_acpi_tables(XH_DECODE_MMAP, &tl[0], 2, &b, &l);
    }
    else if ( i == 4 )
    {
       printf("Running ACPI read from firmware using sysfs.\n");
       r = xh_find_acpi_tables(XH_DECODE_SYSFS, &tl[0], 2, &b, &l);
    }

    if ( r )
    {
        printf("xh_find_acpi_tables failed, errno: %d\n", errno);
        return -1;
    }

    printf("==== START DATA ====\n");
    hexdump(b, l);
    printf("==== END   DATA ====\n");
    free(b);

    return 0;
}

/* Read a set of SMBIOS structures and one ACPI table
 * and write them to files. These files can be used
 * with the HVM BIOS pass-through feature.
 */
int xenhvm_make_bins(void)
{
    struct xh_smbios_spec tl[8] = {
        {0, XH_SMBIOS_FLAG_FIRST},
        {1, XH_SMBIOS_FLAG_FIRST},
        {3, XH_SMBIOS_FLAG_FIRST},
        {11, XH_SMBIOS_FLAG_FIRST},
        {129, XH_SMBIOS_FLAG_FIRST},
        {130, XH_SMBIOS_FLAG_FIRST},
        {131, XH_SMBIOS_FLAG_FIRST},
        {218, XH_SMBIOS_FLAG_ALL}
    };
    struct xh_acpi_spec al[1] = {
        {"SLIC", XH_ACPI_ORDINAL_UNSPECIFIED}
    };
    FILE *fs;
    int r;
    uint8_t *b;
    uint32_t l, c;
    struct xh_data_item di;

    printf("Make SMBIOS file from FW.\n");
    r = xh_find_smbios_structures(XH_DECODE_SYSFS, &tl[0], 8, &b, &l);
    if ( r )
    {
        printf("Fail(1), errno: %d\n", errno);
        return -1;
    }

    /* The libxenhvm lib formats the fw blocks with 32b length integers
     * between each SMBIOS struct which is exactly what we want to pass
     * to the hvmloader code.
     */
    fs = fopen("./smbios_fw.bin", "wb");
    c = ((struct xh_firmware_block*)b)->count;
    fwrite(b + sizeof(struct xh_firmware_block),
                      l - sizeof(struct xh_firmware_block), 1, fs);
    free(b);

    printf("Make SMBIOS Xen vendor struct.\n");
    r = xh_xen_vendor_smbios_structure("XenVendor", "XenValues", 0x80001031,
                                       0x401, &di.data, &di.length);
    if ( r )
    {
        printf("Fail(2), errno: %d\n", errno);
        return -1;
    }
    fwrite((uint8_t*)(&di.length), 4, 1, fs);
    fwrite(di.data, di.length, 1, fs);
    printf("Wrote SMBIOS structures file: smbios_fw.bin count: %d\n", c + 1);
    fclose(fs);

    printf("Make ACPI SLIC file from FW.\n");
    r = xh_find_acpi_tables(XH_DECODE_SYSFS, &al[0], 1, &b, &l);
    if ( r )
    {
        printf("Fail(3), errno: %d\n", errno);
        return -1;
    }

    /* The libxenhvm lib formats the fw blocks with 32b length integers
     * between each ACPI table. These must be removed because the ACPI
     * tables are just packed together for passing to hvmloader. Since
     * only one table was fetched here, the code is just skipping the
     * one length specifier below.
     */
    fs = fopen("./acpi_slic.bin", "wb");
    fwrite(b + (sizeof(struct xh_firmware_block) + 4), l - (sizeof(struct xh_firmware_block) + 4), 1, fs);
    fclose(fs);
    free(b);
    printf("Writing ACPI SLIC table file: acpi_slic.bin\n");

    return 0;
}

static void usage(void)
{
    printf("Usage:\n");
    printf("$ biospt <n>\n");
    printf(" 1 - Write some SMBIOS tables using MMAP\n");
    printf(" 2 - Write some SMBIOS tables using SYSFS\n");
    printf(" 3 - Write some ACPI tables using MMAP\n");
    printf(" 4 - Write some ACPI using SYSFS\n");
    printf(" 5 - Read and trace DMI files\n");
    printf(" 6 - Write out some test files\n");
}

int main(int argc, char *argv[])
{
    if ( argc != 2 )
    {
        usage();
        return -1;
    }

    if ( argv[1][0] == '1' )
        return xenhvm_smbios_fw(1);
    if ( argv[1][0] == '2' )
        return xenhvm_smbios_fw(2);
    if ( argv[1][0] == '3' )
        return xenhvm_acpi_fw(3);
    if ( argv[1][0] == '4' )
        return xenhvm_acpi_fw(4);
    if ( argv[1][0] == '5' )
        return xenhvm_read_dmi_files();
    if ( argv[1][0] == '6' )
        return xenhvm_make_bins();

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
