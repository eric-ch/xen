/*
 * xh_internal.c: internal support routines.
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
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "xenhvm.h"
#include "xh_internal.h"

#define XH_EFI_LINE_SIZE 64

uint8_t* xh_mmap(off_t phys_addr, size_t length)
{
    uint32_t page_offset = phys_addr % sysconf(_SC_PAGESIZE);
    uint8_t *vaddr;
    int fd;
    XH_ERR;

    fd = open("/dev/mem", O_RDONLY);
    if ( fd == -1 )
        return NULL;

    vaddr = (uint8_t*)mmap(0, page_offset + length,
        PROT_READ, MAP_PRIVATE, fd, phys_addr - page_offset);
    XH_PUSHERR();
    close(fd);

    if ( vaddr == MAP_FAILED )
    {
        XH_POPERR();
        return NULL;
    }

    return vaddr + page_offset;
}

void xh_unmmap(uint8_t *vaddr, size_t length)
{
    uint32_t page_offset = (size_t)vaddr % sysconf(_SC_PAGESIZE);

    munmap(vaddr - page_offset, length + page_offset);
}

int xh_efi_locate(const char *efi_entry,
                  uint32_t length,
                  size_t *location)
{
    FILE *systab = NULL;
    char efiline[XH_EFI_LINE_SIZE];
    char *val;
    off_t loc = 0;

    *location = 0;

    /* use EFI tables if present */
    systab = fopen("/sys/firmware/efi/systab", "r");
    if ( systab != NULL )
    {
        while( (fgets(efiline, XH_EFI_LINE_SIZE - 1, systab)) != NULL )
        {
            if ( strncmp(efiline, efi_entry, 6) == 0 )
            {
                /* found EFI entry, get the associated value */
                val = memchr(efiline, '=', strlen(efiline)) + 1;
                loc = strtol(val, NULL, 0);
                break;
            }
        }
        fclose(systab);

        if ( loc != 0 )
        {
            *location = loc;
            return 0;
        }
    }

    return -1;
}

uint8_t *xh_read_bin_sysfs(const char *file,
                           uint32_t *length_out)
{
    uint32_t alloc_size = sysconf(_SC_PAGE_SIZE);
    FILE *fs = NULL;
    size_t rs;
    uint32_t total_length = 0;
    uint8_t *buffer, *tmp;
    XH_ERR;

    /* Allocate an initial buffer of the default size of a sysfs buffer */
    buffer = malloc(alloc_size);
    if ( buffer == NULL )
        return NULL;

    fs = fopen(file, "rb");
    if ( fs == NULL )
        goto error_out;

    for ( ; ; )
    {
        rs = fread((buffer + total_length), 1, alloc_size, fs);

        /* Done reading file? */
        if ( feof(fs) )
        {
            total_length += rs;
            break;
        }

        if ( rs != alloc_size )
        {
            /* Not EOF so an error must have occured */
            goto error_out;
        }

        /* Else a bigger buffer is needed, more to read. */
        total_length += alloc_size;
        tmp = realloc(buffer, total_length + alloc_size);
        if ( tmp == NULL )
            goto error_out;
        buffer = tmp;
    }


    if ( fs != NULL )
        fclose(fs);

    *length_out = total_length;
    return buffer;

error_out:
    XH_PUSHERR();
    if ( fs != NULL )
        fclose(fs);

    free(buffer);
    XH_POPERR();

    return NULL;
}

int xh_init_common(enum xh_decode_mode mode,
                   struct xh_common_ctx *cctx)
{
    cctx->mode = mode;

    /* Create an initial buffer that should be big enough in most cases. */
    cctx->buffer = malloc(XH_INITIAL_ALLOC);
    if ( cctx->buffer == NULL )
        return -1;
    memset(cctx->buffer, 0, XH_INITIAL_ALLOC);

    cctx->buffer_length = XH_INITIAL_ALLOC;
    cctx->total_length = sizeof(struct xh_firmware_block);

    return 0;
}

uint32_t xh_copy_common(struct xh_common_ctx *cctx,
                        uint8_t *ptr,
                        uint32_t length)
{
    uint32_t add, inc;
    uint8_t *tmp;
    uint32_t *header;

    add = sizeof(uint32_t) + length;

    if ( (cctx->total_length + add) >= cctx->buffer_length )
    {
        inc = (add > XH_INITIAL_ALLOC) ? add : XH_INITIAL_ALLOC;
        tmp = realloc(cctx->buffer, cctx->buffer_length + inc);
        if ( tmp == NULL )
            return 0;
        cctx->buffer = tmp;
        cctx->buffer_length += inc;
    }

    header = (uint32_t*)(cctx->buffer + cctx->total_length);
    *header = length;
    header++;
    memcpy((uint8_t*)header, ptr, length);

    cctx->total_length += add;
    cctx->count++;

    return add;
}

void xh_format_common(struct xh_common_ctx *cctx, uint32_t type)
{
    struct xh_firmware_block *xfb;

    /* Format the module header */
    xfb = (struct xh_firmware_block*)cctx->buffer;
    xfb->type = type;
    xfb->length = cctx->total_length;
    xfb->count = cctx->count;
}

void xh_cleanup_common(struct xh_common_ctx *cctx)
{
    if ( cctx->buffer != NULL )
        free(cctx->buffer);
    memset(cctx, 0, sizeof(struct xh_common_ctx));
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
