/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2010, Citrix Systems
 * Copyright (c) 2018-2019, BAE Systems
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef __XEN_PUBLIC_ARGO_H__
#define __XEN_PUBLIC_ARGO_H__

#include "xen.h"

#define XEN_ARGO_DOMID_ANY       DOMID_INVALID

/*
 * The maximum size of an Argo ring is defined to be: 16MB
 *  -- which is 0x1000000 bytes.
 * A byte index into the ring is at most 24 bits.
 */
#define XEN_ARGO_MAX_RING_SIZE  (0x1000000ULL)

/* Fixed-width type for "argo port" number. Nothing to do with evtchns. */
typedef uint32_t xen_argo_port_t;

/* gfn type: 64-bit on all architectures to aid avoiding a compat ABI */
typedef uint64_t xen_argo_gfn_t;

typedef struct xen_argo_addr
{
    xen_argo_port_t aport;
    domid_t domain_id;
    uint16_t pad;
} xen_argo_addr_t;

typedef struct xen_argo_ring
{
    /* Guests should use atomic operations to access rx_ptr */
    uint32_t rx_ptr;
    /* Guests should use atomic operations to access tx_ptr */
    uint32_t tx_ptr;
    /*
     * Header space reserved for later use. Align the start of the ring to a
     * multiple of the message slot size.
     */
    uint8_t reserved[56];
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t ring[];
#elif defined(__GNUC__)
    uint8_t ring[0];
#endif
} xen_argo_ring_t;

typedef struct xen_argo_register_ring
{
    xen_argo_port_t aport;
    domid_t partner_id;
    uint16_t pad;
    uint32_t len;
} xen_argo_register_ring_t;

typedef struct xen_argo_unregister_ring
{
    xen_argo_port_t aport;
    domid_t partner_id;
    uint16_t pad;
} xen_argo_unregister_ring_t;

/* Messages on the ring are padded to a multiple of this size. */
#define XEN_ARGO_MSG_SLOT_SIZE 0x10

struct xen_argo_ring_message_header
{
    uint32_t len;
    struct xen_argo_addr source;
    uint32_t message_type;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    uint8_t data[];
#elif defined(__GNUC__)
    uint8_t data[0];
#endif
};

/*
 * Hypercall operations
 */

/*
 * XEN_ARGO_OP_register_ring
 *
 * Register a ring using the guest-supplied memory pages.
 * Also used to reregister an existing ring (eg. after resume from hibernate).
 *
 * The first argument struct indicates the port number for the ring to register
 * and the partner domain, if any, that is to be allowed to send to the ring.
 * A wildcard (XEN_ARGO_DOMID_ANY) may be supplied instead of a partner domid,
 * and if the hypervisor has wildcard sender rings enabled, this will allow
 * any domain (XSM notwithstanding) to send to the ring.
 *
 * The second argument is an array of guest frame numbers and the third argument
 * indicates the size of the array. This operation only supports 4K-sized pages.
 *
 * arg1: XEN_GUEST_HANDLE(xen_argo_register_ring_t)
 * arg2: XEN_GUEST_HANDLE(xen_argo_gfn_t)
 * arg3: unsigned long npages
 * arg4: unsigned long flags (32-bit value)
 */
#define XEN_ARGO_OP_register_ring     1

/* Register op flags */
/*
 * Fail exist:
 * If set, reject attempts to (re)register an existing established ring.
 * If clear, reregistration occurs if the ring exists, with the new ring
 * taking the place of the old, preserving tx_ptr if it remains valid.
 */
#define XEN_ARGO_REGISTER_FLAG_FAIL_EXIST  0x1

#ifdef __XEN__
/* Mask for all defined flags. */
#define XEN_ARGO_REGISTER_FLAG_MASK XEN_ARGO_REGISTER_FLAG_FAIL_EXIST
#endif

/*
 * XEN_ARGO_OP_unregister_ring
 *
 * Unregister a previously-registered ring, ending communication.
 *
 * arg1: XEN_GUEST_HANDLE(xen_argo_unregister_ring_t)
 * arg2: NULL
 * arg3: 0 (ZERO)
 * arg4: 0 (ZERO)
 */
#define XEN_ARGO_OP_unregister_ring     2

#endif
