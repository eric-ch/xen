/*
 * Copyright (C) 2012      Advanced Micro Devices
 * Author Christoph Egger <Christoph.Egger@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include "libxl_osdeps.h" /* must come before any other headers */
#include "libxl_internal.h"

#include <tap-ctl.h>

#include <list.h>   /* include for list_head structure */

static int blktap_find(const char *type, const char *path, tap_list_t *tap)
{
    struct list_head list; /* Note: structure name updated */
    tap_list_t *entry, *next_t;
    int ret = -ENOENT, err;

    /* TAILQ_INIT(&list);--> old function */
    INIT_LIST_HEAD(&list);

    err = tap_ctl_list(&list);
    if (err)
        return err;

    /* TAILQ_EMPTY(&list)--> old function */
    if (list_empty(&list))
        return ret;

    tap_list_for_each_entry_safe(entry, next_t, &list) {

        if (type && (!entry->type || strcmp(entry->type, type)))
            continue;

        if (path && (!entry->path || strcmp(entry->path, path)))
            continue;

        *tap = *entry;
        tap->type = tap->path = NULL;
        ret = 0;
        break;
    }

    tap_ctl_list_free(&list);

    return ret;
}

/**
 * blktap3 doesn't require blkback, so it's always available.
 */
int libxl__blktap_enabled(libxl__gc *gc)
{
    return 1;
}

char *libxl__blktap_devpath(libxl__gc *gc, const char *disk,
		libxl_disk_format format,
		char *keydir)
{
    const char *type = NULL;
    char *params, *devname = NULL;
    tap_list_t tap;
    int err = 0;
    int flags = 0;

    type = libxl__device_disk_string_of_format(format);

    err = blktap_find(type, disk, &tap);
    if (!err) {
        LOG(DEBUG, "found tapdisk\n");
        devname = libxl__sprintf(gc, "/dev/xen/blktap-2/tapdev%d", tap.minor);
        if (devname)
            return devname;
    }

    LOG(DEBUG, "tapdisk not found\n");

	/* TODO Should we worry about return codes other than ENOENT? */

    if (!keydir || !strncmp(keydir, "", 1))
        setenv("TAPDISK3_CRYPTO_KEYDIR", "/config/platform-crypto-keys", 1);
    else
        setenv("TAPDISK3_CRYPTO_KEYDIR", keydir, 1);

    params = GCSPRINTF("%s:%s", type, disk);

    err = tap_ctl_create(params, &devname, flags, -1, 0, 0, NULL, NULL);
    if (!err) {
        LOG(DEBUG, "created tapdisk\n");
        return devname;
    }

    LOG(ERROR, "error creating tapdisk: %s\n", strerror(err));

    return NULL;
}

int libxl__device_destroy_tapdisk(libxl__gc *gc, const char *params)
{
    char *type, *disk;
    int err;
    tap_list_t tap;

    type = libxl__strdup(gc, params);
    disk = strchr(type, ':');
    if (!disk) {
        LOG(ERROR, "Unable to parse params %s", params);
        return ERROR_INVAL;
    }

    *disk++ = '\0';

    err = blktap_find(type, disk, &tap);
    if (err < 0) {
        /* returns -errno */
        LOGEV(ERROR, -err, "Unable to find type %s disk %s", type, disk);
        return ERROR_FAIL;
    }

    err = tap_ctl_destroy(tap.pid, tap.minor, 0, NULL);
    if (err < 0) {
        LOGEV(ERROR, -err, "Failed to destroy tap device id %d minor %d",
              tap.pid, tap.minor);
        return ERROR_FAIL;
    }

    return 0;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
