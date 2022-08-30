/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK VMAC NetworkManager manipulation.
 *
 * Author:      Quentin Armitage, <quentin@armitage.org.uk>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2022-2022 Alexandre Cassen, <acassen@gmail.com>
 */

#include "config.h"

/* global include */
#include <stdio.h>
#include <glib.h>
#include <NetworkManager.h>
#include <stdbool.h>

/* local include */
#include "vrrp_vmac_nm.h"
#include "logger.h"


#if NM_CHECK_VERSION(1,22,0)
static const char *
nmc_error_get_simple_message(GError *error)
{
	/* Return a clear message instead of the obscure D-Bus policy error */
	if (g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED))
		return "access denied";
	if (g_error_matches(error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN))
		return "NetworkManager is not running";

	return error->message;
}

static void
_device_cb(GObject *object, GAsyncResult *result, gpointer user_data)
{
	GMainLoop *loop = user_data;
	GError *error = NULL;

	if (!nm_client_dbus_set_property_finish(NM_CLIENT(object), result, &error)) {
		g_dbus_error_strip_remote_error(error);
		log_message(LOG_INFO, "Error: failed to set device managed status: %s",
					nmc_error_get_simple_message(error));
		g_error_free(error);
	}

	/* Tell the mainloop we're done and we can quit now */
	g_main_loop_quit(loop);
}
#endif

/* Older versions of NetworkManager (certainly version 1.0.6, but resolved by 1.18)
 * set macvlans, when created, as manager by NetworkManager. This caused problems
 * when the underlying interface went down, since NM would then down the macvlan
 * interface and when the underlying interface recovered, the macvlan interface
 * would remain down, and the VRRP instance would remain in FAULT state.
 * This code, after a macvlan is created, sets the macvlan to be unmanaged by
 * NetworkManager.
 */
void
set_vmac_unmanaged_nm(const char *vmac_name)
{
	NMClient *client;
	NMDevice *device;
	GError *error = NULL;
	GMainLoop *loop;
	static bool logged_nm_version = false;

#if NM_CHECK_VERSION(1,22,0)
	loop = g_main_loop_new(NULL, FALSE);
#endif

	client = nm_client_new(NULL, &error);
	if (!client) {
		g_message("Error: Could not connect to NetworkManager: %s.", error->message);
		g_error_free(error);
		return;
	}

	if (!logged_nm_version) {
		logged_nm_version = true;
		log_message(LOG_INFO, "NetworkManager version: %s", nm_client_get_version (client));
	}

	device = nm_client_get_device_by_iface(client, vmac_name);
	log_message(LOG_INFO, "Setting %s managed off on %s", vmac_name, nm_object_get_path((NMObject *)device));

#if NM_CHECK_VERSION(1,22,0)
	nm_client_dbus_set_property(client,
					nm_object_get_path((NMObject *)device),
					NM_DBUS_INTERFACE_DEVICE,
					"Managed",
					g_variant_new_boolean(false),
					-1,
					NULL,
					_device_cb,
					loop);

	g_main_loop_run(loop);
#else
	nm_device_set_managed(device, 0);
#endif

	g_object_unref(client);
}
