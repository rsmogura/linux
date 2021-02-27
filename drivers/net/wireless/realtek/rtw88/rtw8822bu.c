// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2021 Rado Smogura
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/usb.h>
#include "rtw8822bu.h"

#include "usb.h"

#define TPLINK_VENDOR_ID	0x2357
#define TPLINK_PRODUCT_ID   0x012d

static const struct usb_device_id rtw_8822bu_id_table[] = {
	{
		USB_DEVICE(TPLINK_VENDOR_ID, TPLINK_PRODUCT_ID),
		.driver_info = (kernel_ulong_t)&rtw8822b_hw_spec
	},
	{}
};
MODULE_DEVICE_TABLE(usb, rtw_8822bu_id_table);

static struct usb_driver rtw_8822bu_driver = {
	.name = "rtw_8822be",
	.id_table = rtw_8822bu_id_table,
	.probe = rtw_usb_probe,
	.disconnect = rtw_usb_disconnect, 
	// .remove = rtw_pci_remove,
	// .driver.pm = &rtw_pm_ops,
	// .shutdown = rtw_pci_shutdown,
};
module_usb_driver(rtw_8822bu_driver);

MODULE_AUTHOR("Rado Smogura");
MODULE_DESCRIPTION("Realtek 802.11ac wireless 8822bu driver");
MODULE_LICENSE("Dual BSD/GPL");

