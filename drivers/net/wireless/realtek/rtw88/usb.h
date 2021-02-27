// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2021 Rado Smogura
 */

#ifndef	__RTW_USB_H__
#define __RTW_USB_H__

#include <linux/usb.h>

int rtw_usb_probe(struct usb_interface *intf, const struct usb_device_id *id);
void rtw_usb_disconnect(struct usb_interface *intf);

#endif