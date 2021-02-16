// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2021 Rado Smogura
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/usb.h>
#include "main.h"
#include "tx.h"
#include "debug.h"
#include "rtw8822bu.h"

#define TPLINK_VENDOR_ID	0x2357
#define TPLINK_PRODUCT_ID   0x012d

#define RTLW88_CTRL_BUFF_SIZE (sizeof(u32))

#define RTW88_USB_READ_ADDR_REQ 0x05

int* d;
int d2;



static const struct usb_device_id rtw_8822bu_id_table[] = {
	{
		USB_DEVICE(TPLINK_VENDOR_ID, TPLINK_PRODUCT_ID),
		.driver_info = (kernel_ulong_t)&rtw8822b_hw_spec
	},
	{}
};
MODULE_DEVICE_TABLE(usb, rtw_8822bu_id_table);

void readVersion(struct usb_interface *intf, const struct usb_device_id *id) {
	int i;
	struct usb_device* udev = interface_to_usbdev(intf);
	unsigned int pipe = usb_rcvctrlpipe(udev, 0);
	d = (int*) kmalloc(4, GFP_KERNEL);

	for (i=0 ; i < 5; i++) {
	int read = usb_control_msg(udev, pipe, 0x05, 0xC0, 0x00F0, 0, d, 4, 50);
	printk(KERN_INFO "Read    %d, 0x%x", read, *d);
	}
	kfree(d);
}


void rtw_usb_complete(struct urb * urb) {
	// rename to tx complete and deaalocate resources
	printk(KERN_INFO "Finished urb %d\n", urb->status);
}

struct rtw_usb {
	spinlock_t ctrl_lock;
	volatile void* ctrl_read_buf; //TODO rename to ctrl_buffer as it's for R & W
};

int rtw_usb_tx_write(struct rtw_dev *rtwdev,
		struct rtw_tx_pkt_info *pkt_info,
		struct sk_buff *skb) {
	printk(KERN_ERR "tx_write\n");
	return -1;
}

void rtw_usb_tx_kick_off(struct rtw_dev *rtwdev) {
	printk(KERN_ERR "kick_off\n");
}

int rtw_usb_setup(struct rtw_dev *rtwdev) {
	printk(KERN_ERR "setup\n");
	return 0;
}

int rtw_usb_start(struct rtw_dev *rtwdev) {
	printk(KERN_ERR "start\n");
	return -1;
}

void rtw_usb_stop(struct rtw_dev *rtwdev) {
	printk(KERN_ERR "stop\n");
}

void rtw_usb_deep_ps(struct rtw_dev *rtwdev, bool enter) {
	printk(KERN_ERR "deep_ps\n");
}

void rtw_usb_link_ps(struct rtw_dev *rtwdev, bool enter) {
	printk(KERN_ERR "link_ps\n");
}

void rtw_usb_interface_cfg(struct rtw_dev *rtwdev) {
	printk(KERN_ERR "interface_cfg\n");
}

int rtw_usb_tx_write_to_queue(struct rtw_dev *rtwdev,
		struct rtw_tx_pkt_info *pkt_info,
		struct sk_buff *skb,
		u8 queue) {
	struct rtw_usb *rtwubs = (struct rtw_usb *)rtwdev->priv;
	struct rtw_chip_info *chip = rtwdev->chip;
	struct usb_device* usb_dev = to_usb_device(rtwdev->dev);
	struct urb* urb;
	// const u32 tx_pkt_desc_sz = chip->tx_pkt_desc_sz;
	// const u32 tx_buf_desc_sz = chip->tx_buf_desc_sz;
	
	int r;

	int i;
	u16 *chksumdata;
	u16 chksum = 0;

	u32 size;
	u32 psb_len;
	u8 *pkt_desc;

	printk(KERN_INFO "Skb len: %d, header add %hhd\n", skb->len, chip->tx_pkt_desc_sz);

	pkt_desc = skb_push(skb, chip->tx_pkt_desc_sz);
	memset(pkt_desc, 0, chip->tx_pkt_desc_sz);

	pkt_info->qsel = 16;

	//update_txdesc from RTL
	rtw_tx_fill_tx_desc(pkt_info, skb); 

	//We don't set cheksum here - should we?

	chksumdata = (u16 *) skb->data;
	for (i = 0; i < 8; i++)
		chksum ^= (*(chksumdata + 2 * i) ^ *(chksumdata + (2 * i + 1)));

	le32p_replace_bits((__le32 *)(skb->data) + 0x07, chksum, GENMASK(15, 0));

	// print_hex_dump(KERN_INFO, "rtw_usb: skb", DUMP_PREFIX_ADDRESS, 16, 1, skb->data, min(skb->len, chip->tx_pkt_desc_sz + sizeof(struct ieee80211_hdr)), false);

	// When packet is miscconfigured no completion, should we cancle URB than? Do test with sending worng packet before good.
	urb = usb_alloc_urb(0, GFP_ATOMIC);
	usb_fill_bulk_urb(urb, usb_dev, usb_sndbulkpipe(usb_dev, 0x05), skb->data, skb->len, rtw_usb_complete, NULL);
	r = usb_submit_urb(urb, GFP_NOIO);
	if (r != 0) {
		printk(KERN_ERR "Submit urb error %d\n", r);
		return -1;
	}
	// printk(KERN_INFO "Header %hhd\n", chip->tx_pkt_desc_sz);
	return 0;
}

int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf, u32 size) {
		struct sk_buff *skb;
	struct rtw_tx_pkt_info pkt_info = {0};
	u8 reg_bcn_work;
	int ret;

	skb = rtw_tx_write_data_rsvd_page_get(rtwdev, &pkt_info, buf, size);
	if (!skb)
		return -ENOMEM;
	
	ret = rtw_usb_tx_write_to_queue(rtwdev, &pkt_info, skb, RTW_TX_QUEUE_BCN);
	if (ret < 0) {
		rtw_err(rtwdev, "Error TX packet %d\n", ret);
	}

	// printk(KERN_ERR "rsvd_page\n");
	return 0;
}

int rtw_usb_write_data_h2c(struct rtw_dev *rtwdev, u8 *buf, u32 size) {
	printk(KERN_ERR "write_data_h2c\n");
	return -1;
}

enum rtw_usb_rw_request_t {
	rtw_usb_reg_req_read,
	rtw_usb_reg_req_write,
};

/**
 * Common methods for read and write registry.
 * @param addr - has to be u16
 * @param sz - bytes to read or write; can be 1, 2, 4
 */
inline static int rtw_usb_rw_request(struct rtw_dev *rtwdev, enum rtw_usb_rw_request_t req_type, u32 addr, void* in_out, int sz) {
	struct rtw_usb *rtwusb = (struct rtw_usb *) rtwdev->priv;
	struct usb_device *usbdev;
	unsigned int pipe;

	u8 usb_req_type; // Vendor specific request type (read or write)
	int io_stat, io_stat2; // Status / number of bytes read / wrote
	int repeat_count = 0;

	u8  *u8_io  = (u8 *)  in_out; // Pointer cast
	u16 *u16_io = (u16 *) in_out; // Pointer cast
	u32 *u32_io = (u32 *) in_out; // Pointer cast

	usbdev = usb_get_dev(to_usb_device(rtwdev->dev));
	pipe = usb_rcvctrlpipe(usbdev, 0);

	usb_req_type = (req_type == rtw_usb_reg_req_read ? 0xC0 : 0x40);

	if (unlikely(sz != 1 && sz != 2 && sz != 4)) {
		rtw_err(rtwdev, "Unexpected size of read data %d\n", sz);
		return -1;
	}

	// Lock as we use shared I/O ctrl buffer
	spin_lock(&rtwusb->ctrl_lock);
	*(u32 *) rtwusb->ctrl_read_buf = 0;

	if (req_type == rtw_usb_reg_req_write) {
		switch(sz) {
			case 1:
				*(u8 *) rtwusb->ctrl_read_buf = *u8_io; break;
			case 2:
				*(u16 *) rtwusb->ctrl_read_buf = *u16_io; break;
			case 4:
				*(u32 *) rtwusb->ctrl_read_buf = *u32_io; break;
		}
	}

	// TODO Elaborate on repeat more
	// TODO When this device was conencted to quemu (USB 2.0) it always fiald to set-up, need to check if this is case for physicall device, and bail out fast during probe

	// for (repeat_count = 0; repeat_count < 5; repeat_count++) {
	io_stat = usb_control_msg(usbdev, pipe, 5, usb_req_type, (u16) addr, 0, rtwusb->ctrl_read_buf, sz, 1000);
	// 	if (io_stat == -EPIPE) {
	// 		// Change to rtw_dbg
	// 		rtw_dbg(rtwdev, "Repeating %s due to %d\n", req_type == rtw_usb_reg_req_read ? "read" : "write", io_stat);
	// 		continue;
	// 	} else {
	// 		break;
	// 	}
	// }

	if (req_type == rtw_usb_reg_req_read) {
		switch(sz) {
			case 1:
				*u8_io = *(u8 *) rtwusb->ctrl_read_buf; break;
			case 2:
				*u16_io = *(u16 *) rtwusb->ctrl_read_buf; break;
			case 4:
				*u32_io = *(u32 *) rtwusb->ctrl_read_buf; break;
		}
	}

	if (addr <= 0xFF || (0x1000 <= addr && addr <= 0x10ff)) {
		// printk(KERN_INFO "Special update 0x%x\n", addr);
		// rtw_usb_write8(rtwdev, 0x4e0, u8_io);
		io_stat2 = usb_control_msg(usbdev, pipe, 5, 0x40, (u16) 0x4e0, 0, rtwusb->ctrl_read_buf, 1, 1000);
		if (io_stat2 < 1) {
			rtw_err(rtwdev, "Error submitting write %d\n", io_stat2);
		}
	}

	// Clear - sanity
	*(u32 *) rtwusb->ctrl_read_buf = 0;
	spin_unlock(&rtwusb->ctrl_lock);
	usb_put_dev(usbdev);

	if (io_stat < sz) {
		rtw_err(rtwdev, "%s error: %d (in 0x%x, buff 0x%x), \n", req_type == rtw_usb_reg_req_read ? "Read" : "Write", io_stat, *u32_io, * (u32 *) rtwusb->ctrl_read_buf);
	}

	// printk(KERN_INFO "%s status: %d (in 0x%x, buff 0x%x), \n", req_type == rtw_usb_reg_req_read ? "Read" : "Write", io_stat, *u32_io, * (u32 *) rtwusb->ctrl_read_buf);

	return io_stat;
}

static u8 rtw_usb_read8(struct rtw_dev *rtwdev, u32 addr)
{
	u8 result;
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_read, addr, &result, sizeof(result));
	return result;
}

static u16 rtw_usb_read16(struct rtw_dev *rtwdev, u32 addr)
{
	u16 result;
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_read, addr, &result, sizeof(result));
	return le16_to_cpu(result);
}

static u32 rtw_usb_read32(struct rtw_dev *rtwdev, u32 addr)
{
	u32 result;
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_read, addr, &result, sizeof(result));
	return le32_to_cpu(result);
}

static void rtw_usb_write8(struct rtw_dev *rtwdev, u32 addr, u8 val) {
	u8 out = val;
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_write, addr, &out, sizeof(out));
}

static void rtw_usb_write16(struct rtw_dev *rtwdev, u32 addr, u16 val) {
	u16 out = cpu_to_le16(val);
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_write, addr, &out, sizeof(out));
}

static void rtw_usb_write32(struct rtw_dev *rtwdev, u32 addr, u32 val) {
	u32 out = cpu_to_le32(val);
	rtw_usb_rw_request(rtwdev, rtw_usb_reg_req_write, addr, &out, sizeof(out));
}


static struct rtw_hci_ops rtw_usb_ops = {
	.tx_write = rtw_usb_tx_write,
	.tx_kick_off = rtw_usb_tx_kick_off,
	.setup = rtw_usb_setup,
	.start = rtw_usb_start,
	.stop = rtw_usb_stop,
	.deep_ps = rtw_usb_deep_ps,
	.link_ps = rtw_usb_link_ps,
	.interface_cfg = rtw_usb_interface_cfg,

	.read8 = rtw_usb_read8,
	.read16 = rtw_usb_read16,
	.read32 = rtw_usb_read32,
	.write8 = rtw_usb_write8,
	.write16 = rtw_usb_write16,
	.write32 = rtw_usb_write32,
	.write_data_rsvd_page = rtw_usb_write_data_rsvd_page,
	.write_data_h2c = rtw_usb_write_data_h2c,
};

static int rtw_usb_init(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	int ret = 0;

	// rtwpci->irq_mask[0] = IMR_HIGHDOK |
	// 		      IMR_MGNTDOK |
	// 		      IMR_BKDOK |
	// 		      IMR_BEDOK |
	// 		      IMR_VIDOK |
	// 		      IMR_VODOK |
	// 		      IMR_ROK |
	// 		      IMR_BCNDMAINT_E |
	// 		      0;
	// rtwpci->irq_mask[1] = IMR_TXFOVW |
	// 		      0;
	// rtwpci->irq_mask[3] = IMR_H2CDOK |
	// 		      0;
	
	spin_lock_init(&rtwusb->ctrl_lock);
	// Init read write buffer; avoid allocations later
	rtwusb->ctrl_read_buf = kmalloc(RTLW88_CTRL_BUFF_SIZE, GFP_KERNEL);
	if (rtwusb->ctrl_read_buf == NULL) {
		return -ENOMEM;
	}

	return ret;
}

static int rtw_usb_deinit(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	
	if (rtwusb->ctrl_read_buf) {
		kfree(rtwusb->ctrl_read_buf);
	}
}

static int rtw_usb_setup_resource(struct rtw_dev *rtwdev, struct usb_interface *usbintf)
{
	struct rtw_usb *rtwusb;
	int ret;

	rtwusb = (struct rtw_usb *)rtwdev->priv;
	// rtwpci->pdev = pdev;

	// /* after this driver can access to hw registers */
	// ret = rtw_pci_io_mapping(rtwdev, pdev);
	// if (ret) {
	// 	rtw_err(rtwdev, "failed to request pci io region\n");
	// 	goto err_out;
	// }

	ret = rtw_usb_init(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to allocate usb resources\n");
		goto err_out;
	}

	return 0;

err_out:
	return ret;
}

static void rtw_usb_destroy(struct rtw_dev *rtwdev)
{
	rtw_usb_deinit(rtwdev);
}

static void rtw_usb_claim(struct rtw_dev *rtwdev, struct usb_interface *usbintf)
{
	struct usb_device *usbdev = interface_to_usbdev(usbintf);

	// Set pointer to ieee80211 which has reference to rtw_data
	usb_set_intfdata(usbintf, rtwdev->hw);
	
	SET_IEEE80211_DEV(rtwdev->hw, &usbdev->dev);
}

static void rtw_usb_rx_complete(struct urb *urb) {
	printk(KERN_INFO "rtw recv %d bytes, status %d\n", urb->actual_length, urb->status);
	kfree(urb->transfer_buffer);
	usb_free_urb(urb);
}

static int rtw_usb_rx_thread(void *data) {
	struct rtw_dev *rtwdev = (struct rtw_dev *) data;
	struct rtw_usb *rtwusb = (struct rtw_usb *) rtwdev->priv;

	struct usb_device *usbdev = to_usb_device(rtwdev->dev);

	struct urb* urb;
	unsigned int pipe;
	void *buff; // Buffers from pool, mapped to DMA(?)
	int res = 0;	

	pipe = usb_rcvintpipe(usbdev, 0x87); //TODO magic

	// We are in separte thread, this thread can run during USB disconnect
	// usb_get_dev(usbdev);
	while (1) {
		printk(KERN_INFO "recv iteration\n");
		urb = usb_alloc_urb(0, GFP_ATOMIC);
		buff = kmalloc(64 * 1024, GFP_ATOMIC);
		usb_fill_bulk_urb(urb, usbdev, pipe, buff, 64*1024, rtw_usb_rx_complete, rtwdev);

		res = usb_submit_urb(urb, GFP_ATOMIC);

		if (res < 0) {
			// We should analyze errors and repeat or bailout
			rtw_err(rtwdev, "Error submitting RX: %d\n", res);
			break;
		}

		msleep(100);
	}
	printk(KERN_INFO "Exit rx\n");
	// usb_put_dev(usbdev);

	return 0;
}

int rtw_usb_probe(struct usb_interface *usbintf,
		  const struct usb_device_id *id)
{
	// see rtw_usb_primary_adapter_init
	struct ieee80211_hw *hw;
	struct rtw_dev *rtwdev;
	// struct usb_device *usbdev = usb_get_dev(interface_to_usbdev(usbintf));
	struct usb_device *usbdev = interface_to_usbdev(usbintf);
	int drv_data_size;
	int ret;
	int i;

	drv_data_size = sizeof(struct rtw_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw_ops);
	if (!hw) {
		dev_err(&usbdev->dev, "failed to allocate hw\n");
		return -ENOMEM;
	}

	for (i = 0; i < usbintf->num_altsetting; i++) {
		printk(KERN_INFO, "-- Alt setting %d\n", i);
		struct usb_host_interface *host = usbintf->altsetting + i;
		
		printk(KERN_INFO "Num endpoints %hhd\n", host->desc.bNumEndpoints);

	}
	rtwdev = hw->priv;
	rtwdev->hw = hw;
	rtwdev->dev = &usbdev->dev;
	rtwdev->chip = (struct rtw_chip_info *)id->driver_info;
	rtwdev->hci.ops = &rtw_usb_ops;
	rtwdev->hci.type = RTW_HCI_TYPE_USB;

	ret = rtw_core_init(rtwdev);
	if (ret) {
		dev_err(&usbdev->dev, "rtw8822bu: Can't initialize core - %d\n", ret);
		goto err_release_hw;
	}

	rtw_dbg(rtwdev, RTW_DBG_USB,
		"rtw88 usb probe: vendor=0x%404X product=0x%4.04X\n",
		usbdev->descriptor.idVendor, usbdev->descriptor.idProduct);

	rtw_usb_claim(rtwdev, usbintf);

	ret = rtw_usb_setup_resource(rtwdev, usbintf);
	if (ret) {
		rtw_err(rtwdev, "failed to setup pci resources\n");
		goto err_usb_declaim;
	}

	ret = rtw_chip_info_setup(rtwdev);
	if (ret) {
		rtw_err(rtwdev, "failed to setup chip information\n");
		goto err_destroy_usb;
	}

	// Add switch mode - usb_reprobe_switch_usb_mode - can it be done here, or should be somewehre in chip infor setup
	// rtw_pci_phy_cfg(rtwdev);

	ret = rtw_register_hw(rtwdev, hw);
	if (ret) {
		rtw_err(rtwdev, "failed to register hw\n");
		goto err_destroy_usb;
	}

	// kthread_run(rtw_usb_rx_thread, rtwdev, "rtw88_usb_rx_thread"); 
	// if (ret < 0) {
	// 	rtw_err(rtwdev, "failed to start thread %d\n", ret);
	// }

	// ret = rtw_pci_request_irq(rtwdev, pdev);
	// if (ret) {
	// 	ieee80211_unregister_hw(hw);
	// 	goto err_destroy_pci;
	// }

	return 0;

err_destroy_usb:
	// rtw_usb_destroy(rtwdev, pdev);
	rtw_usb_destroy(rtwdev);

err_usb_declaim:
// 	rtw_pci_declaim(rtwdev, pdev); //TODO

err_deinit_core:
	rtw_core_deinit(rtwdev);

err_release_hw:
	ieee80211_free_hw(hw);

	// usb_put_dev(usbdev);	

	return ret;
}
// EXPORT_SYMBOL(rtw_pci_probe);

int probe(struct usb_interface *intf, const struct usb_device_id *id) {
	printk(KERN_INFO "Attaching %d\n", id->idVendor);
	readVersion(intf, id);
	return rtw_usb_probe(intf, id);
}

void disconnect(struct usb_interface *intf) {
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw_dev *rtwdev;

	printk(KERN_INFO "Disconecting\n");
	if (!hw) {
		printk(KERN_INFO "Hw not registered\n");
		return;
	}

	rtwdev = hw->priv;
	rtw_unregister_hw(rtwdev, hw);
	// free rtw dev rtw usb dev, ieehw
	// usb_put_dev(interface_to_usbdev(intf));
}

static struct usb_driver rtw_8822bu_driver = {
	.name = "rtw_8822be",
	.id_table = rtw_8822bu_id_table,
	.probe = probe,
	.disconnect = disconnect, 
	// .remove = rtw_pci_remove,
	// .driver.pm = &rtw_pm_ops,
	// .shutdown = rtw_pci_shutdown,
};
module_usb_driver(rtw_8822bu_driver);

MODULE_AUTHOR("Rado Smogura");
MODULE_DESCRIPTION("Realtek 802.11ac wireless 8822bu driver");
MODULE_LICENSE("Dual BSD/GPL");
