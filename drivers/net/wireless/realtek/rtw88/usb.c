// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright(c) 2021 Rado Smogura
 */

#include <linux/slab.h>

#include "main.h"
#include "usb.h"
#include "reg.h"
#include "rx.h" 
#include "fw.h" // may not be needed when common rx code moved out
#include "tx.h"
#include "ps.h"
#include "debug.h"


#define RTLW88_CTRL_BUFF_SIZE (sizeof(u32))

#define RTW88_USB_READ_ADDR_REQ 0x05

struct rtw_usb_tx_info {
	struct list_head tx_ack_queue;

	struct rtw_dev *rtwdev;
	struct rtw_tx_pkt_info *pkt_info;
	u8 queue;
	
	struct sk_buff *skb;

	struct urb* urb;

	bool ieee80211_packet;

	u8 sn;
};

static int rtw_usb_rx_thread(void *data);
static int rtw_usb_tx_schedule(struct rtw_dev *rtwdev,
		struct rtw_tx_pkt_info *pkt_info,
		struct rtw_usb_tx_info *tx_info,
		u8 queue);
static struct urb *rtw_usb_tx_submit(struct rtw_usb_tx_info *tx_info);

struct rtw_usb {
	// Used during init, to prevent faults during disconnet, when device was not fully initialized
	struct semaphore init_lock;

	spinlock_t ctrl_lock;
	volatile void* ctrl_read_buf; //TODO rename to ctrl_buffer as it's for R & W
	atomic_t rx_urbs_in_fly;

	volatile bool stop_tx;
	volatile bool stop_rx;
};

void rtw_test_destructor(struct sk_buff *skb) {
	BUG();
}

// TODO Can it be processed here (USB complete), or better to move it to tasklet or thread?
void rtw_usb_process_tx_urb(struct urb * urb) {
	// struct urb * urb = (struct urb *) data;
	struct usb_device *usbdev = urb->dev;

	struct rtw_usb_tx_info *tx_info = (struct rtw_usb_tx_info *) urb->context;
	struct rtw_dev *rtwdev = tx_info->rtwdev;
	// struct rtw_usb *rtwusb = 
	struct ieee80211_hw *hw = rtwdev->hw;
	struct sk_buff *skb = tx_info->skb;
	
	struct ieee80211_tx_info *info;

	if (urb->status < 0) {
		printk(KERN_ERR "Error tx %d\n", urb->status);
	}

	if (tx_info->ieee80211_packet) {

		// Shift hardware header
		skb_pull(skb, rtwdev->chip->tx_pkt_desc_sz);
		info = IEEE80211_SKB_CB(skb);

		if (!urb->status) {
			// PCI copy-paste )move to common
			if (info->flags & IEEE80211_TX_CTL_REQ_TX_STATUS) {
				printk(KERN_INFO "  ctl status    ctl\n");
				rtw_tx_report_enqueue(rtwdev, skb, tx_info->sn);
				goto clear;
			}
			if (info->flags & IEEE80211_TX_CTL_NO_ACK)
				info->flags |= IEEE80211_TX_STAT_NOACK_TRANSMITTED;
			else
				info->flags |= IEEE80211_TX_STAT_ACK;

			// END Oof copy-paste
		}
		// Always update status (in case of usb transfers errors packet has to be put back, to process it as errornous and prevent
		// memory leak
		ieee80211_tx_info_clear_status(info);
		ieee80211_tx_status_irqsafe(hw, skb);

	} else {
		// printk(KERN_INFO "Free skb from sys mgmt\n");
		dev_kfree_skb_irq(skb);
	}

clear:
	// TODO Can be free in this handler, are we in IRQ
	usb_free_urb(urb);
	kfree(tx_info);
}

// Should this be moved to rtw_core? copy-paste from pci
static u8 ac_to_hwq[] = {
	[IEEE80211_AC_VO] = RTW_TX_QUEUE_VO,
	[IEEE80211_AC_VI] = RTW_TX_QUEUE_VI,
	[IEEE80211_AC_BE] = RTW_TX_QUEUE_BE,
	[IEEE80211_AC_BK] = RTW_TX_QUEUE_BK,
};

static u8 rtw_usb_hw_queue_mapping(struct sk_buff *skb)
{
	struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)skb->data;
	__le16 fc = hdr->frame_control;
	u8 q_mapping = skb_get_queue_mapping(skb);
	u8 queue;

	if (unlikely(ieee80211_is_beacon(fc)))
		queue = RTW_TX_QUEUE_BCN;
	else if (unlikely(ieee80211_is_mgmt(fc) || ieee80211_is_ctl(fc)))
		queue = RTW_TX_QUEUE_MGMT;
	else if (WARN_ON_ONCE(q_mapping >= ARRAY_SIZE(ac_to_hwq)))
		queue = ac_to_hwq[IEEE80211_AC_BE];
	else
		queue = ac_to_hwq[q_mapping];


	// printk(KERN_INFO "Queue from skb %hhd, final %hhd\n", q_mapping, queue);
	return queue;
}

static u8 rtw_usb_get_tx_qsel(struct sk_buff *skb, u8 queue)
{
	switch (queue) {
	case RTW_TX_QUEUE_BCN:
		return TX_DESC_QSEL_BEACON;
	case RTW_TX_QUEUE_H2C:
		return TX_DESC_QSEL_H2C;
	case RTW_TX_QUEUE_MGMT:
		return TX_DESC_QSEL_MGMT;
	case RTW_TX_QUEUE_HI0:
		return TX_DESC_QSEL_HIGH;
	default:
		return skb->priority;
	}
};

// END of copy-paste-from-pci

int rtw_usb_tx_write(struct rtw_dev *rtwdev,
		struct rtw_tx_pkt_info *pkt_info,
		struct sk_buff *skb) {
	
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	struct rtw_usb_tx_info* tx_info;

	u8 queue = rtw_usb_hw_queue_mapping(skb);
	int ret;

	tx_info = kmalloc(sizeof(struct rtw_usb_tx_info), GFP_ATOMIC);
	if (!tx_info) {
		return -ENOMEM;
	}

	tx_info->skb = skb;
	tx_info->ieee80211_packet = true;

	ret = rtw_usb_tx_schedule(rtwdev, pkt_info, tx_info, queue);
	if (ret)
		return ret;
	// PCI checks here if rings are full and stops ieee80211 queue, should we do something simillar i.e. too many panding packets?
	return 0;
}

void rtw_usb_tx_kick_off(struct rtw_dev *rtwdev) {
	// TODO Handle it properly (take better look at it)
	// No TX thread nothgin to do?
	// printk(KERN_ERR "kick_off\n");
}

int rtw_usb_setup(struct rtw_dev *rtwdev) {

	// TODO Handle it properly
	// printk(KERN_ERR "setup\n");
	return 0;
}

int rtw_usb_start(struct rtw_dev *rtwdev) {

	// TODO Handle it properly
	printk(KERN_ERR "Here we should start rcv threads & other stuff\n");
	// TX can't be started here
	return 0;
}

void rtw_usb_stop(struct rtw_dev *rtwdev) {

	// TODO Handle it properly
	printk(KERN_ERR "stop\n");

	// WARN_ON(1);
}

void rtw_usb_deep_ps(struct rtw_dev *rtwdev, bool enter) {
	// TODO Handle it properly
	// PWR control causes tx issues... maybe it lack of link_ps, or should we wait for tx to finish
	// if (enter) {
	// 	set_bit(RTW_FLAG_LEISURE_PS_DEEP, rtwdev->flags);
	// 	rtw_power_mode_change(rtwdev, true);
	// } else {
	// 	if (test_and_clear_bit(RTW_FLAG_LEISURE_PS_DEEP, rtwdev->flags))
	// 		rtw_power_mode_change(rtwdev, false);
	// }
	// Should be stopped completly, rx thread to suspend
	// WHen suspended on barrier, disconnect should unsuspend it, to prevent deadlock
	// Check how often jumps into deep_ps (printk)
	// Shoould USB power routines be handled here, too?

	printk(KERN_ERR "deep_ps %d\n", enter);
	// WARN_ON(1);
}

void rtw_usb_link_ps(struct rtw_dev *rtwdev, bool enter) {

	// TODO Handle it properly
	// Should still be able to recv? Where it was
	printk(KERN_ERR "link_ps %d\n", enter);
}

void rtw_usb_interface_cfg(struct rtw_dev *rtwdev) {
	// printk(KERN_ERR "interface_cfg\n");
	// WARN_ON(1);
}

//rtw_usb_rx_thread

static struct urb *rtw_usb_tx_submit(struct rtw_usb_tx_info *tx_info) {
	struct usb_device* usb_dev = to_usb_device(tx_info->rtwdev->dev);
	struct sk_buff *skb = tx_info->skb;
	usb_complete_t urb_handler = rtw_usb_process_tx_urb;
	struct urb* urb;
	int r;

	// printk(KERN_INFO "Submit URB to bus\n");
	urb = usb_alloc_urb(0, GFP_ATOMIC);

	// Here we should chose an endpoint, but we are fine wiih 0x05
	// Maybe a reason for 'timed out to flush queue 3', but for now it works...
	usb_fill_bulk_urb(urb, usb_dev, usb_sndbulkpipe(usb_dev, 0x05), skb->data, skb->len, urb_handler, tx_info);
	r = usb_submit_urb(urb, GFP_NOIO);
	if (r != 0) {
		printk(KERN_ERR "Submit urb error %d\n", r);
		return NULL;
	}

	return urb;
}

static int rtw_usb_tx_schedule(struct rtw_dev *rtwdev,
		struct rtw_tx_pkt_info *pkt_info,
		struct rtw_usb_tx_info *tx_info,
		u8 queue) {
	struct rtw_usb *rtwubs = (struct rtw_usb *)rtwdev->priv;
	struct rtw_chip_info *chip = rtwdev->chip;
	struct sk_buff *skb = tx_info->skb;

	const u32 tx_pkt_desc_sz = chip->tx_pkt_desc_sz;
	// const u32 tx_buf_desc_sz = chip->tx_buf_desc_sz; //TODO Not needed for USB?
	
	int i;
	u16 *chksumdata;
	u16 chksum = 0;

	u32 size;
	u32 psb_len;
	u8 *pkt_desc;

	pkt_desc = skb_push(skb, tx_pkt_desc_sz);
	memset(pkt_desc, 0, tx_pkt_desc_sz);

	// Finding issu with this took a lot of time
	pkt_info->qsel = rtw_usb_get_tx_qsel(skb, queue);

	// printk(KERN_INFO "rtv tx__ >>> tx fw queue %hxx, driver queue %hhx kind %s\n", pkt_info->qsel, queue, rtw_usb_get_frame_kind(skb));

	//update_txdesc from RTL
	rtw_tx_fill_tx_desc(pkt_info, skb); 

	//We don't set cheksum here - should we?

	// TODO Move cheksum to inlined function
	chksumdata = (u16 *) skb->data;
	for (i = 0; i < 8; i++)
		chksum ^= (*(chksumdata + 2 * i) ^ *(chksumdata + (2 * i + 1)));

	le32p_replace_bits((__le32 *)(skb->data) + 0x07, chksum, GENMASK(15, 0));

	// When packet is miscconfigured no completion, should we cancle URB than? Do test with sending worng packet before good.
	
	tx_info->rtwdev = rtwdev;
	tx_info->pkt_info = pkt_info;
	tx_info->queue = queue;
	tx_info->sn = pkt_info->sn;

	// TODO Error handling
	rtw_usb_tx_submit(tx_info);

	return 0;
}

struct rtw_usb_tx_info *rtw_usb_alloc_tx_info_conf(struct sk_buff *skb) {
	struct rtw_usb_tx_info *tx_info;

	tx_info = kmalloc(sizeof(struct rtw_usb_tx_info), GFP_ATOMIC);
	if (!tx_info) {
		return NULL;
	}

	tx_info->skb = skb;
	tx_info->ieee80211_packet = false;	

	return tx_info;
}

int rtw_usb_write_data_rsvd_page(struct rtw_dev *rtwdev, u8 *buf, u32 size) {
		struct sk_buff *skb;
	struct rtw_tx_pkt_info pkt_info = {0};
	struct rtw_usb_tx_info *tx_info;

	u8 reg_bcn_work; // TODO Why it's in PCI
	int ret;

	// TODO Probably we want to cache skb
	skb = rtw_tx_write_data_rsvd_page_get(rtwdev, &pkt_info, buf, size);
	if (!skb)
		return -ENOMEM;

	tx_info = rtw_usb_alloc_tx_info_conf(skb);
	if (!tx_info) {
		dev_kfree_skb_any(skb);
		return -ENOMEM;
	}

	ret = rtw_usb_tx_schedule(rtwdev, &pkt_info, tx_info, RTW_TX_QUEUE_BCN);
	if (ret < 0) {
		rtw_err(rtwdev, "Error TX packet %d\n", ret);
	}

	// printk(KERN_ERR "rsvd_page\n");
	return 0;
}

int rtw_usb_write_data_h2c(struct rtw_dev *rtwdev, u8 *buf, u32 size) {
	struct sk_buff *skb;
	struct rtw_tx_pkt_info pkt_info = {0};
	struct rtw_usb_tx_info *tx_info;

	int ret;

	printk(KERN_INFO "write_data_h2c\n");

	skb = rtw_tx_write_data_h2c_get(rtwdev, &pkt_info, buf, size);
	if (!skb)
		return -ENOMEM;

	tx_info = rtw_usb_alloc_tx_info_conf(skb);
	if (!tx_info) {
		dev_kfree_skb_any(skb);
		return -ENOMEM;
	}

	ret = rtw_usb_tx_schedule(rtwdev, &pkt_info, tx_info, RTW_TX_QUEUE_H2C);
	if (ret) {
		//TODO Who should deallpcate buf?
		rtw_err(rtwdev, "failed to write h2c data %d\n", ret);

		dev_kfree_skb_any(skb);
		return ret;
	}

	return 0;
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
	struct urb *urb;

	u8 usb_req_type; // Vendor specific request type (read or write)
	int io_stat, io_stat2; // Status / number of bytes read / wrote
	// int repeat_count = 0;

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
	// for (repeat_count = 0; repeat_count < 5; repeat_count++) {
	io_stat = usb_control_msg(usbdev, pipe, 5, usb_req_type, (u16) addr, 0, (void *) rtwusb->ctrl_read_buf, sz, 1000);
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

	// TODO Why we need this? Can this be controlled by module option or chip info?
	if (addr <= 0xFF || (0x1000 <= addr && addr <= 0x10ff)) {
		// printk(KERN_INFO "Special update 0x%x\n", addr);
		io_stat2 = usb_control_msg(usbdev, pipe, 5, 0x40, (u16) 0x4e0, 0, (void *) rtwusb->ctrl_read_buf, 1, 1000);
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

	rtw_dbg(rtwdev, RTW_DBG_USB, "Initializing usb device structure\n");

	spin_lock_init(&rtwusb->ctrl_lock);
	// Init read write buffer; avoid allocations later
	rtwusb->ctrl_read_buf = kmalloc(RTLW88_CTRL_BUFF_SIZE, GFP_KERNEL);
	if (rtwusb->ctrl_read_buf == NULL) {
		return -ENOMEM;
	}

	sema_init(&rtwusb->init_lock, 1);

	atomic_set(&rtwusb->rx_urbs_in_fly, 0);

	mb();

	return ret;
}

static int rtw_usb_deinit(struct rtw_dev *rtwdev)
{
	struct rtw_usb *rtwusb = (struct rtw_usb *)rtwdev->priv;
	
	if (rtwusb->ctrl_read_buf) {
		kfree((const void *) rtwusb->ctrl_read_buf);
	}

	return 0;
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

static void rtw_usb_destroy(struct rtw_dev *rtwdev, struct usb_interface *usbintf)
{
	rtw_usb_deinit(rtwdev);
    usb_set_intfdata(usbintf, NULL);
}

static void rtw_usb_claim(struct rtw_dev *rtwdev, struct usb_interface *usbintf)
{
	struct usb_device *usbdev = interface_to_usbdev(usbintf);

	// Set pointer to ieee80211 which has reference to rtw_data
	usb_set_intfdata(usbintf, rtwdev->hw);
	
	SET_IEEE80211_DEV(rtwdev->hw, &usbdev->dev);
}

static void rtw_usb_rx_complete(struct urb *urb) {
	struct rtw_dev *rtwdev = (struct rtw_dev *) urb->context;
	struct rtw_usb *rtwusb = (struct rtw_usb *) rtwdev->priv;
	struct rtw_chip_info *chip = rtwdev->chip;

	struct rtw_rx_pkt_stat pkt_stat;

	struct ieee80211_rx_status rx_status;

int res;

	u32 pkt_offset;
	u32 pkt_desc_sz = chip->rx_pkt_desc_sz;
	struct sk_buff *new;
	u32 new_len;

	u8 *rx_desc;

	rtwdev->chip->ops->query_rx_desc(rtwdev, urb->transfer_buffer, &pkt_stat, &rx_status);


	// print_hex_dump(KERN_INFO, "rtw_usb: rx", DUMP_PREFIX_OFFSET, 16, 1, urb->transfer_buffer, min(urb->actual_length, 128), false);

	if (urb->status != 0) {
		// Device can get disconnect or other issues, rx watchdog will refill if needed
		goto clear;
	}

	// COPY_PASTE FROM PCI should go be moved to RTW
	rx_desc = urb->transfer_buffer; //Single vriable part
	chip->ops->query_rx_desc(rtwdev, rx_desc, &pkt_stat, &rx_status);

	/* offset from rx_desc to payload */
	pkt_offset = pkt_desc_sz + pkt_stat.drv_info_sz +
				pkt_stat.shift;


	// printk(KERN_INFO " rtw recv %d bytes, status %d, len %hd, shift %hhd, offset=%d, pipe=0x%x\n", urb->actual_length, urb->status, pkt_stat.pkt_len, pkt_stat.shift, pkt_offset, urb->pipe);
	/* allocate a new skb for this frame,
		* discard the frame if none available
		*/
	new_len = pkt_stat.pkt_len + pkt_offset;
	new = dev_alloc_skb(new_len);
	if (WARN_ONCE(!new, "rx routine starvation\n"))
		goto resubmit; // RTW return -ENOMEM

	/* put the DMA data including rx_desc from phy to new skb */
	skb_put_data(new, urb->transfer_buffer, new_len);

	if (pkt_stat.is_c2h) {
		printk(KERN_INFO "                                 C2H packet\n");
		rtw_fw_c2h_cmd_rx_irqsafe(rtwdev, pkt_offset, new);
	} else {
		/* remove rx_desc */
		skb_pull(new, pkt_offset);

		// printk(KERN_INFO " rtw recv <<< %s\t%d bytes, status %d, len %hd, shift %hhd, offset=%d\n", rtw_usb_get_frame_kind(new), urb->actual_length, urb->status, pkt_stat.pkt_len, pkt_stat.shift, pkt_offset, urb->pipe);

		// printk(KERN_INFO "   rtw recv %s\n", rtw_usb_get_frame_kind(new));

		rtw_rx_stats(rtwdev, pkt_stat.vif, new);
		memcpy(new->cb, &rx_status, sizeof(rx_status));
		if (in_irq())
			ieee80211_rx_irqsafe(rtwdev->hw, new);
		else
			ieee80211_rx(rtwdev->hw, new);
	}
	// END OF  FROM PCI should go be moved to RTW

resubmit:	
	res = usb_submit_urb(urb, GFP_ATOMIC);

	if (res < 0) {
		// We should analyze errors and repeat or bailout
		rtw_err(rtwdev, "Error re-submitting RX: %d\n", res);
		goto clear;
	}

	return;

clear:
	atomic_dec(&rtwusb->rx_urbs_in_fly);
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

	pipe = usb_rcvbulkpipe(usbdev, 0x84); //TODO magic

	// We are in separte thread, this thread can run during USB disconnect
	usb_get_dev(usbdev);
	while (!rtwusb->stop_rx) {
		// printk(KERN_INFO "recv iteration\n");
		if (atomic_read(&rtwusb->rx_urbs_in_fly) < 10) {
			rtw_dbg(rtwdev, RTW_DBG_USB, "Adding RX urb & submitting due to exhaustion of RX buffers\n");

			// TODO URBs should be preallocated with DMA coherent and submitted as well
			// URB submit method should be created
			urb = usb_alloc_urb(0, GFP_ATOMIC);
			buff = kmalloc(64 * 1024, GFP_ATOMIC); //TOOD What's a correct size, check again orignal driver, 24kb, 48kb
			usb_fill_bulk_urb(urb, usbdev, pipe, buff, 64*1024, rtw_usb_rx_complete, rtwdev);

			res = usb_submit_urb(urb, GFP_ATOMIC);

			if (res < 0) {
				//TODO Analyze device state - disconnected break, other error continue?
				rtw_err(rtwdev, "Error submitting RX: %d\n", res);
				usb_free_urb(urb);
				kfree(buff);
				break;
			}

			atomic_inc(&rtwusb->rx_urbs_in_fly);
			continue;
		}
		msleep(1);
	}
	printk(KERN_INFO "Exit rx\n");
	usb_put_dev(usbdev);

	return 0;
}

int rtw_usb_probe(struct usb_interface *usbintf,
		  const struct usb_device_id *id)
{
	// see rtw_usb_primary_adapter_init
	struct ieee80211_hw *hw;
	struct rtw_dev *rtwdev;
	struct rtw_usb *rtwusb;
	struct usb_device *usbdev = interface_to_usbdev(usbintf);
	int drv_data_size;
	int ret;

    // TODO Almost same like for PCIe
	drv_data_size = sizeof(struct rtw_dev) + sizeof(struct rtw_usb);
	hw = ieee80211_alloc_hw(drv_data_size, &rtw_ops);
	if (!hw) {
		dev_err(&usbdev->dev, "failed to allocate hw\n");
		return -ENOMEM;
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


	rtwdev->hci.bulkout_num = 3;

	rtw_usb_claim(rtwdev, usbintf);

	ret = rtw_usb_setup_resource(rtwdev, usbintf);
	if (ret) {
		rtw_err(rtwdev, "failed to setup usb resources\n");
		goto err_deinit_core;
	}
	rtwusb = (struct rtw_usb *) rtwdev->priv;

	down(&rtwusb->init_lock);

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

    // TODO Move RX watchdog kickoff somewhere else, do we need this in anyway?
	kthread_run(rtw_usb_rx_thread, rtwdev, "rtw88_usb_rx_thread"); 
	if (ret < 0) {
		rtw_err(rtwdev, "failed to start thread %d\n", ret);
        goto err_unregister_hw;
	}

	// ret = rtw_pci_request_irq(rtwdev, pdev);
	// if (ret) {
	// 	ieee80211_unregister_hw(hw);
	// 	goto err_destroy_pci;
	// }

	up(&rtwusb->init_lock);
	return 0;

err_unregister_hw:
    rtw_unregister_hw(rtwdev, hw);

err_destroy_usb:
	rtw_usb_destroy(rtwdev, usbintf);

// err_usb_declaim:
// 	rtw_pci_declaim(rtwdev, pdev); //TODO

err_deinit_core:
	rtw_core_deinit(rtwdev);

err_release_hw:
	ieee80211_free_hw(hw);

	up(&rtwusb->init_lock);
	return ret;
}
EXPORT_SYMBOL(rtw_usb_probe);

void rtw_usb_disconnect(struct usb_interface *intf) {
	struct ieee80211_hw *hw = usb_get_intfdata(intf);
	struct rtw_dev *rtwdev = hw->priv;
	struct rtw_usb *rtwusb;

	if (!hw) {
        // Disconnect happend just after probe, or init failed
		dev_warn(intf->usb_dev, "rtw_usb: Hardware not registerd\n");
		return;
	}

	rtwusb = (struct rtw_usb *) rtwdev->priv;
	
    // Wait for init to finish
	if (down_trylock(&rtwusb->init_lock)) {
        rtw_info(rtwdev, "Waiting for initialization end\n");
        down(&rtwusb->init_lock);
    }
	
    // Now we are sure, that driver has been set-up
	rtwusb->stop_tx = true;
	rtwusb->stop_rx = true;

    hw = usb_get_intfdata(intf);
    if (!hw)
        return;

    // TODO Wait for rx & tx to stop?

	rtw_unregister_hw(rtwdev, hw);
    rtw_usb_destroy(rtwdev, intf);
    rtw_core_deinit(rtwdev);
    ieee80211_free_hw(hw);
}
EXPORT_SYMBOL(rtw_usb_disconnect);

MODULE_AUTHOR("Rado Smogura");
MODULE_DESCRIPTION("Realtek 802.11ac wireless USB driver");
MODULE_LICENSE("Dual BSD/GPL");

