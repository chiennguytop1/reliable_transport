import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


# func tao goi tin RTP co kem crc-32
def xaydung_packet(loai_pkt, so_seq, du_lieu=b""):
    if isinstance(du_lieu, str):
        du_lieu = du_lieu.encode("utf-8")
    hdr = PacketHeader(type=loai_pkt, seq_num=so_seq, length=len(du_lieu), checksum=0)
    hdr.checksum = compute_checksum(hdr / du_lieu)
    return bytes(hdr / du_lieu)


# Ham kiem tra va unpack goi ack
def giaima_packet(raw_bytes):
    if len(raw_bytes) < 16:
        return None, None
    hdr = PacketHeader(raw_bytes[:16])
    data = raw_bytes[16 : 16 + hdr.length]
    crc_nhan = hdr.checksum
    hdr.checksum = 0
    if crc_nhan != compute_checksum(hdr / data):
        return None, None
    return hdr, data


def sender(receiver_ip, receiver_port, window_size):
    # read data tho tu stdin
    du_lieu_goc = sys.stdin.buffer.read()
    MAX_PAYLOAD = 1456
    
    # chia nho data thanh tung chunk va dong goi
    danh_sach_goi = {}
    dem_seq = 1
    for i in range(0, len(du_lieu_goc), MAX_PAYLOAD):
        chunk = du_lieu_goc[i : i + MAX_PAYLOAD]
        danh_sach_goi[dem_seq] = xaydung_packet(2, dem_seq, chunk)
        dem_seq += 1
    tong_so_goi = len(danh_sach_goi)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    # giai doan bat tay: ban start (seq=0) va doi ack 1
    goi_start = xaydung_packet(0, 0)
    while True:
        sock.sendto(goi_start, (receiver_ip, receiver_port))
        readable, _, _ = select.select([sock], [], [], 0.5)
        if readable:
            try:
                phan_hoi, _ = sock.recvfrom(2048)
                hdr, _ = giaima_packet(phan_hoi)
                if hdr and hdr.type == 3 and hdr.seq_num == 1:
                    break
            except BlockingIOError:
                pass

    # truyen du lieu co che selective repeat
    win_base = 1         # vi tri dau cua so
    next_seq_send = 1    # goi tiep theo can ban di
    tap_da_ack = set()   # set luu lai cac goi da nhan duoc ack
    timer_start = None   # dem timeout 500ms

    while win_base <= tong_so_goi:
        # ban cac goi moi chua tung gui nam trong cua so
        while next_seq_send < win_base + window_size and next_seq_send <= tong_so_goi:
            sock.sendto(danh_sach_goi[next_seq_send], (receiver_ip, receiver_port))
            if timer_start is None:
                timer_start = time.time()
            next_seq_send += 1

        # tinh thoi gian timeout con lai cua cua so
        thoi_gian_hien_tai = time.time()
        if timer_start is not None:
            time_cho = max(0.0, 0.5 - (thoi_gian_hien_tai - timer_start))
        else:
            time_cho = 0.5

        # doi phan hoi ack
        readable, _, _ = select.select([sock], [], [], time_cho)
        if readable:
            while True:
                try:
                    phan_hoi, _ = sock.recvfrom(2048)
                    hdr, _ = giaima_packet(phan_hoi)
                    if hdr and hdr.type == 3:  # nhan duoc goi ack
                        ack_seq = hdr.seq_num
                        if ack_seq >= win_base and ack_seq not in tap_da_ack:
                            tap_da_ack.add(ack_seq)
                            old_base = win_base
                            # truot cua so qua cac goi da duoc ack lien tuc
                            while win_base in tap_da_ack:
                                win_base += 1
                            if win_base > old_base:
                                if win_base == next_seq_send:
                                    timer_start = None
                                else:
                                    timer_start = time.time()  # reset timer khi cua so tien len
                except BlockingIOError:
                    break

        # xu li timeout 500ms: CHI ban lai nhung goi CHUA nhan duoc ack
        thoi_gian_hien_tai = time.time()
        if timer_start is not None and (thoi_gian_hien_tai - timer_start >= 0.5):
            for seq in range(win_base, next_seq_send):
                if seq not in tap_da_ack:
                    sock.sendto(danh_sach_goi[seq], (receiver_ip, receiver_port))
            timer_start = time.time()

    # Ket thuc: gui end va cho toi da 500ms
    end_seq = tong_so_goi + 1
    goi_end = xaydung_packet(1, end_seq)
    sock.sendto(goi_end, (receiver_ip, receiver_port))
    tg_bat_dau_end = time.time()
    while time.time() - tg_bat_dau_end < 0.5:
        con_lai = max(0.0, 0.5 - (time.time() - tg_bat_dau_end))
        readable, _, _ = select.select([sock], [], [], con_lai)
        if readable:
            try:
                phan_hoi, _ = sock.recvfrom(2048)
                hdr, _ = giaima_packet(phan_hoi)
                if hdr and hdr.type == 3 and hdr.seq_num == end_seq:
                    break
            except BlockingIOError:
                break

    sock.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
