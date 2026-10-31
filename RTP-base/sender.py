import argparse
import select
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


# func gói tin RTP với checksum CRC-32
def xaydung_packet(loai_pkt, so_seq, du_lieu=b""):
    if isinstance(du_lieu, str):
        du_lieu = du_lieu.encode("utf-8")
    hdr = PacketHeader(type=loai_pkt, seq_num=so_seq, length=len(du_lieu), checksum=0)
    hdr.checksum = compute_checksum(hdr / du_lieu)
    return bytes(hdr / du_lieu)


# Hàm kiểm tra và giải mã gói ACK từ receiver
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
    # read data thô từ luồng vào theo kieu stdin
    du_lieu_goc = sys.stdin.buffer.read()
    MAX_PAYLOAD = 1456
    
    # Chia dữ liệu thành từng khối và đóng gói sẵn
    danh_sach_goi = {}
    dem_seq = 1
    for i in range(0, len(du_lieu_goc), MAX_PAYLOAD):
        chunk = du_lieu_goc[i : i + MAX_PAYLOAD]
        danh_sach_goi[dem_seq] = xaydung_packet(2, dem_seq, chunk)
        dem_seq += 1
    tong_so_goi = len(danh_sach_goi)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)

    # . Giai đoạn bắt tay: gui start (seq=0) và đợi ack 1
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

    #  Giai đoạn truyền dữ liệu voi GO back
    win_base = 1         # first sliding
    next_seq_send = 1    # so thu tu goi tiep theo can gi
    timer_start = None   # Thời điểm bắt đầu đếm 500ms

    while win_base <= tong_so_goi:
        # Bắn liên tục các gói nằm trong phạm vi window_size
        while next_seq_send < win_base + window_size and next_seq_send <= tong_so_goi:
            sock.sendto(danh_sach_goi[next_seq_send], (receiver_ip, receiver_port))
            if timer_start is None:
                timer_start = time.time()
            next_seq_send += 1

        #  thời gian chờ timeout còn lại của cửa sổ
        thoi_gian_hien_tai = time.time()
        if timer_start is not None:
            time_cho = max(0.0, 0.5 - (thoi_gian_hien_tai - timer_start))
        else:
            time_cho = 0.5

        # wait phan  hoi cua ack
        readable, _, _ = select.select([sock], [], [], time_cho)
        if readable:
            while True:
                try:
                    phan_hoi, _ = sock.recvfrom(2048)
                    hdr, _ = giaima_packet(phan_hoi)
                    if hdr and hdr.type == 3:  # xac nhan dung goi ack
                        ack_num = hdr.seq_num
                        if ack_num > win_base:
                            win_base = ack_num
                            # tat ca cac goi phai thoa man ack het
                            if win_base == next_seq_send:
                                timer_start = None
                            else:
                                timer_start = time.time()  # reset khoi tao lai time
                except BlockingIOError:
                    break

        # xu li problem time out 500ms: Gửi lại toàn bộ các gói đang có trong cửa sổ
        thoi_gian_hien_tai = time.time()
        if timer_start is not None and (thoi_gian_hien_tai - timer_start >= 0.5):
            for seq in range(win_base, next_seq_send):
                sock.sendto(danh_sach_goi[seq], (receiver_ip, receiver_port))
            timer_start = time.time()

    #  giai doan ending: gui end và chờ tối đa 500ms
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
