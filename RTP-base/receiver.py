import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


# func tạo và đóng gói tin RTP kèm checksum CRC-32
def xaydung_packet(loai_pkt, so_seq, du_lieu=b""):
    if isinstance(du_lieu, str):
        du_lieu = du_lieu.encode("utf-8")
    hdr = PacketHeader(type=loai_pkt, seq_num=so_seq, length=len(du_lieu), checksum=0)
    hdr.checksum = compute_checksum(hdr / du_lieu)
    return bytes(hdr / du_lieu)


# Ham giai ma goi tin and check
def giaima_packet(raw_bytes):
    if len(raw_bytes) < 16:
        return None, None
    hdr = PacketHeader(raw_bytes[:16])
    data = raw_bytes[16 : 16 + hdr.length]
    crc_nhan = hdr.checksum
    hdr.checksum = 0
    # Nếu checksum sai lệch or bị lỗi đường truyền thi drop
    if crc_nhan != compute_checksum(hdr / data):
        return None, None
    return hdr, data


def receiver(receiver_ip, receiver_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    da_ket_noi = False
    dia_chi_sender = None
    next_seq = 1        
    buffer_cho = {}     # buffer  các gói đến sớm

    while True:
        raw_bytes, addr = sock.recvfrom(2048)
        hdr, du_lieu = giaima_packet(raw_bytes)
        if hdr is None:
            # Gói tin hỏng thif checksum se bỏ qua, không gửi ACK
            continue

        if hdr.type == 0:
            if not da_ket_noi:
                da_ket_noi = True
                dia_chi_sender = addr
                next_seq = 1
                buffer_cho.clear()
                # Phản hồi ACK với seq_num = 1
                sock.sendto(xaydung_packet(3, 1), dia_chi_sender)
            continue

        if not da_ket_noi:
            continue

        # 2. Xử lý gói kết thúc END
        if hdr.type == 1:
            # Gửi ACK xác nhận gói END rồi hoàn tất
            sock.sendto(xaydung_packet(3, hdr.seq_num), dia_chi_sender)
            sys.stdout.flush()
            break

        # 3. Xử lý gói dữ liệu DATA
        if hdr.type == 2:
            seq = hdr.seq_num

            # Nếu gói nằm ngoài phạm vi cửa sổ hiện tại -> drop
            if seq >= next_seq + window_size:
                continue

            # Trường hợp 1: Nhận đúng gói mong đợi (seq == next_seq)
            if seq == next_seq:
                buffer_cho[seq] = du_lieu
                # Ghi liên tục các gói đã nhận đủ ra stdout
                while next_seq in buffer_cho:
                    sys.stdout.buffer.write(buffer_cho.pop(next_seq))
                    next_seq += 1
                sys.stdout.flush()
                # Gửi Cumulative ACK báo gói tiếp theo đang chờ
                sock.sendto(xaydung_packet(3, next_seq), dia_chi_sender)

            # Trường hợp 2: Gói đến sớm (seq > next_seq) -> lưu vào buffer tạm
            elif seq > next_seq:
                buffer_cho[seq] = du_lieu
                # Gửi lại ACK lặp báo vẫn đang chờ next_seq
                sock.sendto(xaydung_packet(3, next_seq), dia_chi_sender)

            # Trường hợp 3: Gói cũ gửi lại (seq < next_seq) -> báo lại next_seq
            else:
                sock.sendto(xaydung_packet(3, next_seq), dia_chi_sender)

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()

