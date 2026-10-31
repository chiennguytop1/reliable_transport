import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


# func tao va dong goi RTP kem checksum
def xaydung_packet(loai_pkt, so_seq, du_lieu=b""):
    if isinstance(du_lieu, str):
        du_lieu = du_lieu.encode("utf-8")
    hdr = PacketHeader(type=loai_pkt, seq_num=so_seq, length=len(du_lieu), checksum=0)
    hdr.checksum = compute_checksum(hdr / du_lieu)
    return bytes(hdr / du_lieu)


# Ham giai ma goi tin and check crc
def giaima_packet(raw_bytes):
    if len(raw_bytes) < 16:
        return None, None
    hdr = PacketHeader(raw_bytes[:16])
    data = raw_bytes[16 : 16 + hdr.length]
    crc_nhan = hdr.checksum
    hdr.checksum = 0
    # check xem co bi loi bit hay khong
    if crc_nhan != compute_checksum(hdr / data):
        return None, None
    return hdr, data


def receiver(receiver_ip, receiver_port, window_size):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((receiver_ip, receiver_port))

    da_ket_noi = False
    dia_chi_sender = None
    next_seq = 1        # goi tiep theo can day ra stdout
    buffer_cho = {}     # buffer luu tam cac packet den truoc

    while True:
        raw_bytes, addr = sock.recvfrom(2048)
        hdr, du_lieu = giaima_packet(raw_bytes)
        if hdr is None:
            # checksum fail thi drop bo qua
            continue

        # bat tay START
        if hdr.type == 0:
            if not da_ket_noi:
                da_ket_noi = True
                dia_chi_sender = addr
                next_seq = 1
                buffer_cho.clear()
                # phan hoi ack 1
                sock.sendto(xaydung_packet(3, 1), dia_chi_sender)
            continue

        if not da_ket_noi:
            continue

        # goi ket thuc end
        if hdr.type == 1:
            sock.sendto(xaydung_packet(3, hdr.seq_num), dia_chi_sender)
            sys.stdout.flush()
            break

        # xu ly data voi co che selective ack
        if hdr.type == 2:
            seq = hdr.seq_num

            # nam ngoai cua so thi bo qua
            if seq >= next_seq + window_size:
                continue

            if seq < next_seq:
                # goi cu den lai thi van phai ack rieng cho no
                sock.sendto(xaydung_packet(3, seq), dia_chi_sender)
            else:
                # luu vao buffer roi ack rieng dung seq do
                buffer_cho[seq] = du_lieu
                sock.sendto(xaydung_packet(3, seq), dia_chi_sender)

                # day lien tuc cac goi hop le ra stdout
                while next_seq in buffer_cho:
                    sys.stdout.buffer.write(buffer_cho.pop(next_seq))
                    next_seq += 1
                sys.stdout.flush()

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
