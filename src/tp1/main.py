import argparse
from tp1.utils.capture import capture, sort_network_protocols
from tp1.utils.config import logger
from tp1.utils.report import build_report, write_json
from tp1.utils.detection import analyse, trouver_flag


def main():
    logger.info("Starting TP1")

    ### Ouverture de la capture
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface to capture")
    parser.add_argument("-p", "--pcap", help="filename to capture")
    parser.add_argument("-o", "--out", default="report.json", help="report json")

    args = parser.parse_args()
    packet = capture(interface=args.interface, pcap=args.pcap)
    protocols = sort_network_protocols(packets=packet)
    attacks = analyse(packet)
    flag = trouver_flag(packet, attacks)
    report = build_report(protocols, attacks, flag)
    write_json(report, args.out)


if __name__ == "__main__":
    main()
