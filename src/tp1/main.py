from tp1.utils.capture import capture
from tp1.utils.config import logger
import argparse


def main():
    logger.info("Starting TP1")

    ### Ouverture de la capture
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface to capture")
    parser.add_argument("-p", "--pcap", help="filename to capture")
    args = parser.parse_args()
    packet = capture(interface=args.interface, pcap=args.pcap)
    print(packet)

    ### Analyse de la capture
    # capture.analyse("tcp")
    # summary = capture.get_summary()

    ### Reporting json / pdf
    # filename = "report.pdf"
    # report = Report(capture, filename, summary)
    # report.generate("graph")
    # report.generate("array")
    # report.save(filename)


if __name__ == "__main__":
    main()
