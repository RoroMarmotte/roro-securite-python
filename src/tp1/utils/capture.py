from scapy.sendrecv import sniff
from scapy.utils import rdpcap

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap) -> None:
        self.interface = choose_interface()
        self.summary = ""

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary


def capture(interface=None, pcap=None):
    if pcap:
        packets = rdpcap(pcap)
    elif interface:
        logger.info(f"Capture traffic from interface {interface}")
        packets = sniff(iface=interface, count=15)
    else:
        raise ValueError("Il faut une interface ou un fichier pcap")
    return packets
