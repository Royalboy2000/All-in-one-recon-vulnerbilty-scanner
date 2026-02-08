import logging
import os
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class Logger:
    def __init__(self, log_file="redsentry.log"):
        self.log_file = log_file
        self.setup_logging()

    def setup_logging(self):
        # Configure logging to file
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filemode='a'
        )

    def success(self, message):
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")
        logging.info(f"SUCCESS: {message}")

    def error(self, message):
        print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")
        logging.error(f"ERROR: {message}")

    def info(self, message):
        print(f"{Fore.BLUE}[*] {message}{Style.RESET_ALL}")
        logging.info(f"INFO: {message}")

    def warning(self, message):
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
        logging.warning(f"WARNING: {message}")
