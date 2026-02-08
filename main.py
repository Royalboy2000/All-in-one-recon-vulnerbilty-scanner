import os
import sys
import importlib
import logging
from utils import Logger
from database import DatabaseManager
from colorama import Fore, Style

class RedSentry:
    def __init__(self):
        self.logger = Logger()
        self.db = DatabaseManager()
        self.modules = {}
        self.load_modules()

    def print_banner(self):
        # Clear screen based on OS
        os.system('cls' if os.name == 'nt' else 'clear')

        banner = f"""
{Fore.RED}
  _____          _  _____            _
 |  __ \        | |/ ____|          | |
 | |__) |___  __| | (___   ___ _ __ | |_ _ __ _   _
 |  _  // _ \/ _` |\___ \ / _ \ '_ \| __| '__| | | |
 | | \ \  __/ (_| |____) |  __/ | | | |_| |  | |_| |
 |_|  \_\___|\__,_|_____/ \___|_| |_|\__|_|   \__, |
                                               __/ |
                                              |___/
{Style.RESET_ALL}
        """
        print(banner)
        print(f"{Fore.CYAN}Welcome to RedSentry - The Ultimate Red Teaming Framework{Style.RESET_ALL}")
        print("-" * 60)

    def load_modules(self):
        module_path = "modules"
        if not os.path.exists(module_path):
            self.logger.error(f"Modules directory '{module_path}' not found.")
            return

        for filename in os.listdir(module_path):
            if filename.endswith(".py") and filename != "__init__.py":
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f"modules.{module_name}")
                    if hasattr(module, "run"):
                        self.modules[module_name] = module
                        # self.logger.info(f"Loaded module: {module_name}") # Keeping this quiet for cleaner startup
                    else:
                        self.logger.warning(f"Module '{module_name}' does not have a 'run' function.")
                except Exception as e:
                    self.logger.error(f"Failed to load module '{module_name}': {e}")

    def main_menu(self):
        while True:
            self.print_banner()
            if not self.modules:
                print(f"{Fore.YELLOW}No modules loaded.{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}Available Modules:{Style.RESET_ALL}")
                # Sort modules for consistent order
                sorted_modules = sorted(self.modules.keys())
                for idx, module_name in enumerate(sorted_modules, 1):
                    print(f"{idx}. {module_name.upper()}")

            print("0. Exit")

            try:
                choice = input(f"\n{Fore.GREEN}Select a module > {Style.RESET_ALL}")

                if choice == "0":
                    print("Exiting...")
                    break

                try:
                    choice_idx = int(choice) - 1
                    sorted_modules = sorted(self.modules.keys())

                    if 0 <= choice_idx < len(sorted_modules):
                        selected_module_name = sorted_modules[choice_idx]
                        self.run_module(selected_module_name)
                    else:
                        input(f"{Fore.RED}Invalid selection. Press Enter...{Style.RESET_ALL}")
                except ValueError:
                    input(f"{Fore.RED}Please enter a number. Press Enter...{Style.RESET_ALL}")
            except KeyboardInterrupt:
                print("\nExiting...")
                break

    def run_module(self, module_name):
        module = self.modules[module_name]
        print(f"\n{Fore.CYAN}Running {module_name}...{Style.RESET_ALL}")

        # Get target from user
        target = ""
        if module_name == "osint":
            target = input(f"Enter target domain (e.g., example.com): ")
        elif module_name == "android":
            target = input(f"Enter path to APK file: ")
        else:
            target = input(f"Enter target: ")

        if not target:
             print(f"{Fore.RED}Target cannot be empty.{Style.RESET_ALL}")
             input("Press Enter to continue...")
             return

        try:
            # Pass the logger and db to the module so it can use them
            # Check signature of run method? No, assume standard signature: run(target, logger, db)
            module.run(target, self.logger, self.db)
        except TypeError as e:
             # Fallback if module doesn't accept logger/db (though I will ensure they do)
             try:
                 module.run(target)
             except Exception as inner_e:
                 self.logger.error(f"Error running module '{module_name}': {e} | {inner_e}")
        except Exception as e:
            self.logger.error(f"Error running module '{module_name}': {e}")

        input(f"\n{Fore.YELLOW}Press Enter to return to menu...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        app = RedSentry()
        app.main_menu()
    except KeyboardInterrupt:
        print("\nExiting...")
