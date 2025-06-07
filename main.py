import argparse
import logging
import socket
import random
import time
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Detects potential port knocking implementations by sending a sequence of packets to different ports and analyzing responses."
    )
    parser.add_argument("target_host", help="The target host IP address or hostname.")
    parser.add_argument(
        "--ports",
        nargs="+",
        type=int,
        required=True,
        help="A space-separated list of ports to knock on, in the correct sequence.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Timeout in seconds for each port connection attempt (default: 1.0).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay in seconds between knocking on each port (default: 0.1).",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose output (debug logging)."
    )
    return parser


def knock_port(host, port, timeout=1.0):
    """
    Attempts to connect to a specified port on a given host.
    Args:
        host (str): The target host IP address or hostname.
        port (int): The port number to attempt to connect to.
        timeout (float): Timeout in seconds for the connection attempt.

    Returns:
        bool: True if the connection was successful, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            logging.debug(f"Successfully connected to {host}:{port}")
            return True
    except socket.timeout:
        logging.debug(f"Connection to {host}:{port} timed out.")
        return False
    except ConnectionRefusedError:
        logging.debug(f"Connection to {host}:{port} was refused.")
        return False
    except Exception as e:
        logging.error(f"An error occurred while connecting to {host}:{port}: {e}")
        return False


def main():
    """
    Main function to execute the port knocking detection tool.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    host = args.target_host
    ports = args.ports
    timeout = args.timeout
    delay = args.delay

    # Input Validation (added to avoid common errors)
    if not isinstance(host, str) or not host:
        logging.error("Invalid target host. Please provide a valid hostname or IP address.")
        sys.exit(1)

    if not all(isinstance(port, int) and 1 <= port <= 65535 for port in ports):
        logging.error("Invalid port numbers. Please provide a list of integers between 1 and 65535.")
        sys.exit(1)
    
    if timeout <= 0:
        logging.error("Timeout must be a positive value.")
        sys.exit(1)

    if delay < 0:
        logging.error("Delay must be a non-negative value.")
        sys.exit(1)

    logging.info(f"Starting port knocking detection on {host}...")
    logging.debug(f"Target host: {host}, Ports: {ports}, Timeout: {timeout}, Delay: {delay}")

    try:
        success = True
        for i, port in enumerate(ports):
            logging.info(f"Knocking on port {port} ({i+1}/{len(ports)})...")
            if not knock_port(host, port, timeout):
                success = False
                logging.warning(f"Failed to connect to port {port}.")
                break # Stop on first failure for realistic knocking
            time.sleep(delay)

        if success:
            logging.info("Successfully knocked on all ports in sequence.")
            print("Port knocking sequence successful.  Investigate further for potential vulnerabilities.") # Indicate a potential finding.
        else:
            logging.info("Port knocking sequence failed.")
            print("Port knocking sequence failed.  No ports opened after knocking sequence.") # Indicate a failed attempt

    except KeyboardInterrupt:
        logging.info("Port knocking detection interrupted by user.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
    finally:
        logging.info("Port knocking detection completed.")


if __name__ == "__main__":
    """
    Entry point of the script.
    """
    main()

"""
Usage Examples:

1. Basic port knocking detection:
   python vuln-Port-Knocking-Detector.py target.example.com --ports 1234 5678 9012

2. Port knocking detection with custom timeout and delay:
   python vuln-Port-Knocking-Detector.py target.example.com --ports 1234 5678 9012 --timeout 2.0 --delay 0.5

3. Verbose output for debugging:
   python vuln-Port-Knocking-Detector.py target.example.com --ports 1234 5678 9012 --verbose

Offensive Tool Steps (Illustrative - use with authorization only):

1.  After detecting a successful port knock, attempt to connect to a service on a port that *should* be opened by the knock.
2.  Send crafted packets to the opened service, attempting to exploit known vulnerabilities for that service version.
3.  Attempt to retrieve sensitive information from the opened service (e.g., configuration files, database credentials).

Important Considerations:

*   Ensure you have explicit permission to perform port knocking detection and any subsequent exploitation attempts on the target system.
*   Be aware of the potential for false positives and false negatives in port knocking detection.
*   Monitor network traffic for any unusual activity that may indicate a security breach.
*   Regularly update your vulnerability assessment tools and techniques to stay ahead of emerging threats.
"""