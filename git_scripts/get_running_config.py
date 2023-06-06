import json
import argparse
from napalm import get_network_driver
from rich import print as rprint
import concurrent.futures

parser = argparse.ArgumentParser(description="Get device running configuration")
parser.add_argument('-e', '--environment', type=str, metavar='',
                    help='Infrastructure environment [PROD/DEV]', required=True)
parser.add_argument('-u', '--username', type=str, metavar='',
                    help='Tacacs username', required=True)
parser.add_argument('-s', '--password', type=str, metavar='',
                    help='Tacacs password', required=True)
args = parser.parse_args()


def process_device(device):
    host = device['Device Name']
    ip_address = device['IP Address']
    rprint(f"\n[cyan]********** {host} **********[/cyan]")

    # Napalm driver
    driver = get_network_driver('ios')
    device_instance = driver(
        hostname=ip_address,
        username=args.username,
        password=args.password,
        timeout=10
    )

    try:
        # Connect to the device
        device_instance.open()

        # Execute CLI command 'show run'
        run_config = device_instance.cli(['show run'])

        # Save the running configuration in a file
        filename = f"device_configurations/{args.environment.lower()}/{host}.txt"
        with open(filename, 'w') as write_output:
            write_output.write(run_config['show run'])

        # Close the device connection
        device_instance.close()

        rprint(f"[green]✅ {host} - OK [/green]")
    except Exception as err:
        rprint(f"[red]❌ {host} - ERROR - {err}[/red]")


def main():
    '''
    Main script to get device running configuration via CLI
    Python CLI module used is Napalm
    '''
    # Initialize variables
    inventory_file = f'inventory/host_{args.environment.lower()}.json'

    # Load devices from inventory file
    with open(inventory_file, 'r') as inventory:
        devices = json.load(inventory)

    # Create a ThreadPoolExecutor with max_workers set to the number of devices
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # Submit a task for each device to the executor
        futures = [executor.submit(process_device, device) for device in devices]

        # Wait for all tasks to complete
        concurrent.futures.wait(futures)

    rprint("All devices processed successfully.")


if __name__ == "__main__":
    main()
