import csv
from netutils.config.compliance import compliance
import json
from rich import print as rprint
from pprint import pprint

features = [
    {
        "name": "tacacs",
        "ordered": True,
        "section": [
            "tacacs server"
        ]
    },
]

environment = 'DEV'
inventory_file = f'inventory/host_{environment.lower()}.json'
csv_report_file = 'compliance_report.csv'


def process_device(device):
    host = device['Device Name']
    ip_address = device['IP Address']
    backup = f"device_configurations/{environment.lower()}/{host}.txt"
    intended = f"properties/compliance_netutils/intended_US.txt"
    network_os = "cisco_ios"
    compliance_report = compliance(features, backup, intended, network_os)
    return host, compliance_report


if __name__ == "__main__":
    with open(inventory_file, 'r') as inventory:
        devices = json.load(inventory)

    # Process each device
    results = []
    for device in devices:
        result = process_device(device)
        results.append(result)

    # Prepare data for CSV report
    report_data = {}
    feature_names = [feature["name"] for feature in features]
    summary_row = {'Device': 'Total Non-compliant'}
    for feature_name in feature_names:
        summary_row[feature_name] = 0

    for host, result in results:
        device_row = {'Device': host}
        for feature_name in feature_names:
            compliant = result.get(feature_name, {}).get('compliant', False)
            compliant = 'Compliant' if compliant else 'Non-compliant'
            device_row[feature_name] = compliant

            missing = result.get(feature_name, {}).get('missing', [])
            device_row[f'{feature_name}_missing'] = missing

            extra = result.get(feature_name, {}).get('extra', [])
            device_row[f'{feature_name}_extra'] = extra

            if compliant == 'Non-compliant':
                summary_row[feature_name] += 1

        report_data[host] = device_row

    # Add summary row to report data
    report_data['Total Non-compliant'] = summary_row

    # Create the CSV report
    with open(csv_report_file, 'w', newline='') as csv_file:
        fieldnames = ['Device'] + feature_names + [f'{name}_missing' for name in feature_names] + [f'{name}_extra' for name in feature_names]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(report_data.values())

    print(f"CSV report generated successfully: {csv_report_file}")
