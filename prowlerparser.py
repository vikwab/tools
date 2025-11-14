import csv
import glob
import argparse
import os

def analyze_prowler_output(file_path, region_filter=None):
    """
    Analyzes a Prowler CSV output file (AWS or Azure) and returns a list of
    failed checks. Can be filtered by a specific region/location.

    Args:
        file_path (str): The path to the Prowler CSV file.
        region_filter (str, optional): The Region or Location to filter by.
                                       If None, checks from all regions are included.
                                       Defaults to None.

    Returns:
        list: A list of lists, where each inner list contains the
              CHECK_TITLE, SEVERITY, and ACCOUNT_ID for a failed check.
    """
    failed_checks = []
    try:
        with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
            # Prowler CSVs typically use a semicolon as a delimiter.
            reader = csv.DictReader(csvfile, delimiter=';')
            
            # Check for empty files or missing headers
            if not reader.fieldnames:
                print(f"Warning: Skipping empty or invalid file: {file_path}")
                return []

            # Create a set of headers for efficient lookup
            headers = set(reader.fieldnames)

            # --- Platform Detection ---
            # Determine column names based on the platform (AWS vs Azure)
            # This is based on unique column names for each platform.
            if 'ACCOUNT_UID' in headers:
                # AWS Platform
                check_title_col = 'CHECK_TITLE'
                severity_col = 'SEVERITY'
                account_col = 'ACCOUNT_UID'
                region_col = 'REGION'
            elif 'SUBSCRIPTIONID' in headers:
                # Azure Platform
                # Note: Azure reports (like the sample) may not have 'SEVERITY'.
                # row.get(severity_col, 'N/A') will handle this.
                check_title_col = 'REQUIREMENTS_DESCRIPTION' # Best equivalent to CHECK_TITLE
                severity_col = 'SEVERITY' # This will default to 'N/A' if not present
                account_col = 'SUBSCRIPTIONID'
                region_col = 'LOCATION' # Azure uses 'LOCATION'
            else:
                # Unknown platform
                print(f"Warning: Skipping file '{os.path.basename(file_path)}'.")
                print("Could not detect known AWS ('ACCOUNT_UID') or Azure ('SUBSCRIPTIONID') headers.")
                return []

            # --- Process Rows ---
            for row in reader:
                # First, check for failed status
                if row.get('STATUS') == 'FAIL':
                    # If a region is specified, filter by it.
                    # Otherwise, include the check.
                    if region_filter is None or row.get(region_col) == region_filter:
                        failed_checks.append([
                            row.get(check_title_col, 'N/A'),
                            row.get(severity_col, 'N/A'),
                            row.get(account_col, 'N/A')
                        ])
                        
    except (FileNotFoundError, Exception) as e:
        print(f"Error processing file {file_path}: {e}")
    return failed_checks

def main():
    """
    Main function to find and analyze Prowler CSV files (AWS and Azure),
    remove duplicates, optionally filter by region, and save the output.
    """
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Analyze Prowler CSV output files (AWS & Azure) and filter for failed checks."
    )
    parser.add_argument(
        '-r', '--region',
        type=str,
        help="Cloud Region or Location to filter results by (e.g., us-east-1, westeurope)."
    )
    parser.add_argument(
        '-d', '--directory',
        type=str,
        default='.',
        help="Directory to search for Prowler CSV files. Defaults to current directory."
    )
    args = parser.parse_args()

    # Validate that the specified directory exists
    if not os.path.isdir(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist.")
        return

    # Find all Prowler CSV files (generic pattern for AWS and Azure)
    search_pattern = os.path.join(args.directory, 'prowler-*.csv')
    csv_files = glob.glob(search_pattern)

    if not csv_files:
        print(f"No Prowler CSV files (matching 'prowler-*.csv') found in directory: {args.directory}")
        return

    all_failed_checks = []
    print(f"Searching in directory: {args.directory}")
    print(f"Analyzing files: {', '.join([os.path.basename(f) for f in csv_files])}")
    
    for file in csv_files:
        # Pass the region from the command line to the analysis function
        all_failed_checks.extend(analyze_prowler_output(file, args.region))

    if not all_failed_checks:
        if args.region:
            print(f"No failed checks found in the '{args.region}' region/location.")
        else:
            print("No failed checks found.")
        return

    # Convert list of lists to a set of tuples to remove duplicates.
    unique_failed_checks_set = {tuple(check) for check in all_failed_checks}
    # Convert the set back to a list of lists for sorting and writing.
    unique_failed_checks = [list(check) for check in unique_failed_checks_set]

    # Sort the unique failed checks by Account ID and then by Severity
    # (Sorting by x[2] (Account) first, then x[1] (Severity))
    unique_failed_checks.sort(key=lambda x: (x[2], x[1]))

    # Save the results to a new CSV file in the current working directory
    output_filename = 'failed_items.csv'
    try:
        with open(output_filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write the generic header row
            writer.writerow(['Failed Item', 'Severity', 'Account ID'])
            
            # Write the data rows
            writer.writerows(unique_failed_checks)

        if args.region:
            region_text = f"in the '{args.region}' region/location"
        else:
            region_text = "across all regions/locations"

        print(f"\nAnalysis complete. Found {len(unique_failed_checks)} unique failed items {region_text}.")
        print(f"Results have been saved to '{output_filename}' in the current directory.")

    except IOError as e:
        print(f"Error writing to file {output_filename}: {e}")

if __name__ == "__main__":
    main()
