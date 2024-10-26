import boto3
from botocore.exceptions import ClientError

# List of all AWS regions (including all regions where SNS is available)
regions = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2', 'af-south-1',
    'ap-east-1', 'ap-south-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-southeast-1',
    'ap-southeast-2', 'ca-central-1', 'eu-central-1', 'eu-west-1', 'eu-west-2',
    'eu-west-3', 'eu-north-1', 'me-south-1', 'sa-east-1'
]

# Function to get the current SNS SMS MonthlySpendLimit for a region
def get_sns_limits_for_region(region):
    sns_client = boto3.client('sns', region_name=region)
    try:
        # Fetch the SMS attributes
        response = sns_client.get_sms_attributes(attributes=['MonthlySpendLimit'])
        return response['attributes'].get('MonthlySpendLimit', 'Not Set')
    except ClientError as e:
        print(f"Error getting SMS limits for region {region}: {e}")
        return None

# Function to update the SNS MonthlySpendLimit for a region
def update_sns_limit(region, new_limit):
    sns_client = boto3.client('sns', region_name=region)
    try:
        sns_client.set_sms_attributes(
            attributes={'MonthlySpendLimit': str(new_limit)}
        )
        print(f"Successfully updated MonthlySpendLimit to {new_limit} for region {region}.")
    except ClientError as e:
        print(f"Error updating limit for region {region}: {e}")

# Function to send a test SMS message
def send_test_sms(region, phone_number, message="This is a test SMS from AWS SNS"):
    sns_client = boto3.client('sns', region_name=region)
    try:
        response = sns_client.publish(
            PhoneNumber=phone_number,
            Message=message
        )
        print(f"Successfully sent test SMS to {phone_number} in region {region}. Message ID: {response['MessageId']}")
    except ClientError as e:
        print(f"Error sending test SMS in region {region}: {e}")

# Function to check and automatically update limits
def check_and_auto_update_limits():
    for region_name in regions:
        print(f"\n--- Region: {region_name} ---")

        # Get current MonthlySpendLimit
        current_limit = get_sns_limits_for_region(region_name)
        print(f"Current MonthlySpendLimit: {current_limit}")

        # If the limit is $1, automatically update
        if current_limit == '1':
            new_limit = input(f"MonthlySpendLimit is 1 USD in {region_name}. Enter the new limit to update (e.g., 10, 20): ")
            update_sns_limit(region_name, new_limit)

        # Ask if user wants to send a test SMS
        send_sms = input(f"Do you want to send a test SMS in {region_name}? (y/n): ").lower()
        if send_sms == 'y':
            phone_number = input("Enter the phone number to send test SMS (in E.164 format, e.g., +1234567890): ")
            send_test_sms(region_name, phone_number)

if __name__ == "__main__":
    check_and_auto_update_limits()
