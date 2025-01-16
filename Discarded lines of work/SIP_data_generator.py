# Script for SIP data generation
import subprocess
import random
import time

# Generate a SIP request using sipexer.
def generate_sip_request(dest, method='options'):
    # Method to flag mapping
    method_flags = {
        'register': '-register',
        'options': '-options',
        'subscribe': '-subscribe',
        'notify': '-notify'
    }

    # Ensure method is supported
    method = method.lower()
    if method not in method_flags:
        raise ValueError(f"Unsupported SIP method: {method}")

    # Base command
    cmd = ['sipexer', method_flags[method]]

    # Add destination
    cmd.append(dest)

    try:
        # Run command and capture output
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
        return result.stdout
    except subprocess.TimeoutExpired:
        return f"Timeout generating SIP {method.upper()} request to {dest}"
    except subprocess.CalledProcessError as e:
        return f"Command failed: {e.cmd}\nError output: {e.stderr}"
    except Exception as e:
        return f"Unexpected error: {e}\nCommand used: {' '.join(cmd)}"

# Generate multiple SIP requests for testing traffic.
def generate_traffic(iterations=50):
    # Define possible destinations and methods
    dest_targets = ['10.0.1.1:5060', '10.0.1.2:5060']
    methods = ['options', 'register', 'subscribe', 'notify']

    for i in range(iterations):
        # Randomly choose destination and method
        dest = random.choice(dest_targets)
        method = random.choice(methods)

        print(f"[{i+1}/{iterations}] Generating {method.upper()} request to {dest}")
        output = generate_sip_request(dest, method)

        if output:
            print(f"Response:\n{output}")

        # Random delay between requests
        time.sleep(random.uniform(0.1, 0.5))

# Main function
if __name__ == '__main__':
    generate_traffic()
