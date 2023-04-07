import sys
import frida
import time
import argparse

# Function that will be called every time the instrumented app sends a message to the script.
def on_message(message, data):
    print(f"[{message}] -> {data}")

# Spawns the target app and attaches to it, returning the session object.
def attach_to_app(device, app):
    # if this fails then either frida is not running or wrong package name.
    try:
        pid = device.spawn([app])
    except Exception as e:
        print(f"[-] Either frida server not running on device or wrong package name: \n", str(e))
        exit(1)

    device.resume(pid)
    time.sleep(1)  # Wait for the app to start up.
    session = device.attach(pid)
    return session

# Detaches from the app and cleans up the session object.
def detach_from_app(session):
    session.detach()

# Runs the given Frida script and sets up message handling.
def run_script(script):
    script.on('message', on_message)
    script.load()
    input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')

# Constructs the Frida script to search for the given pattern in memory.
def get_frida_script(pattern, password_len):
    return f"""
        // Get all readable memory ranges for the target process.
        var ranges = Process.enumerateRangesSync({{protection: 'r--', coalesce: true}});
        var range;
        // Define a recursive function to search through each range.
        function processNext(){{
            // Pop the next range off the stack.
            range = ranges.pop();
            if(!range){{
                // If there are no more ranges left, we're done.
                return;
            }}
            // Search for the given pattern in this range.
            Memory.scan(range.base, range.size, '{pattern}', {{
                onMatch: function(address, size){{
                        console.log('[+] Pattern found at: ' + address.toString());
                        // Read the password from memory and print it out.
                        var buf = Memory.readByteArray(ptr(address.toString()), {password_len});
                        console.log('[+] Dumping cleartext at this address: ' + hexdump(buf, {{
                            offset: 0,
                            length: {password_len},
                            header: true,
                            ansi: false
                        }}));
                    }},
                onError: function(reason){{
                        console.log('[!] There was an error scanning memory');
                    }},
                onComplete: function(){{
                        // After scanning this range, move on to the next one.
                        processNext();
                    }}
                }});
        }}
        processNext();
    """

def main(args):
    # Connect to the device and attach to the target app.
    device = frida.get_usb_device()
    session = attach_to_app(device, args.app_package)
    input("Waiting, press any key to continue")
    # Create a new script to search for the pattern in memory.
    script = session.create_script(get_frida_script(args.pattern, args.password_len))
    # Run the script and wait for the user to detach from the app.
    run_script(script)
    detach_from_app(session)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Dump memory based on pattern')
    parser.add_argument('-pt','--pattern', type=str, required=True, help='pattern to search for in memory')
    parser.add_argument('-ap','--app-package', type=str, required=True, help='app package name')
    parser.add_argument('-pl','--password-len', type=int, default=20, help='password length, default: 20')
    args = parser.parse_args()
    main(args)
