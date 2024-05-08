import argparse
import subprocess

all_tests = [
    "get.py",
    "getbulk.py",
    "ifIndex.py",
    "tableget.py",
#   "walk.py",
    "twistget.py"
]


def main():
    parser = argparse.ArgumentParser(description="Pynetsnmp test runner")
    parser.add_argument("--host", help="Specify the host for all tests (adds --host argument to each test)")

    args = parser.parse_args()

    host = args.host

    success_count = 0
    failure_count = 0

    for test in all_tests:
        command = ["python", test]
        if host and test != "walk.py":
            command.extend(["--host", host])
        if test == "walk.py":
            command.extend([host])
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print(output)
            if "error" not in output.lower():
                success_count += 1
            else:
                failure_count += 1

        except subprocess.CalledProcessError as e:
            print("Error running command for {}: {}".format(test, e))
            failure_count += 1
        except Exception as e:
            print("Error in {}: {}".format(test, e))

    print("===================")
    print("Successful Tests: {}".format(success_count))
    print("Failed Tests: {}".format(failure_count))


if __name__ == "__main__":
    main()
