# Pynetsnmp Test Runner

This Python script, named `test_runner.py`, is a utility for running a series of tests related to the pynetsnmp library. 
It allows you to specify a host and runs various SNMP-related test scripts with the option to pass the host as an argument to each test.

## Usage

Run the script using Python and provide the necessary arguments:

- `--host HOST`: Specify the SNMP host for all tests. This option adds a `--host` argument to each test script. If not provided, the tests will run without specifying a host.

The script will execute a series of SNMP-related test scripts and display the output of each test.

## Test Scripts

The following test scripts are included and run by this test runner:

1. `get.py`: Test script for SNMP GET requests.
2. `getbulk.py`: Test script for SNMP GETBULK requests.
3. `ifIndex.py`: Test script for querying SNMP IF-MIB.
4. `tableget.py`: Test script for querying SNMP tables.
5. `walk.py`: Test script for SNMP walk requests. **NOTE: script runs only for one host. If you want use it for list of hosts run this test separately.**
6. `twistget.py`: Test script using the Twisted framework for SNMP GET requests.

## Test Scripts for Manual Run

The following test scripts are NOT included to run by this test runner:
1. `trap.py`: SNMP Trap Receiver Test. To run this script and check result you will need 2 terminal windows:
first one to run test, e.g.:
```bash
python trap.py --host <host> --port <port> 
```
and second to send snmptrap:

```bash
snmptrap -v<SNMP version> -c <community_string> <host>:<port> '' .1.3.6.1.6.3.1.1.5.1
```

## Output

The test runner provides output for each test script, indicating whether the test was successful or not. If "error" is not found in the output, the test is considered successful; otherwise, it is marked as a failure.

## Results

After running all tests, the test runner displays the following summary:

- Total Successful Tests
- Total Failed Tests

## Example

Here's an example of how to use the test runner:

```bash
python test_runner.py --host <ip_or_hostname>
```
